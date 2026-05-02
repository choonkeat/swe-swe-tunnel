// Command swe-swe-tunneld is the public-facing tunnel server.
//
// Phase 2: a single :443 listener serves the apex hello page and accepts
// tunnel-control connections at POST /v1/connect (HTTP Upgrade →
// yamux). Browser requests for `{port}.{label}-tunnel.{apex}` are
// reverse-proxied through the matching tunnel.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/dnsimple"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
	"github.com/choonkeat/swe-swe-tunnel/internal/cert"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
)

func main() {
	var (
		listen           = flag.String("listen", ":443", "HTTPS listener address")
		apex             = flag.String("apex-domain", "", "DNS apex (required), e.g. example.com")
		email            = flag.String("acme-email", "", "ACME account email (required)")
		stateDir         = flag.String("state-dir", defaultStateDir(), "persistent state directory")
		dnsProv          = flag.String("dns-provider", "dnsimple", "lego DNS provider")
		staging          = flag.Bool("acme-staging", false, "use Let's Encrypt staging (untrusted, no rate limits)")
		ensureCert       = flag.String("ensure-cert", "", "issue *.{label}.{apex} cert and exit (admin one-shot)")
		registerIPLimit  = flag.Int("register-rate-ip-per-hour", 5, "max REGISTER attempts per source IP per hour (0 = disabled)")
		registerKeyLimit = flag.Int("register-rate-pubkey-per-day", 10, "max REGISTER attempts per pubkey per day (0 = disabled)")
		// Lego's defaults (PropagationTimeout=60s, PollingInterval=2s) are
		// too tight for DNSimple's edge nameservers under load — we've seen
		// real-world TXT propagation occasionally take 2–4 minutes, which
		// burns LE failed-validation budget on otherwise-healthy issuance.
		// 5min/5s is a comfortable ceiling: still recovers fast on a normal
		// day, rides out an edge hiccup without telling LE to validate
		// prematurely.
		dnsPropagationTimeout = flag.Duration("dns-propagation-timeout", 5*time.Minute, "DNS-01 TXT propagation timeout passed to lego provider")
		dnsPollingInterval    = flag.Duration("dns-polling-interval", 5*time.Second, "DNS-01 TXT propagation poll interval")
		// allowlistDir is the directory of authorized Ed25519 pubkeys. When
		// unset, registration is open (today's behavior). When set, only
		// keys present in some file under the directory may register; an
		// empty directory means deny-all (explicit operator intent). Files
		// are reloaded on SIGHUP and live sessions whose key was removed
		// are dropped immediately.
		allowlistDir = flag.String("allowlist-dir", "", "directory of Ed25519 pubkey files (one per line, '#' comments); enables Register gate")
		// Port allowlist: gates which destination port labels in
		// {port}.{label}.{apex} the server is willing to proxy. Default
		// (portpolicy.DefaultSpec) covers common dev/web ports plus 9898
		// (swe-swe primary UI). The two flags are mutually exclusive:
		// inline (--allowed-ports / SWE_TUNNEL_ALLOWED_PORTS) is
		// restart-only; file (--allowed-ports-file /
		// SWE_TUNNEL_ALLOWED_PORTS_FILE) is SIGHUP-reloadable.
		allowedPorts     = flag.String("allowed-ports", portpolicy.DefaultSpec, "destination port allowlist (comma-separated, ranges like 3000-3099); 'all' disables the gate (DANGEROUS)")
		allowedPortsFile = flag.String("allowed-ports-file", "", "path to a file containing the port allowlist (SIGHUP-reloadable); mutually exclusive with --allowed-ports")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Env fallback: flag wins, env fills in if flag is empty.
	if *apex == "" {
		*apex = os.Getenv("SWE_TUNNEL_APEX")
	}
	if *email == "" {
		*email = os.Getenv("SWE_TUNNEL_ACME_EMAIL")
	}
	if env := os.Getenv("SWE_TUNNEL_STATE"); env != "" && *stateDir == defaultStateDir() {
		*stateDir = env
	}
	if *allowlistDir == "" {
		*allowlistDir = os.Getenv("SWE_TUNNEL_ALLOWLIST_DIR")
	}

	// --allowed-ports has a non-empty default (DefaultSpec). Override
	// from env only if the env var is *non-empty* — Compose's
	// `${VAR:-}` indirection sets the var to empty string when the
	// operator hasn't configured anything, and an empty spec parses
	// to deny-all. Treat empty env as "not set."
	if envP := os.Getenv("SWE_TUNNEL_ALLOWED_PORTS"); envP != "" && !flagSet("allowed-ports") {
		*allowedPorts = envP
	}
	if *allowedPortsFile == "" {
		*allowedPortsFile = os.Getenv("SWE_TUNNEL_ALLOWED_PORTS_FILE")
	}

	if *apex == "" || *email == "" {
		flag.Usage()
		logger.Error("--apex-domain and --acme-email are required (or SWE_TUNNEL_APEX / SWE_TUNNEL_ACME_EMAIL)")
		os.Exit(2)
	}

	// Mutually exclusive: an operator who set both is asking which one
	// "wins" — fail loudly rather than picking silently.
	if *allowedPortsFile != "" && flagSet("allowed-ports") {
		logger.Error("--allowed-ports and --allowed-ports-file are mutually exclusive")
		os.Exit(2)
	}

	ports, err := loadPortPolicy(*allowedPorts, *allowedPortsFile)
	if err != nil {
		logger.Error("port allowlist load failed", "err", err)
		os.Exit(1)
	}
	logger.Info("port allowlist", "spec", ports.Spec(), "source", ports.Source())

	// Wrap the lego DNS provider with our authoritative-NS pre-check so
	// Present blocks until every authoritative NS for the apex actually
	// serves the TXT we wrote — otherwise lego signals LE prematurely on
	// a slow DNSimple edge and burns LE's "60 failed validations / hour"
	// budget. See internal/cert/precheck.go for full rationale.
	baseFactory := dnsProviderFactory(*dnsProv, *dnsPropagationTimeout, *dnsPollingInterval)
	providerFactory := func() (challenge.Provider, error) {
		inner, err := baseFactory()
		if err != nil {
			return nil, err
		}
		return &cert.AuthoritativePreCheck{
			Inner:        inner,
			Apex:         *apex,
			WaitTimeout:  *dnsPropagationTimeout,
			WaitInterval: *dnsPollingInterval,
			Logger:       logger,
		}, nil
	}
	mgr := cert.New(*stateDir, *email, *apex, providerFactory, logger)
	if *staging {
		mgr.SetStaging()
		logger.Info("ACME staging mode (browser will not trust the cert)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *ensureCert != "" {
		if err := mgr.EnsureName(ctx, *ensureCert); err != nil {
			logger.Error("ensure-cert failed", "label", *ensureCert, "err", err)
			os.Exit(1)
		}
		logger.Info("cert ensured", "label", *ensureCert, "hostname", *ensureCert+"."+*apex)
		return
	}

	if err := mgr.Ensure(ctx); err != nil {
		logger.Error("cert acquisition failed", "err", err)
		os.Exit(1)
	}

	if n, err := mgr.LoadAllFromDisk(); err != nil {
		logger.Warn("load-all-from-disk had errors", "err", err)
	} else {
		logger.Info("loaded certs from disk", "count", n)
	}

	// Boot-time DNS sanity check. Doesn't block startup; just surfaces a
	// loud WARN if the apex's authoritative DNS doesn't return a wildcard
	// for multi-label names — the property documented in
	// docs/adr/0001-dns-host-multi-label-wildcards.md.
	cert.ProbeWildcard(ctx, *apex, cert.DefaultLookup, logger)

	go func() {
		if err := mgr.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("cert renewal loop exited", "err", err)
		}
	}()

	idStore, err := identity.Open(filepath.Join(*stateDir, "identities.db"))
	if err != nil {
		logger.Error("identity store open failed", "err", err)
		os.Exit(1)
	}
	defer idStore.Close()

	ipLim := ratelimit.New(*registerIPLimit, time.Hour)
	keyLim := ratelimit.New(*registerKeyLimit, 24*time.Hour)
	logger.Info("register rate limits",
		"ip_per_hour", *registerIPLimit,
		"pubkey_per_day", *registerKeyLimit,
		"max_keys", ratelimit.DefaultMaxKeys,
	)

	// Periodic janitor: drops keys whose sample windows have entirely
	// aged out. Without this the per-IP and per-pubkey maps grow without
	// bound when source addresses or keys keep rotating (DoS vector via
	// IPv6 source-address rotation). 15min cadence is well below the 1h
	// window and cheap (single map iteration).
	go ipLim.RunPruner(ctx, 15*time.Minute)
	go keyLim.RunPruner(ctx, 15*time.Minute)

	// Allowlist: optional. When set, only keys in some file under the dir
	// may register. Loud-fail on boot: a typo'd dir must not silently fall
	// back to open-registration. SIGHUP reloads + revokes (see goroutine
	// below). When unset, log loudly so an operator who *thought* they
	// turned the gate on can spot a misspelled flag at startup.
	var allow *allowlist.Set
	if *allowlistDir != "" {
		var err error
		allow, err = allowlist.Load(*allowlistDir)
		if err != nil {
			logger.Error("allowlist load failed", "source", *allowlistDir, "err", err)
			os.Exit(1)
		}
		denyAll := ""
		if allow.Len() == 0 {
			denyAll = " (deny-all)"
		}
		logger.Info("allowlist loaded"+denyAll,
			"source", *allowlistDir,
			"files", allow.Files(),
			"count", allow.Len())
	} else {
		logger.Info("allowlist disabled (no --allowlist-dir set; open registration)")
	}

	reg := newRegistry()

	// SIGHUP reload: re-read the allowlist directory (drop any live
	// sessions whose pubkey is no longer authorized) AND re-read the
	// port allowlist file (if file-sourced). Both are no-ops when
	// their respective source isn't reloadable (allow is nil; ports
	// is inline-sourced), but the signal handler is always armed so
	// an operator who later switches to a file source doesn't have
	// to restart to get HUP behaviour.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		defer signal.Stop(hupCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				if allow != nil {
					reloadAllowlistAndRevoke(allow, reg, logger)
				}
				reloadPortPolicy(ports, logger)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, idStore, mgr, *apex, ipLim, keyLim, allow, logger))
	mux.Handle("/", route(reg, *apex, ports, logger, helloHandler(*apex)))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		TLSConfig:         &tls.Config{GetCertificate: mgr.GetCertificate, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	logger.Info("listening", "addr", *listen, "apex", *apex)
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("listener exited", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func helloHandler(apex string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "swe-swe-tunnel\napex: %s\nhttps://github.com/choonkeat/swe-swe-tunnel\n", apex)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// dnsProviderFactory returns a closure that constructs a fresh challenge.Provider
// per cert request. propagationTimeout / pollingInterval override the lego
// defaults, which are too tight for DNSimple's edge under load.
func dnsProviderFactory(name string, propagationTimeout, pollingInterval time.Duration) func() (challenge.Provider, error) {
	switch name {
	case "dnsimple":
		return func() (challenge.Provider, error) {
			cfg := dnsimple.NewDefaultConfig()
			cfg.AccessToken = os.Getenv("DNSIMPLE_OAUTH_TOKEN")
			cfg.BaseURL = os.Getenv("DNSIMPLE_BASE_URL")
			if propagationTimeout > 0 {
				cfg.PropagationTimeout = propagationTimeout
			}
			if pollingInterval > 0 {
				cfg.PollingInterval = pollingInterval
			}
			return dnsimple.NewDNSProviderConfig(cfg)
		}
	default:
		return func() (challenge.Provider, error) {
			return nil, fmt.Errorf("unsupported dns provider %q (only dnsimple in phase 1)", name)
		}
	}
}

// reloadAllowlistAndRevoke re-reads the allowlist directory and, on a
// successful reload only, drops any live sessions whose pubkey is no
// longer authorized. A parse error logs loudly and keeps the prior set
// in place — the in-memory policy didn't change, so no revoke is
// warranted (a typo'd file mid-flight should not flip the gate to
// deny-all).
func reloadAllowlistAndRevoke(allow *allowlist.Set, reg *registry, logger *slog.Logger) {
	added, removed, files, err := allow.Reload()
	if err != nil {
		logger.Error("allowlist reload failed",
			"source", allow.Dir(), "err", err,
			"keeping_previous", true)
		return
	}
	logger.Info("allowlist reloaded",
		"source", allow.Dir(),
		"files", files, "count", allow.Len(),
		"added", added, "removed", removed)
	reg.RevokeMissing(allow, logger)
}

// loadPortPolicy resolves the port-allowlist source. Mutual exclusion
// is checked by the caller; here we only pick the active one.
//
// Source labels emitted into boot logs:
//
//	source=default   no flag, no env, no file → compiled-in DefaultSpec
//	source=flag      --allowed-ports=...
//	source=env       SWE_TUNNEL_ALLOWED_PORTS
//	source=file:/p   --allowed-ports-file=/p (SIGHUP-reloadable)
func loadPortPolicy(inline, file string) (*portpolicy.Set, error) {
	if file != "" {
		return portpolicy.LoadFile(file)
	}
	src := "default"
	if flagSet("allowed-ports") {
		src = "flag"
	} else if v := os.Getenv("SWE_TUNNEL_ALLOWED_PORTS"); v != "" {
		src = "env"
	}
	return portpolicy.LoadInline(inline, src)
}

// reloadPortPolicy is a SIGHUP hook for the port allowlist. For the
// inline source it's a no-op (Set.Reload returns false, nil); for the
// file source it re-reads + re-parses + atomic-swaps on success and
// preserves the prior policy on parse error.
func reloadPortPolicy(ports *portpolicy.Set, logger *slog.Logger) {
	if ports == nil {
		return
	}
	if ports.File() == "" {
		// inline source: nothing to reload, don't bother logging.
		return
	}
	changed, err := ports.Reload()
	if err != nil {
		logger.Error("port allowlist reload failed",
			"source", ports.Source(), "err", err,
			"keeping_previous", true)
		return
	}
	logger.Info("port allowlist reloaded",
		"source", ports.Source(),
		"spec", ports.Spec(),
		"changed", changed)
}

// flagSet reports whether the named flag was set on the command line.
// Used to give CLI flags precedence over env-var defaults without
// having to distinguish "user passed empty string" from "user didn't
// pass it at all".
func flagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func defaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".swe-swe-tunnel")
	}
	return "./.swe-swe-tunnel"
}
