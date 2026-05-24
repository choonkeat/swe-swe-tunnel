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
	"github.com/go-acme/lego/v4/providers/dns/route53"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
	"github.com/choonkeat/swe-swe-tunnel/internal/cert"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/version"
)

// certService is the union of cert-manager methods main.go needs.
// Both *cert.Manager and *cert.StaticLoader satisfy it; the active
// implementation is chosen at boot from --no-acme. The narrower
// certEnsurer interface in tunnel.go (just EnsureName) is what
// connectHandler accepts — certService extends it with the SNI hook
// and the disk-rescan that main owns.
type certService interface {
	EnsureName(ctx context.Context, label string) error
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	LoadAllFromDisk() (int, error)
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// One-shot subcommand dispatch (mtls-init / mtls-issue /
	// mtls-sign). Runs BEFORE flag.Parse so subcommand-specific
	// flags don't trigger the daemon's unknown-flag error. The
	// subcommand's --dir defaults to {state-dir}/mtls; we resolve
	// state-dir here from the env var (or the home-default) since
	// the daemon's --state-dir flag isn't parsed yet. Operators who
	// need a non-default state-dir for the subcommand set
	// SWE_TUNNEL_STATE explicitly.
	sd := os.Getenv("SWE_TUNNEL_STATE")
	if sd == "" {
		sd = defaultStateDir()
	}
	if code, handled := runSubcommand(os.Args, sd, os.Stdout, logger); handled {
		os.Exit(code)
	}

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
		// Per-IP cap on how many "timestamp out of range" denies will be
		// refunded against --register-rate-ip-per-hour before the main
		// IP limiter starts holding the burns. A legit clock-drift case
		// (laptop suspend) typically produces 1-3 skew denies before
		// NTP steps the clock; 10/hour is a generous safety margin.
		// Above the cap the main IP limiter takes over, escalating to
		// rate_limited:ip — which is the correct signal for "your
		// clock isn't drifting, it's broken." 0 disables the refund
		// entirely (every skew deny burns the main budget).
		registerSkewDenyLimit = flag.Int("register-rate-skew-deny-per-hour", 10, "max refunded 'timestamp out of range' denies per source IP per hour (0 = no refund)")
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
		// no-acme: skip ACME entirely. Operator provisions certs out of
		// band (lego CLI, certbot, cert-manager, etc.) and drops them
		// into {state-dir}/lego/certificates/ for tunneld to serve.
		// SIGHUP rescans the directory. See docs/manual-certs.md.
		noAcme = flag.Bool("no-acme", false, "skip ACME entirely; serve only pre-provisioned certs from {state-dir}/lego/certificates/ (SIGHUP-reloadable)")
		// mtls-ca: path to a PEM bundle of CAs trusted for client
		// certs on the public listener. Presence enables mTLS:
		// tls.Config.ClientAuth = RequireAndVerifyClientCert. Empty
		// (the default) keeps today's behaviour. SIGHUP reloads the
		// bundle in place; load failures keep the prior pool.
		mtlsCA = flag.String("mtls-ca", "", "PEM bundle of CAs to trust for client certs (enables mTLS on the public listener; SIGHUP-reloadable)")
		// register-listen-without-mtls: an ADDITIONAL HTTPS listener
		// that mounts only /v1/connect and does NOT require a client
		// cert, so cert-less agents can register while browser access on
		// the main listener stays mTLS-gated. Requires --mtls-ca (the
		// main listener already accepts cert-less registration when mTLS
		// is off, so the flag is meaningless without it) and
		// --allowlist-dir (a cert-less registration port without an
		// allowlist is open to the internet). The main listener keeps its
		// own mTLS-gated /v1/connect — this is additive, not a
		// replacement. SIGHUP reloads its CA pool too (used only for the
		// opportunistic cert_key_mismatch binding; cert-less agents pass).
		registerListenNoMTLS = flag.String("register-listen-without-mtls", "", "additional HTTPS listener that accepts /v1/connect WITHOUT a client cert (e.g. :8443); requires --mtls-ca and --allowlist-dir")
		showVersion          = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "swe-swe-tunneld %s\n\n", version.String())
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	logger.Info("starting", "binary", "swe-swe-tunneld", "version", version.String())

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
	// --no-acme has env parity with the other env-fallback flags. The
	// flag wins; env fills in only when the flag wasn't explicitly set.
	if !flagSet("no-acme") && os.Getenv("SWE_TUNNEL_NO_ACME") == "1" {
		*noAcme = true
	}
	if *mtlsCA == "" {
		*mtlsCA = os.Getenv("SWE_TUNNEL_MTLS_CA")
	}
	if *registerListenNoMTLS == "" {
		*registerListenNoMTLS = os.Getenv("SWE_TUNNEL_REGISTER_LISTEN_WITHOUT_MTLS")
	}

	if err := requireFlags(*apex, *email, *noAcme); err != nil {
		flag.Usage()
		logger.Error(err.Error())
		os.Exit(2)
	}

	// Mutually exclusive: an operator who set both is asking which one
	// "wins" — fail loudly rather than picking silently.
	if *allowedPortsFile != "" && flagSet("allowed-ports") {
		logger.Error("--allowed-ports and --allowed-ports-file are mutually exclusive")
		os.Exit(2)
	}

	// The cert-less registration listener has two hard preconditions
	// (see validateRegisterListen). Loud-fail on boot rather than start a
	// listener that's either pointless (no mTLS) or open to the internet
	// (no allowlist).
	if err := validateRegisterListen(*registerListenNoMTLS, *mtlsCA, *allowlistDir); err != nil {
		logger.Error(err.Error())
		os.Exit(2)
	}

	ports, err := loadPortPolicy(*allowedPorts, *allowedPortsFile)
	if err != nil {
		logger.Error("port allowlist load failed", "err", err)
		os.Exit(1)
	}
	logger.Info("port allowlist", "spec", ports.Spec(), "source", ports.Source())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// certMgr: ACME-driven *cert.Manager by default; *cert.StaticLoader
	// when --no-acme is set. Both satisfy this interface, so the rest
	// of main treats them uniformly: TLS hello dispatch, register-time
	// EnsureName, SIGHUP-driven LoadAllFromDisk.
	var certMgr certService

	if *noAcme {
		sl := cert.NewStaticLoader(*stateDir, *apex, logger)
		certMgr = sl
		logger.Info("ACME disabled (--no-acme); serving pre-provisioned certs only",
			"cert_dir", filepath.Join(*stateDir, "lego", "certificates"))
		if *ensureCert != "" {
			logger.Info("--ensure-cert is a no-op in --no-acme mode; issuance is external (use lego/certbot directly)",
				"label", *ensureCert)
			return
		}
	} else {
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
		certMgr = mgr
	}

	if n, err := certMgr.LoadAllFromDisk(); err != nil {
		logger.Warn("load-all-from-disk had errors", "err", err)
	} else {
		logger.Info("loaded certs from disk", "count", n)
	}

	idStore, err := identity.Open(filepath.Join(*stateDir, "identities.db"))
	if err != nil {
		logger.Error("identity store open failed", "err", err)
		os.Exit(1)
	}
	defer idStore.Close()

	ipLim := ratelimit.New(*registerIPLimit, time.Hour)
	keyLim := ratelimit.New(*registerKeyLimit, 24*time.Hour)
	skewLim := ratelimit.New(*registerSkewDenyLimit, time.Hour)
	logger.Info("register rate limits",
		"ip_per_hour", *registerIPLimit,
		"pubkey_per_day", *registerKeyLimit,
		"skew_deny_refund_per_hour", *registerSkewDenyLimit,
		"max_keys", ratelimit.DefaultMaxKeys,
	)

	// Periodic janitor: drops keys whose sample windows have entirely
	// aged out. Without this the per-IP and per-pubkey maps grow without
	// bound when source addresses or keys keep rotating (DoS vector via
	// IPv6 source-address rotation). 15min cadence is well below the 1h
	// window and cheap (single map iteration).
	go ipLim.RunPruner(ctx, 15*time.Minute)
	go keyLim.RunPruner(ctx, 15*time.Minute)
	go skewLim.RunPruner(ctx, 15*time.Minute)

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

	// mTLS bundle: when --mtls-ca is set, load the CA bundle now and
	// fail boot loudly on any error — a misconfigured bundle path must
	// not silently produce a permissive daemon. The pool is read on
	// every TLS handshake (through GetConfigForClient below) so SIGHUP
	// reloads take effect for new connections without restart.
	var mtlsB *mtlsBundle
	if *mtlsCA != "" {
		var err error
		mtlsB, err = loadMtlsBundle(*mtlsCA)
		if err != nil {
			logger.Error("mTLS CA bundle load failed", "path", *mtlsCA, "err", err)
			os.Exit(1)
		}
		logger.Info("mTLS enabled", "ca", *mtlsCA, "count", mtlsB.Count())
	} else {
		logger.Info("mTLS disabled (no --mtls-ca)")
	}

	// SIGHUP reload: re-read the allowlist directory (drop any live
	// sessions whose pubkey is no longer authorized) AND re-read the
	// port allowlist file (if file-sourced) AND rescan the cert
	// directory so an operator who just dropped a freshly-issued cert
	// (especially in --no-acme mode, but also useful as a manual
	// override during an ACME outage) can ask tunneld to pick it up
	// without restarting. All arms are idempotent and skip cleanly
	// when their source isn't reloadable (allow is nil; ports is
	// inline-sourced), but the signal handler is always armed so an
	// operator who later switches to a file source doesn't have to
	// restart to get HUP behaviour.
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
				reloadCerts(certMgr, logger)
				reloadMtlsBundle(mtlsB, logger)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, idStore, certMgr, *apex, ipLim, keyLim, skewLim, allow, logger))
	mux.Handle("/", route(reg, *apex, ports, logger, helloHandler(*apex)))

	tlsCfg := &tls.Config{
		GetCertificate: certMgr.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	if mtlsB != nil {
		// Per-handshake hook returns a config carrying the *current*
		// CA pool. Without GetConfigForClient, ClientCAs would be a
		// snapshot from boot and SIGHUP reloads would not take effect
		// on new connections. The returned config nils its own
		// GetConfigForClient to break any recursion.
		bundle := mtlsB
		baseGetCert := certMgr.GetCertificate
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				GetCertificate: baseGetCert,
				MinVersion:     tls.VersionTLS12,
				ClientCAs:      bundle.Pool(),
				ClientAuth:     tls.RequireAndVerifyClientCert,
			}, nil
		}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		TLSConfig:         tlsCfg,
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

	// Optional cert-less registration listener. Mounts only
	// /v1/connect (reusing the same connectHandler value, so it shares
	// the registry, identity store, rate limiters and allowlist with
	// the main listener) plus /healthz. No hello page, no proxy
	// route() — the browser-facing proxy stays exclusively on the
	// mTLS listener. validateRegisterListen above guarantees mtlsB is
	// non-nil here.
	var regSrv *http.Server
	if *registerListenNoMTLS != "" {
		regMux := http.NewServeMux()
		regMux.Handle("/v1/connect", connectHandler(reg, idStore, certMgr, *apex, ipLim, keyLim, skewLim, allow, logger))
		regMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		regSrv = &http.Server{
			Addr:              *registerListenNoMTLS,
			Handler:           regMux,
			TLSConfig:         registerTLSConfig(certMgr.GetCertificate, mtlsB),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		logger.Info("register-without-mtls listening", "addr", *registerListenNoMTLS)
		go func() {
			if err := regSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logger.Error("register listener exited", "err", err)
				stop()
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if regSrv != nil {
		_ = regSrv.Shutdown(shutdownCtx)
	}
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
	case "route53":
		// Auth flows through the AWS SDK default credential chain
		// (env → shared file → IMDS/IRSA/task role), so running on
		// Lightsail/EC2/ECS-Fargate with an attached role needs zero
		// static secrets. AWS_HOSTED_ZONE_ID is optional — lego will
		// discover the zone from the FQDN if unset, but pinning it
		// shaves a ListHostedZonesByName call per issuance.
		return func() (challenge.Provider, error) {
			cfg := route53.NewDefaultConfig()
			if propagationTimeout > 0 {
				cfg.PropagationTimeout = propagationTimeout
			}
			if pollingInterval > 0 {
				cfg.PollingInterval = pollingInterval
			}
			return route53.NewDNSProviderConfig(cfg)
		}
	default:
		return func() (challenge.Provider, error) {
			return nil, fmt.Errorf("unsupported dns provider %q (supported: dnsimple, route53)", name)
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

// requireFlags validates the boot-time required-flag rules. apex is
// always required; --acme-email is required only when ACME is enabled
// (i.e. --no-acme is not set). Pure function so it can be unit-tested
// without spinning up the full main loop.
func requireFlags(apex, email string, noAcme bool) error {
	if apex == "" {
		return fmt.Errorf("--apex-domain is required (or SWE_TUNNEL_APEX)")
	}
	if !noAcme && email == "" {
		return fmt.Errorf("--acme-email is required when ACME is enabled (or SWE_TUNNEL_ACME_EMAIL); pass --no-acme to skip ACME entirely")
	}
	return nil
}

// validateRegisterListen enforces the preconditions for the cert-less
// registration listener (--register-listen-without-mtls). When the
// address is empty the listener is off and there's nothing to check.
// When set it requires:
//
//   - --mtls-ca: without mTLS on the main listener, that listener
//     already accepts cert-less registration, so a second cert-less
//     port is meaningless (a misconfiguration to flag, not honour).
//   - --allowlist-dir: a cert-less registration port without an
//     allowlist is open registration reachable by anyone on the
//     internet (rate-limited only). The allowlist is the gate that
//     replaces mTLS here, so it must be present.
//
// Pure function so it can be unit-tested without spinning up main.
func validateRegisterListen(registerAddr, mtlsCA, allowlistDir string) error {
	if registerAddr == "" {
		return nil
	}
	if mtlsCA == "" {
		return fmt.Errorf("--register-listen-without-mtls requires --mtls-ca (the main listener already accepts cert-less registration when mTLS is off)")
	}
	if allowlistDir == "" {
		return fmt.Errorf("--register-listen-without-mtls requires --allowlist-dir (a cert-less registration port without an allowlist is open to the internet)")
	}
	return nil
}

// registerTLSConfig builds the TLS config for the cert-less
// registration listener. Unlike the main listener's
// RequireAndVerifyClientCert, this uses VerifyClientCertIfGiven: a
// cert-less agent completes the handshake (its register is gated by
// the Ed25519 signature + allowlist in handleRegister), while a
// cert-*bearing* agent must present one signed by --mtls-ca — and a
// verified cert then populates r.TLS.PeerCertificates, flowing through
// the cert_key_mismatch binding in handleRegister (opportunistic
// defence-in-depth). RequestClientCert is deliberately NOT used: it
// would populate an *unverified* peer cert, making that binding
// forgeable.
//
// The CA pool is read per handshake via GetConfigForClient, so SIGHUP
// CA reloads take effect on this listener too — same mechanism as the
// main listener. bundle must be non-nil (the boot guard in
// validateRegisterListen guarantees --mtls-ca is set).
func registerTLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), bundle *mtlsBundle) *tls.Config {
	return &tls.Config{
		GetCertificate: getCert,
		MinVersion:     tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				GetCertificate: getCert,
				MinVersion:     tls.VersionTLS12,
				ClientCAs:      bundle.Pool(),
				ClientAuth:     tls.VerifyClientCertIfGiven,
			}, nil
		},
	}
}

// reloadCerts is a SIGHUP hook for the cert table. It rescans the
// cert directory and refreshes any entries already loaded; new files
// are added, existing entries get the latest disk bytes. Idempotent
// and safe to call regardless of mode — in ACME mode this lets an
// operator manually drop a cert during an ACME outage; in --no-acme
// mode this is the canonical way to publish a freshly-issued cert.
func reloadCerts(certMgr certService, logger *slog.Logger) {
	n, err := certMgr.LoadAllFromDisk()
	if err != nil {
		logger.Warn("cert reload failed", "err", err)
		return
	}
	logger.Info("cert reload OK", "count", n)
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
