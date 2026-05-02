// Command swe-swe-tunnel is the client side of the swe-swe-tunnel pair.
//
// Thin wrapper around internal/tunnelclient. See that package for the
// connect/register/serve logic.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

func main() {
	var (
		server       = flag.String("server", "", "tunnel server URL, e.g. https://tunnel.example.com (required)")
		unique       = flag.String("unique", "", "requested name (required); server stores it as {unique}-tunnel")
		target       = flag.String("target", "127.0.0.1", "default forward target host (port comes from Host header label)")
		identityKey  = flag.String("identity-key", "", "path to Ed25519 identity key (default ~/.swe-swe-tunnel/identity.key)")
		insecure     = flag.Bool("insecure", false, "skip TLS verification (testing only)")
		reportFormat = flag.String("report-format", "none", "supervisor event format on stdout: none|jsonl (env: SWE_TUNNEL_REPORT_FORMAT)")
		ports        = flag.String("ports", portpolicy.DefaultSpec, "allowlist of forwardable ports (comma-separated, ranges like 3000-3099); 'all' disables the gate (DANGEROUS — exposes every localhost port to the Internet)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *server == "" {
		*server = os.Getenv("SWE_TUNNEL_SERVER")
	}
	if *unique == "" {
		*unique = os.Getenv("SWE_TUNNEL_UNIQUE")
	}
	if *identityKey == "" {
		*identityKey = os.Getenv("SWE_TUNNEL_KEY")
	}
	if *identityKey == "" {
		*identityKey = defaultIdentityKey()
	}
	if envRF, ok := os.LookupEnv("SWE_TUNNEL_REPORT_FORMAT"); ok && !flagSet("report-format") {
		*reportFormat = envRF
	}
	if envP, ok := os.LookupEnv("SWE_TUNNEL_PORTS"); ok && !flagSet("ports") {
		*ports = envP
	}
	if *server == "" || *unique == "" {
		flag.Usage()
		logger.Error("--server and --unique are required (or SWE_TUNNEL_SERVER / SWE_TUNNEL_UNIQUE)")
		os.Exit(2)
	}

	policy, err := portpolicy.Parse(*ports)
	if err != nil {
		logger.Error("invalid --ports", "value", *ports, "err", err)
		os.Exit(2)
	}
	logger.Info("port policy", "spec", policy.String())

	emitter, err := buildEmitter(*reportFormat, os.Stdout, logger)
	if err != nil {
		logger.Error("invalid --report-format", "value", *reportFormat, "err", err)
		os.Exit(2)
	}

	priv, err := tunnelclient.LoadIdentity(*identityKey, logger)
	if err != nil {
		logger.Error("identity key", "path", *identityKey, "err", err)
		emitter.Emit(tunnelclient.EventFatal, tunnelclient.FatalData{
			Message:  fmt.Sprintf("identity key %q: %v", *identityKey, err),
			ExitCode: 1,
		})
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var tlsCfg *tls.Config
	if *insecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user opted in
	}

	runErr := tunnelclient.Run(ctx, tunnelclient.RunOptions{
		Connect: tunnelclient.Options{
			ServerURL:  *server,
			Unique:     *unique,
			PrivateKey: priv,
			TLSConfig:  tlsCfg,
			Logger:     logger,
			Emitter:    emitter,
		},
		Handler: tunnelclient.PortDispatchHandler(*target, policy, logger),
	})
	if runErr != nil {
		logger.Error("run", "err", runErr)
		os.Exit(1)
	}
}

// buildEmitter constructs the Emitter named by format. "none" returns a
// NoopEmitter; "jsonl" writes JSON-lines events to out (typically
// os.Stdout). Any other value is rejected.
func buildEmitter(format string, out *os.File, logger *slog.Logger) (tunnelclient.Emitter, error) {
	switch format {
	case "", "none":
		return tunnelclient.NoopEmitter{}, nil
	case "jsonl":
		return tunnelclient.NewJSONLEmitter(out).WithLogger(logger), nil
	default:
		return nil, fmt.Errorf("unknown format %q (want one of: none, jsonl)", format)
	}
}

// flagSet reports whether the named flag was set on the command line. Used
// to give CLI flags precedence over env-var defaults without having to
// distinguish "user passed empty string" from "user didn't pass it".
func flagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func defaultIdentityKey() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".swe-swe-tunnel", "identity.key")
	}
	return ".swe-swe-tunnel/identity.key"
}
