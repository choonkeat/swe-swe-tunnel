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

	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
	"github.com/choonkeat/swe-swe-tunnel/internal/version"
)

func main() {
	var (
		server       = flag.String("server", "", "tunnel server URL, e.g. https://tunnel.example.com (required)")
		unique       = flag.String("unique", "", "requested name (required); server stores it as {unique}-tunnel")
		target       = flag.String("target", "127.0.0.1", "default forward target host (port comes from Host header label)")
		identityKey  = flag.String("identity-key", "", "path to Ed25519 identity key (default ~/.swe-swe-tunnel/identity.key)")
		insecure     = flag.Bool("insecure", false, "skip TLS verification (testing only)")
		clientCert   = flag.String("client-cert", "", "path to client cert PEM for mTLS; the private key comes from --identity-key (env: SWE_TUNNEL_CLIENT_CERT)")
		reportFormat = flag.String("report-format", "none", "supervisor event format on stdout: none|jsonl (env: SWE_TUNNEL_REPORT_FORMAT)")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	// Prefix the default usage with a version line so `-h` answers
	// "what am I running" without a separate --version invocation.
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "swe-swe-tunnel %s\n\n", version.String())
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

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
	if *clientCert == "" {
		*clientCert = os.Getenv("SWE_TUNNEL_CLIENT_CERT")
	}
	if envRF, ok := os.LookupEnv("SWE_TUNNEL_REPORT_FORMAT"); ok && !flagSet("report-format") {
		*reportFormat = envRF
	}
	if *server == "" || *unique == "" {
		flag.Usage()
		logger.Error("--server and --unique are required (or SWE_TUNNEL_SERVER / SWE_TUNNEL_UNIQUE)")
		os.Exit(2)
	}

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

	tlsCfg, err := buildTLSConfig(*clientCert, *identityKey, *insecure)
	if err != nil {
		logger.Error("tls config", "err", err)
		emitter.Emit(tunnelclient.EventFatal, tunnelclient.FatalData{
			Message:  fmt.Sprintf("tls config: %v", err),
			ExitCode: 1,
		})
		os.Exit(1)
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
		Handler: tunnelclient.PortDispatchHandler(*target, logger),
	})
	if runErr != nil {
		logger.Error("run", "err", runErr)
		os.Exit(1)
	}
}

// buildTLSConfig assembles the dial-side tls.Config from the
// --client-cert + --identity-key + --insecure inputs. When
// clientCert is set, the cert is paired with identityKey via
// tls.X509KeyPair — i.e. the agent's existing identity.key doubles
// as the TLS private key (RFC 8410, Ed25519 X.509). No
// --client-key flag exists by design.
//
// Returns (nil, nil) when neither mTLS nor --insecure was requested
// — the dial uses Go's default tls.Config and the server's normal
// cert is verified against the system trust store.
func buildTLSConfig(clientCertPath, identityKeyPath string, insecure bool) (*tls.Config, error) {
	if clientCertPath == "" && !insecure {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCertPath != "" {
		certPEM, err := os.ReadFile(clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("read --client-cert %s: %w", clientCertPath, err)
		}
		keyPEM, err := os.ReadFile(identityKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read --identity-key %s: %w", identityKeyPath, err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("pair cert+key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if insecure {
		cfg.InsecureSkipVerify = true //nolint:gosec // user opted in
	}
	return cfg, nil
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
