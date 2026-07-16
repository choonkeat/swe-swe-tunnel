// Command swe-swe-tunnel is the client side of the swe-swe-tunnel pair.
//
// Thin wrapper around internal/tunnelclient. See that package for the
// connect/register/serve logic.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

	priv, generated, err := tunnelclient.LoadIdentityStatus(*identityKey, logger)
	if err != nil {
		logger.Error("identity key", "path", *identityKey, "err", err)
		emitter.Emit(tunnelclient.EventFatal, tunnelclient.FatalData{
			Reason:   "identity_error",
			Message:  fmt.Sprintf("identity key %q: %v", *identityKey, err),
			ExitCode: 1,
		})
		os.Exit(1)
	}
	// First boot: the key was just generated, so its public half has
	// never been allowlisted on the tunnel server. Connecting now would
	// only burn a rate-limited registration attempt. Print the pubkey +
	// path so the operator can allowlist it, emit a fatal event so the
	// swe-swe-server supervisor stops instead of restart-looping, and
	// exit. The next boot finds the key on disk and connects normally.
	// (LoadIdentityStatus reports generated=false for the inline
	// SWE_TUNNEL_IDENTITY_KEY env path, so this never fires there.)
	if generated {
		pub := priv.Public().(ed25519.PublicKey)
		pubB64 := base64.RawStdEncoding.EncodeToString(pub)
		fmt.Fprintf(os.Stderr,
			"\nGenerated a new tunnel identity key.\n"+
				"  path:   %s\n"+
				"  pubkey: %s\n\n"+
				"Allowlist this pubkey on the tunnel server, then start again.\n\n",
			*identityKey, pubB64)
		emitter.Emit(tunnelclient.EventFatal, tunnelclient.FatalData{
			Reason:   "identity_generated",
			Message:  fmt.Sprintf("generated new identity %s; allowlist pubkey %s then restart", *identityKey, pubB64),
			ExitCode: 1,
		})
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tlsCfg, err := buildTLSConfig(*clientCert, priv, *insecure)
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
// --client-cert path + the already-loaded identity private key +
// --insecure. The cert is paired with priv via tls.X509KeyPair —
// the agent's identity.key doubles as the TLS private key (RFC
// 8410, Ed25519 X.509), so there is no --client-key flag.
//
// Taking priv as an in-memory ed25519.PrivateKey (rather than a
// disk path) is load-bearing: tunnelclient.LoadIdentity may have
// resolved the identity from SWE_TUNNEL_IDENTITY_KEY env, in
// which case no file exists at --identity-key. Reading that path
// would fail with "no such file or directory" and the agent
// would refuse to boot even when its identity was already in
// memory.
//
// Returns (nil, nil) when neither mTLS nor --insecure was
// requested — the dial uses Go's default tls.Config and the
// server's normal cert is verified against the system trust
// store.
func buildTLSConfig(clientCertPath string, priv ed25519.PrivateKey, insecure bool) (*tls.Config, error) {
	if clientCertPath == "" && !insecure {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if clientCertPath != "" {
		if priv == nil {
			return nil, errors.New("identity private key is nil; load identity before buildTLSConfig")
		}
		certPEM, err := os.ReadFile(clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("read --client-cert %s: %w", clientCertPath, err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal identity key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
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
