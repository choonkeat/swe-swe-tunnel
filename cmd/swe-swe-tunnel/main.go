// Command swe-swe-tunnel is the client side of the swe-swe-tunnel pair.
//
// Thin wrapper around internal/tunnelclient. See that package for the
// connect/register/serve logic.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

func main() {
	var (
		server      = flag.String("server", "", "tunnel server URL, e.g. https://tunnel.example.com (required)")
		unique      = flag.String("unique", "", "requested name (required); server stores it as {unique}-tunnel")
		target      = flag.String("target", "127.0.0.1", "default forward target host (port comes from Host header label)")
		identityKey = flag.String("identity-key", "", "path to Ed25519 identity key (default ~/.swe-swe-tunnel/identity.key)")
		stateFile   = flag.String("state-file", "/workspace/.swe-swe/tunnel-state.json", "path to write JSON {hostname,unique,registered_at} after RegisterOK; empty to disable")
		insecure    = flag.Bool("insecure", false, "skip TLS verification (testing only)")
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
	// SWE_TUNNEL_STATE_FILE overrides the flag default but loses to an
	// explicitly-set --state-file. Empty string disables.
	if envSF, ok := os.LookupEnv("SWE_TUNNEL_STATE_FILE"); ok && !flagSet("state-file") {
		*stateFile = envSF
	}
	if *server == "" || *unique == "" {
		flag.Usage()
		logger.Error("--server and --unique are required (or SWE_TUNNEL_SERVER / SWE_TUNNEL_UNIQUE)")
		os.Exit(2)
	}

	priv, err := tunnelclient.LoadOrCreateIdentity(*identityKey, logger)
	if err != nil {
		logger.Error("identity key", "path", *identityKey, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var tlsCfg *tls.Config
	if *insecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user opted in
	}

	sess, err := tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  *server,
		Unique:     *unique,
		PrivateKey: priv,
		TLSConfig:  tlsCfg,
		Logger:     logger,
	})
	if err != nil {
		logger.Error("connect", "err", err)
		os.Exit(1)
	}
	defer sess.Close()

	if *stateFile != "" {
		if err := tunnelclient.WriteState(*stateFile, sess); err != nil {
			// Best-effort: the tunnel still works without a state file.
			// Consumers that need it (e.g. swe-swe's public-hostname
			// resolver) will fall through to env/flag defaults.
			logger.Warn("write state file", "path", *stateFile, "err", err)
		} else {
			logger.Info("wrote state file", "path", *stateFile, "hostname", sess.Hostname())
		}
	}

	if err := tunnelclient.Serve(ctx, sess, tunnelclient.PortDispatchHandler(*target, logger)); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
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
