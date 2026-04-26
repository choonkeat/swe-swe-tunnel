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

	if err := tunnelclient.Serve(ctx, sess, tunnelclient.PortDispatchHandler(*target, logger)); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func defaultIdentityKey() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".swe-swe-tunnel", "identity.key")
	}
	return ".swe-swe-tunnel/identity.key"
}
