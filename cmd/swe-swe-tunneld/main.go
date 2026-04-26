// Command swe-swe-tunneld is the public-facing tunnel server.
//
// Phase 1: acquires *.{apex} via Let's Encrypt DNS-01, serves a hello page
// over HTTPS, and renews the cert daily. No tunneling logic yet.
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

	"github.com/choonkeat/swe-swe-tunnel/internal/cert"
)

func main() {
	var (
		listen    = flag.String("listen", ":443", "HTTPS listener address")
		apex      = flag.String("apex-domain", "", "DNS apex (required), e.g. example.com")
		email     = flag.String("acme-email", "", "ACME account email (required)")
		stateDir  = flag.String("state-dir", defaultStateDir(), "persistent state directory")
		dnsProv   = flag.String("dns-provider", "dnsimple", "lego DNS provider")
		staging   = flag.Bool("acme-staging", false, "use Let's Encrypt staging (untrusted, no rate limits)")
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

	if *apex == "" || *email == "" {
		flag.Usage()
		logger.Error("--apex-domain and --acme-email are required (or SWE_TUNNEL_APEX / SWE_TUNNEL_ACME_EMAIL)")
		os.Exit(2)
	}

	mgr := cert.New(*stateDir, *email, *apex, dnsProviderFactory(*dnsProv), logger)
	if *staging {
		mgr.SetStaging()
		logger.Info("ACME staging mode (browser will not trust the cert)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := mgr.Ensure(ctx); err != nil {
		logger.Error("cert acquisition failed", "err", err)
		os.Exit(1)
	}

	go func() {
		if err := mgr.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("cert renewal loop exited", "err", err)
		}
	}()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           helloHandler(*apex),
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
		fmt.Fprintf(w, "swe-swe-tunnel server\napex: %s\nphase: 1 (apex cert + hello)\n", apex)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func dnsProviderFactory(name string) func() (challenge.Provider, error) {
	switch name {
	case "dnsimple":
		return func() (challenge.Provider, error) { return dnsimple.NewDNSProvider() }
	default:
		return func() (challenge.Provider, error) {
			return nil, fmt.Errorf("unsupported dns provider %q (only dnsimple in phase 1)", name)
		}
	}
}

func defaultStateDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".swe-swe-tunnel")
	}
	return "./.swe-swe-tunnel"
}
