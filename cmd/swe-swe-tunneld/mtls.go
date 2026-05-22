package main

import (
	"crypto/x509"
	"log/slog"
	"sync"

	"github.com/choonkeat/swe-swe-tunnel/internal/mtls"
)

// mtlsBundle holds the trusted CA pool for the public listener's
// client-cert verification. Set at boot from --mtls-ca and reloaded
// via SIGHUP. The active pool is read on every TLS handshake (through
// tls.Config.GetConfigForClient in main), so updates take effect for
// new connections without restarting the listener.
type mtlsBundle struct {
	path string

	mu   sync.RWMutex
	pool *x509.CertPool
	n    int
}

// loadMtlsBundle reads path once at boot. Subsequent SIGHUPs call
// (*mtlsBundle).Reload on the same struct.
func loadMtlsBundle(path string) (*mtlsBundle, error) {
	pool, n, err := mtls.LoadCABundle(path)
	if err != nil {
		return nil, err
	}
	return &mtlsBundle{path: path, pool: pool, n: n}, nil
}

// Pool returns the active CertPool. Cheap; safe to call per handshake.
func (b *mtlsBundle) Pool() *x509.CertPool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool
}

// Count returns the number of CERTIFICATE blocks in the current pool.
// Exposed for boot/reload logs so operators can spot a truncated file.
func (b *mtlsBundle) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.n
}

// Path returns the file path used at boot. Re-used by Reload.
func (b *mtlsBundle) Path() string { return b.path }

// Reload re-reads the bundle from disk and atomically swaps the pool.
// On error the prior pool is preserved (same shape as the allowlist
// reload arm: a typo'd or vanished file mid-flight must not flip the
// gate open or reject everyone).
func (b *mtlsBundle) Reload() error {
	pool, n, err := mtls.LoadCABundle(b.path)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.pool = pool
	b.n = n
	b.mu.Unlock()
	return nil
}

// reloadMtlsBundle is the SIGHUP hook. Idempotent; logs success or
// failure and keeps the prior pool on error.
func reloadMtlsBundle(b *mtlsBundle, logger *slog.Logger) {
	if b == nil {
		return
	}
	if err := b.Reload(); err != nil {
		logger.Error("mTLS CA reload failed",
			"path", b.Path(), "err", err, "keeping_previous", true)
		return
	}
	logger.Info("mTLS CA reloaded", "path", b.Path(), "count", b.Count())
}
