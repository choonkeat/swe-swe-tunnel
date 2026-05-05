package cert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
)

// StaticLoader serves pre-provisioned certs from disk and never talks
// to ACME. Pair with --no-acme on swe-swe-tunneld: an external
// orchestrator (lego, certbot, cert-manager, etc.) is responsible for
// dropping {state-dir}/lego/certificates/{base}.{crt,key} pairs into
// place; SIGHUP triggers a re-scan. No background renewal — the
// orchestrator owns that too.
//
// The on-disk layout matches what *Manager produces, so an operator
// switching from ACME-mode to --no-acme on an existing state dir keeps
// serving the same certs until they expire.
type StaticLoader struct {
	store    *certStore
	stateDir string
	apex     string
	logger   *slog.Logger
}

// NewStaticLoader builds an empty StaticLoader. Call LoadAllFromDisk
// before serving traffic to populate the in-memory table.
func NewStaticLoader(stateDir, apex string, logger *slog.Logger) *StaticLoader {
	if logger == nil {
		logger = slog.Default()
	}
	return &StaticLoader{
		store:    newCertStore(apex, logger),
		stateDir: stateDir,
		apex:     apex,
		logger:   logger,
	}
}

func (s *StaticLoader) certDir() string {
	return filepath.Join(s.stateDir, "lego", "certificates")
}

// EnsureName verifies a cert covering *.{label}.{apex} (or the exact
// hostname {label}.{apex}) is loaded. If not, it does a last-chance
// disk read for the conventional `_.{label}.{apex}.crt` filename in
// case the operator dropped a file but hasn't SIGHUPped yet. Returns
// `cert not provisioned for {label}` if still missing — that string
// is matched verbatim by the client's permanent-deny check.
func (s *StaticLoader) EnsureName(ctx context.Context, label string) error {
	if label == "" {
		return errors.New("ensure-name: empty label")
	}
	parent := label + "." + s.apex
	if s.store.has(parent) {
		return nil
	}
	baseName := "_." + parent
	if cert, ok, err := loadCertFile(s.certDir(), baseName); err == nil && ok {
		s.store.addEntry(&certEntry{
			cert:     cert,
			sans:     dnsNamesFromCert(cert),
			baseName: baseName,
		})
		s.logger.Info("loaded cert from disk on demand",
			"base", baseName, "sans", dnsNamesFromCert(cert))
		return nil
	}
	return fmt.Errorf("cert not provisioned for %s", label)
}

// GetCertificate is the tls.Config.GetCertificate hook.
func (s *StaticLoader) GetCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.store.getCertificate(ch)
}

// LoadAllFromDisk re-scans the cert dir. Idempotent: refreshes
// already-loaded entries with the latest disk state. Called on boot
// and on SIGHUP.
func (s *StaticLoader) LoadAllFromDisk() (int, error) {
	return s.store.loadAllFromDir(s.certDir())
}
