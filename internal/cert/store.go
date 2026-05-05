package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// certStore owns the in-memory cert table and the SNI dispatch hot
// path. Both Manager (ACME-driven) and StaticLoader (--no-acme,
// pre-provisioned certs) embed one so they publish identical
// SNI-dispatch and disk-load semantics.
//
// Apex is captured at construction so the dispatch can fall back to
// the apex cert when no exact or wildcard match exists for an SNI.
type certStore struct {
	apex   string
	logger *slog.Logger

	mu       sync.RWMutex
	entries  map[string]*certEntry // baseName → entry
	exact    map[string]*certEntry // exact-match SAN → entry
	wildcard map[string]*certEntry // wildcard parent (e.g. "example.com") → entry
}

func newCertStore(apex string, logger *slog.Logger) *certStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &certStore{
		apex:     apex,
		logger:   logger,
		entries:  make(map[string]*certEntry),
		exact:    make(map[string]*certEntry),
		wildcard: make(map[string]*certEntry),
	}
}

// addEntry inserts (or replaces by baseName) and rebuilds the per-SAN
// indexes. Safe to call from any goroutine.
func (s *certStore) addEntry(e *certEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.entries[e.baseName]; ok {
		s.removeFromIndexLocked(old)
	}
	s.entries[e.baseName] = e
	for _, name := range dnsNamesFromCert(e.cert) {
		if strings.HasPrefix(name, "*.") {
			s.wildcard[name[2:]] = e
		} else {
			s.exact[name] = e
		}
	}
}

func (s *certStore) removeFromIndexLocked(e *certEntry) {
	for _, name := range dnsNamesFromCert(e.cert) {
		if strings.HasPrefix(name, "*.") {
			if cur, ok := s.wildcard[name[2:]]; ok && cur == e {
				delete(s.wildcard, name[2:])
			}
		} else {
			if cur, ok := s.exact[name]; ok && cur == e {
				delete(s.exact, name)
			}
		}
	}
}

// getCertificate is the tls.Config.GetCertificate hot path. Picks a
// cert by SNI: exact-match first, then a one-level wildcard match,
// then falls back to the apex cert.
func (s *certStore) getCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := normalizeSNI(ch.ServerName)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if e := s.exact[sni]; e != nil {
		return e.cert, nil
	}
	if i := strings.Index(sni, "."); i >= 0 {
		if e := s.wildcard[sni[i+1:]]; e != nil {
			return e.cert, nil
		}
	}
	if e := s.exact[s.apex]; e != nil {
		return e.cert, nil
	}
	if e := s.wildcard[s.apex]; e != nil {
		return e.cert, nil
	}
	return nil, fmt.Errorf("no certificate for SNI %q", ch.ServerName)
}

// has reports whether an entry covering fqdn (exact match or one-level
// wildcard) is currently loaded.
func (s *certStore) has(fqdn string) bool {
	fqdn = normalizeSNI(fqdn)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.exact[fqdn]; ok {
		return true
	}
	if i := strings.Index(fqdn, "."); i >= 0 {
		if _, ok := s.wildcard[fqdn[i+1:]]; ok {
			return true
		}
	}
	return false
}

// snapshot returns a copy of the current entries slice for iteration
// without holding the lock.
func (s *certStore) snapshot() []*certEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*certEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out
}

// loadAllFromDir walks dir and loads every {base}.crt + {base}.key
// pair it finds, addEntry-ing each. Already-loaded entries are
// refreshed. Broken pairs log+skip rather than aborting the whole
// scan. Returns the number of certs loaded.
func (s *certStore) loadAllFromDir(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("mkdir cert dir: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read cert dir: %w", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".crt") {
			continue
		}
		baseName := strings.TrimSuffix(name, ".crt")
		cert, ok, err := loadCertFile(dir, baseName)
		if err != nil {
			s.logger.Warn("skipping cert with load error", "file", name, "err", err)
			continue
		}
		if !ok {
			continue
		}
		sans := dnsNamesFromCert(cert)
		s.addEntry(&certEntry{cert: cert, sans: sans, baseName: baseName})
		s.logger.Info("loaded cert from disk",
			"base", baseName,
			"sans", sans,
			"expires_in", expiresIn(cert).Round(time.Hour))
		n++
	}
	return n, nil
}

// loadCertFile reads {dir}/{baseName}.crt + {dir}/{baseName}.key.
// Returns ok=false if no .crt file exists; an error is returned only
// on corruption or partial state (e.g. .crt without matching .key).
func loadCertFile(dir, baseName string) (*tls.Certificate, bool, error) {
	crtPath := filepath.Join(dir, baseName+".crt")
	keyPath := filepath.Join(dir, baseName+".key")
	crt, err := os.ReadFile(crtPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read crt: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("read key: %w", err)
	}
	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, false, fmt.Errorf("parse keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, false, fmt.Errorf("parse leaf: %w", err)
	}
	cert.Leaf = leaf
	return &cert, true, nil
}
