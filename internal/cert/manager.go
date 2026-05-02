// Package cert manages wildcard certificates for the tunnel server.
//
// The manager holds an apex wildcard (*.{Apex}) for the public landing page
// and the control-channel hostname, plus zero or more per-session wildcards
// (*.{label}.{Apex}) for tunneled subdomains. Each cert is obtained via lego
// DNS-01 and persisted in a directory layout compatible with the lego CLI.
// tls.Config.GetCertificate dispatches by SNI: exact match first, then a
// one-level wildcard match, then falls back to the apex cert.
package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/sync/singleflight"
)

const (
	renewBefore  = 30 * 24 * time.Hour
	checkEvery   = 24 * time.Hour
	leProduction = "https://acme-v02.api.letsencrypt.org/directory"
	leStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Manager holds the apex wildcard cert plus any per-session wildcards, and
// renews them in the background.
type Manager struct {
	StateDir    string
	Email       string
	Apex        string
	CADirURL    string
	NewProvider func() (challenge.Provider, error)

	mu       sync.RWMutex
	entries  map[string]*certEntry // baseName → entry
	exact    map[string]*certEntry // exact-match SAN → entry
	wildcard map[string]*certEntry // wildcard parent (e.g. "example.com") → entry

	// issueGroup coalesces concurrent ensureSANs calls for the same
	// baseName. Without it, two parallel Register attempts for the same
	// `unique` each kick off a full ACME flow against Let's Encrypt;
	// the parallel TXT-record cleanup steps step on each other and one
	// of the flows fails with "no TXT record found." See bug 2 in
	// commit ceba11d's parent log.
	issueGroup singleflight.Group

	// obtainOverride, if non-nil, replaces the real ACME-backed obtain
	// in ensureSANs. Only set in tests; production constructs a Manager
	// via New, which leaves it nil.
	obtainOverride func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error)

	logger *slog.Logger
}

type certEntry struct {
	cert     *tls.Certificate
	sans     []string
	baseName string
}

// New constructs a Manager. CADirURL defaults to leProduction.
func New(stateDir, email, apex string, newProvider func() (challenge.Provider, error), logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		StateDir:    stateDir,
		Email:       email,
		Apex:        apex,
		CADirURL:    leProduction,
		NewProvider: newProvider,
		entries:     make(map[string]*certEntry),
		exact:       make(map[string]*certEntry),
		wildcard:    make(map[string]*certEntry),
		logger:      logger,
	}
}

// Domains returns the SAN list the apex cert must cover.
func (m *Manager) Domains() []string {
	return []string{m.Apex, "*." + m.Apex}
}

// Ensure loads the apex cert from disk if fresh, otherwise issues a new one.
// Must be called once before serving traffic.
func (m *Manager) Ensure(ctx context.Context) error {
	return m.ensureSANs(ctx, m.Domains(), m.apexBaseName())
}

// EnsureName issues (or loads if fresh on disk) a wildcard cert for
// *.{label}.{Apex}. Idempotent.
//
// label is the host portion immediately to the left of Apex — e.g. "test-tunnel"
// for the per-session hostname "test-tunnel.example.com" (covering ports as
// "1977.test-tunnel.example.com" etc).
func (m *Manager) EnsureName(ctx context.Context, label string) error {
	if label == "" {
		return errors.New("ensure-name: empty label")
	}
	parent := label + "." + m.Apex
	sans := []string{parent, "*." + parent}
	return m.ensureSANs(ctx, sans, "_."+parent)
}

// LoadAllFromDisk walks the cert directory and loads every cert file it finds
// into the manager. Safe to call repeatedly; certs already loaded are
// overwritten with the latest disk state. Returns the number of certs loaded.
func (m *Manager) LoadAllFromDisk() (int, error) {
	if err := os.MkdirAll(m.certDir(), 0o700); err != nil {
		return 0, fmt.Errorf("mkdir cert dir: %w", err)
	}
	entries, err := os.ReadDir(m.certDir())
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
		cert, ok, err := m.loadCertFile(baseName)
		if err != nil {
			m.logger.Warn("skipping cert with load error", "file", name, "err", err)
			continue
		}
		if !ok {
			continue
		}
		sans := dnsNamesFromCert(cert)
		m.addEntry(&certEntry{cert: cert, sans: sans, baseName: baseName})
		m.logger.Info("loaded cert from disk",
			"base", baseName,
			"sans", sans,
			"expires_in", expiresIn(cert).Round(time.Hour))
		n++
	}
	return n, nil
}

// Run blocks, periodically renewing certs. Returns when ctx is canceled.
func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			m.checkAndRenew(ctx)
		}
	}
}

// GetCertificate is a tls.Config.GetCertificate hook. Picks a cert by SNI:
// exact-match first, then a one-level wildcard match, then falls back to the
// apex cert.
func (m *Manager) GetCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := normalizeSNI(ch.ServerName)
	m.mu.RLock()
	defer m.mu.RUnlock()

	if e := m.exact[sni]; e != nil {
		return e.cert, nil
	}
	if i := strings.Index(sni, "."); i >= 0 {
		if e := m.wildcard[sni[i+1:]]; e != nil {
			return e.cert, nil
		}
	}
	if e := m.exact[m.Apex]; e != nil {
		return e.cert, nil
	}
	if e := m.wildcard[m.Apex]; e != nil {
		return e.cert, nil
	}
	return nil, fmt.Errorf("no certificate for SNI %q", ch.ServerName)
}

func (m *Manager) ensureSANs(ctx context.Context, sans []string, baseName string) error {
	if err := os.MkdirAll(m.certDir(), 0o700); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}
	if err := os.MkdirAll(m.accountDir(), 0o700); err != nil {
		return fmt.Errorf("mkdir account dir: %w", err)
	}

	// Fast path: cert is already on disk and fresh. Outside the
	// singleflight group so a quiescent in-process restart that hits
	// EnsureName(label) for many already-issued labels doesn't
	// serialize behind one singleflight key per label.
	if cert, ok, err := m.loadCertFile(baseName); err != nil {
		return err
	} else if ok && expiresIn(cert) > renewBefore {
		m.logger.Info("loaded existing cert from disk",
			"base", baseName,
			"expires_in", expiresIn(cert).Round(time.Hour))
		m.addEntry(&certEntry{cert: cert, sans: dnsNamesFromCert(cert), baseName: baseName})
		return nil
	}

	// Slow path: needs an ACME flow. Coalesce concurrent callers for
	// the same baseName into a single in-flight Issue so retries
	// during in-flight cert issuance don't fire parallel ACME flows
	// (which race each other's TXT-record cleanup and waste LE quota).
	_, err, _ := m.issueGroup.Do(baseName, func() (any, error) {
		// Re-check disk inside the group: a concurrent leader may
		// have just landed it. If so, take that and skip ACME.
		if cert, ok, err := m.loadCertFile(baseName); err != nil {
			return nil, err
		} else if ok && expiresIn(cert) > renewBefore {
			m.logger.Info("loaded existing cert from disk",
				"base", baseName,
				"expires_in", expiresIn(cert).Round(time.Hour))
			m.addEntry(&certEntry{cert: cert, sans: dnsNamesFromCert(cert), baseName: baseName})
			return nil, nil
		}

		m.logger.Info("issuing cert", "sans", sans, "ca", m.CADirURL)
		obtain := m.obtain
		if m.obtainOverride != nil {
			obtain = m.obtainOverride
		}
		cert, err := obtain(ctx, sans, baseName)
		if err != nil {
			return nil, fmt.Errorf("obtain cert %v: %w", sans, err)
		}
		m.addEntry(&certEntry{cert: cert, sans: sans, baseName: baseName})
		return nil, nil
	})
	return err
}

func (m *Manager) checkAndRenew(ctx context.Context) {
	m.mu.RLock()
	snapshot := make([]*certEntry, 0, len(m.entries))
	for _, e := range m.entries {
		snapshot = append(snapshot, e)
	}
	m.mu.RUnlock()

	for _, e := range snapshot {
		if expiresIn(e.cert) > renewBefore {
			continue
		}
		m.logger.Info("renewing cert", "base", e.baseName, "expires_in", expiresIn(e.cert).Round(time.Hour))
		cert, err := m.obtain(ctx, e.sans, e.baseName)
		if err != nil {
			m.logger.Error("renewal failed", "base", e.baseName, "err", err)
			continue
		}
		m.addEntry(&certEntry{cert: cert, sans: e.sans, baseName: e.baseName})
		m.logger.Info("cert renewed", "base", e.baseName, "expires_in", expiresIn(cert).Round(time.Hour))
	}
}

func (m *Manager) addEntry(e *certEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.entries[e.baseName]; ok {
		m.removeEntryFromIndexLocked(old)
	}
	m.entries[e.baseName] = e
	for _, name := range dnsNamesFromCert(e.cert) {
		if strings.HasPrefix(name, "*.") {
			m.wildcard[name[2:]] = e
		} else {
			m.exact[name] = e
		}
	}
}

func (m *Manager) removeEntryFromIndexLocked(e *certEntry) {
	for _, name := range dnsNamesFromCert(e.cert) {
		if strings.HasPrefix(name, "*.") {
			if cur, ok := m.wildcard[name[2:]]; ok && cur == e {
				delete(m.wildcard, name[2:])
			}
		} else {
			if cur, ok := m.exact[name]; ok && cur == e {
				delete(m.exact, name)
			}
		}
	}
}

func (m *Manager) accountDir() string {
	caHost := "acme-v02.api.letsencrypt.org"
	if m.CADirURL == leStaging {
		caHost = "acme-staging-v02.api.letsencrypt.org"
	}
	return filepath.Join(m.StateDir, "lego", "accounts", caHost, m.Email)
}

func (m *Manager) certDir() string {
	return filepath.Join(m.StateDir, "lego", "certificates")
}

func (m *Manager) apexBaseName() string {
	return "_." + m.Apex
}

// loadCertFile reads a cert + key pair by basename. Returns ok=false if no
// .crt file exists; an error is returned only on corruption or partial state.
func (m *Manager) loadCertFile(baseName string) (*tls.Certificate, bool, error) {
	crtPath := filepath.Join(m.certDir(), baseName+".crt")
	keyPath := filepath.Join(m.certDir(), baseName+".key")
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

func (m *Manager) obtain(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
	user, err := m.loadOrCreateUser()
	if err != nil {
		return nil, err
	}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = m.CADirURL
	cfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}

	provider, err := m.NewProvider()
	if err != nil {
		return nil, fmt.Errorf("dns provider: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("set dns-01: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register account: %w", err)
		}
		user.Registration = reg
		if err := m.saveUser(user); err != nil {
			return nil, fmt.Errorf("save account: %w", err)
		}
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: sans,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain: %w", err)
	}

	if err := m.saveResource(res, baseName); err != nil {
		return nil, fmt.Errorf("save cert: %w", err)
	}

	cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("build keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	cert.Leaf = leaf
	return &cert, nil
}

// --- account persistence (lego-CLI-compatible layout) ---------------------

type acmeUser struct {
	Email        string                 `json:"-"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (m *Manager) accountFiles() (key, meta string) {
	return filepath.Join(m.accountDir(), "account.key"),
		filepath.Join(m.accountDir(), "account.json")
}

func (m *Manager) loadOrCreateUser() (*acmeUser, error) {
	keyPath, metaPath := m.accountFiles()

	var priv crypto.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("account key: not PEM")
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse account key: %w", err)
		}
		priv = k
	} else if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("gen account key: %w", err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal account key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
			return nil, fmt.Errorf("write account key: %w", err)
		}
		priv = k
	} else {
		return nil, fmt.Errorf("read account key: %w", err)
	}

	user := &acmeUser{Email: m.Email, key: priv}

	if data, err := os.ReadFile(metaPath); err == nil {
		var u acmeUser
		if err := json.Unmarshal(data, &u); err != nil {
			return nil, fmt.Errorf("parse account.json: %w", err)
		}
		user.Registration = u.Registration
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read account.json: %w", err)
	}

	return user, nil
}

func (m *Manager) saveUser(u *acmeUser) error {
	_, metaPath := m.accountFiles()
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, data, 0o600)
}

// --- cert persistence -----------------------------------------------------

func (m *Manager) saveResource(r *certificate.Resource, baseName string) error {
	base := filepath.Join(m.certDir(), baseName)
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{base + ".crt", r.Certificate, 0o600},
		{base + ".key", r.PrivateKey, 0o600},
	}
	for _, f := range files {
		if err := writeAtomic(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func expiresIn(c *tls.Certificate) time.Duration {
	if c.Leaf == nil {
		return 0
	}
	return time.Until(c.Leaf.NotAfter)
}

func dnsNamesFromCert(c *tls.Certificate) []string {
	if c == nil || c.Leaf == nil {
		return nil
	}
	out := make([]string, 0, len(c.Leaf.DNSNames))
	for _, n := range c.Leaf.DNSNames {
		out = append(out, strings.ToLower(n))
	}
	return out
}

func normalizeSNI(s string) string {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// SetStaging configures the manager to use Let's Encrypt's staging environment.
// Useful during development to avoid burning rate-limit budget.
func (m *Manager) SetStaging() { m.CADirURL = leStaging }
