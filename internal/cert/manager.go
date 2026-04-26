// Package cert manages the apex wildcard certificate for the tunnel server.
//
// It embeds lego/v4 to obtain *.{apex} via DNS-01, persists state in a
// directory layout compatible with the lego CLI, and exposes a hot-swappable
// *tls.Certificate for use in tls.Config.GetCertificate.
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
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	renewBefore  = 30 * 24 * time.Hour
	checkEvery   = 24 * time.Hour
	leProduction = "https://acme-v02.api.letsencrypt.org/directory"
	leStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Manager holds the apex wildcard cert and renews it in the background.
type Manager struct {
	StateDir    string                          // ~/.swe-swe-tunnel
	Email       string                          // ACME account email
	Apex        string                          // e.g. "example.com"; cert covers Apex and *.Apex
	CADirURL    string                          // leProduction or leStaging
	NewProvider func() (challenge.Provider, error) // factory for a fresh DNS provider per call

	mu   sync.RWMutex
	cert *tls.Certificate

	logger *slog.Logger
}

// New constructs a Manager. CADirURL defaults to leProduction if empty.
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
		logger:      logger,
	}
}

// Domains returns the SAN list the apex cert must cover.
func (m *Manager) Domains() []string {
	return []string{m.Apex, "*." + m.Apex}
}

// Ensure loads an existing cert from disk if fresh, otherwise issues a new one.
// Must be called once before serving traffic.
func (m *Manager) Ensure(ctx context.Context) error {
	if err := os.MkdirAll(m.certDir(), 0o700); err != nil {
		return fmt.Errorf("mkdir cert dir: %w", err)
	}
	if err := os.MkdirAll(m.accountDir(), 0o700); err != nil {
		return fmt.Errorf("mkdir account dir: %w", err)
	}

	if cert, ok, err := m.loadFromDisk(); err != nil {
		return err
	} else if ok && expiresIn(cert) > renewBefore {
		m.logger.Info("loaded existing apex cert from disk",
			"apex", m.Apex,
			"expires_in", expiresIn(cert).Round(time.Hour))
		m.swap(cert)
		return nil
	}

	m.logger.Info("issuing apex cert", "apex", m.Apex, "ca", m.CADirURL)
	cert, err := m.obtain(ctx)
	if err != nil {
		return fmt.Errorf("obtain apex cert: %w", err)
	}
	m.swap(cert)
	return nil
}

// Run blocks, periodically renewing the cert. Returns when ctx is canceled.
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

// GetCertificate is a tls.Config.GetCertificate hook.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("no apex cert loaded")
	}
	return m.cert, nil
}

func (m *Manager) checkAndRenew(ctx context.Context) {
	m.mu.RLock()
	current := m.cert
	m.mu.RUnlock()
	if current == nil {
		return
	}
	if expiresIn(current) > renewBefore {
		return
	}
	m.logger.Info("renewing apex cert", "expires_in", expiresIn(current).Round(time.Hour))
	cert, err := m.obtain(ctx)
	if err != nil {
		m.logger.Error("renewal failed", "err", err)
		return
	}
	m.swap(cert)
	m.logger.Info("apex cert renewed", "expires_in", expiresIn(cert).Round(time.Hour))
}

func (m *Manager) swap(cert *tls.Certificate) {
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
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

func (m *Manager) certBaseName() string {
	return "_." + m.Apex
}

// loadFromDisk reads the previously-issued cert/key. Returns ok=false if no
// files exist; an error is returned only on corruption.
func (m *Manager) loadFromDisk() (*tls.Certificate, bool, error) {
	crtPath := filepath.Join(m.certDir(), m.certBaseName()+".crt")
	keyPath := filepath.Join(m.certDir(), m.certBaseName()+".key")
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

func (m *Manager) obtain(ctx context.Context) (*tls.Certificate, error) {
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
		Domains: m.Domains(),
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain: %w", err)
	}

	if err := m.saveResource(res); err != nil {
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

	// account key
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

	// registration metadata (optional — present after first registration)
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

func (m *Manager) saveResource(r *certificate.Resource) error {
	base := filepath.Join(m.certDir(), m.certBaseName())
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

// SetStaging configures the manager to use Let's Encrypt's staging environment.
// Useful during development to avoid burning rate-limit budget.
func (m *Manager) SetStaging() { m.CADirURL = leStaging }
