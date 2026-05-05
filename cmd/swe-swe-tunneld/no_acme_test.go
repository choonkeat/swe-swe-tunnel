package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/cert"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// noAcmeFixture wires an in-process tunneld whose certEnsurer is a
// real *cert.StaticLoader backed by a temp state dir. Tests drop
// {base}.{crt,key} pairs into stateDir/lego/certificates/ to control
// what the loader sees.
type noAcmeFixture struct {
	t        *testing.T
	tunneld  *httptest.Server
	apex     string
	stateDir string
	certDir  string
	loader   *cert.StaticLoader
	registry *registry
	store    *identity.Store
	tlsCfg   *tls.Config
	logger   *slog.Logger
}

func newNoAcmeFixture(t *testing.T) *noAcmeFixture {
	t.Helper()
	apex := "tunnel.test"
	stateDir := t.TempDir()
	certDir := filepath.Join(stateDir, "lego", "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}

	store, err := identity.Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	loader := cert.NewStaticLoader(stateDir, apex, logger)
	if _, err := loader.LoadAllFromDisk(); err != nil {
		t.Fatal(err)
	}

	reg := newRegistry()
	ipLim := ratelimit.New(0, time.Hour)
	keyLim := ratelimit.New(0, 24*time.Hour)

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, store, loader, apex, ipLim, keyLim, nil, nil, logger))
	mux.Handle("/", route(reg, apex, nil, logger, http.NotFoundHandler()))

	tunneld := httptest.NewTLSServer(mux)
	t.Cleanup(tunneld.Close)

	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: mustURL(t, tunneld.URL).Hostname(),
		MinVersion: tls.VersionTLS12,
	}

	return &noAcmeFixture{
		t:        t,
		tunneld:  tunneld,
		apex:     apex,
		stateDir: stateDir,
		certDir:  certDir,
		loader:   loader,
		registry: reg,
		store:    store,
		tlsCfg:   tlsCfg,
		logger:   logger,
	}
}

// dropTunnelCert writes the wildcard cert pair StaticLoader expects
// for the per-session label `{label}-tunnel.{apex}` (i.e. baseName
// `_.{label}-tunnel.{apex}`).
func (f *noAcmeFixture) dropTunnelCert(label string) {
	f.t.Helper()
	parent := label + "-tunnel." + f.apex
	writeSelfSignedCertPair(f.t, f.certDir, "_."+parent, parent, "*."+parent)
}

func (f *noAcmeFixture) connect(ctx context.Context, unique string, priv ed25519.PrivateKey) (*tunnelclient.Session, error) {
	return tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  f.tunneld.URL,
		Unique:     unique,
		PrivateKey: priv,
		TLSConfig:  f.tlsCfg,
		Logger:     f.logger,
	})
}

// writeSelfSignedCertPair generates a short-lived self-signed cert
// with the given DNS SANs and writes {dir}/{base}.crt + {base}.key.
// Lives here rather than reusing cert/manager_test.go because that
// helper is in the cert package's test scope.
func writeSelfSignedCertPair(t *testing.T, dir, base string, dnsNames ...string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, base+".crt"), crtPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestNoAcme_PreProvisionedCertServed: with the per-session cert
// already on disk at boot, Connect must succeed and the SNI dispatch
// for the resulting hostname must return the dropped cert (proving
// StaticLoader is wired into both EnsureName and GetCertificate).
func TestNoAcme_PreProvisionedCertServed(t *testing.T) {
	f := newNoAcmeFixture(t)
	f.dropTunnelCert("alpha")
	if _, err := f.loader.LoadAllFromDisk(); err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := f.connect(ctx, "alpha", priv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if want := "alpha-tunnel." + f.apex; sess.Hostname() != want {
		t.Errorf("hostname = %q, want %q", sess.Hostname(), want)
	}

	// The StaticLoader must serve the dropped cert via GetCertificate
	// for both the parent and a wildcard child SNI.
	for _, sni := range []string{
		"alpha-tunnel." + f.apex,
		"1977.alpha-tunnel." + f.apex,
	} {
		got, err := f.loader.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Errorf("GetCertificate(%q): %v", sni, err)
			continue
		}
		if !slices.Contains(got.Leaf.DNSNames, "*.alpha-tunnel."+f.apex) {
			t.Errorf("GetCertificate(%q) returned cert with SANs %v, want to include *.alpha-tunnel.%s",
				sni, got.Leaf.DNSNames, f.apex)
		}
	}
}

// TestNoAcme_MissingCertReturnsPermanentDeny: with no cert on disk
// for the requested label, the server must reply with the well-known
// "cert not provisioned" deny reason and the client must classify it
// as permanent (no retry loop).
func TestNoAcme_MissingCertReturnsPermanentDeny(t *testing.T) {
	f := newNoAcmeFixture(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = f.connect(ctx, "ghost", priv)
	if err == nil {
		t.Fatal("Connect: want deny error, got nil")
	}
	var de *tunnelclient.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("Connect err = %v (%T); want *tunnelclient.DenyError", err, err)
	}
	if de.Reason != "cert not provisioned" {
		t.Errorf("Deny.Reason = %q, want %q", de.Reason, "cert not provisioned")
	}
	if !de.IsPermanent() {
		t.Errorf("DenyError.IsPermanent() = false; want true so the client supervisor exits "+
			"instead of looping (Reason=%q)", de.Reason)
	}
}

// TestNoAcme_SighupReloadPicksUpNewCert: start empty (Connect fails
// permanent-deny), drop the cert mid-test, run the SIGHUP equivalent
// (reloadCerts), Connect again, expect success. This is the canonical
// --no-acme operator workflow: external orchestrator drops a fresh
// cert, sends SIGHUP, tunnel comes online without a restart.
func TestNoAcme_SighupReloadPicksUpNewCert(t *testing.T) {
	f := newNoAcmeFixture(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First attempt: empty disk → permanent deny.
	if _, err := f.connect(ctx, "beta", priv); err == nil {
		t.Fatal("expected deny on first attempt with empty cert dir")
	} else {
		var de *tunnelclient.DenyError
		if !errors.As(err, &de) || de.Reason != "cert not provisioned" {
			t.Fatalf("first Connect err = %v; want Deny{cert not provisioned}", err)
		}
	}

	// Operator drops the cert and SIGHUPs.
	f.dropTunnelCert("beta")
	reloadCerts(f.loader, f.logger)

	// Second attempt: must now succeed.
	sess, err := f.connect(ctx, "beta", priv)
	if err != nil {
		t.Fatalf("post-reload Connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	if want := "beta-tunnel." + f.apex; sess.Hostname() != want {
		t.Errorf("hostname = %q, want %q", sess.Hostname(), want)
	}
}

// TestNoAcme_NoEmailRequired exercises the boot-time required-flag
// validator. With --no-acme set, --acme-email must NOT be required;
// without --no-acme it must be required (regression guard for the
// split that landed with --no-acme).
func TestNoAcme_NoEmailRequired(t *testing.T) {
	cases := []struct {
		name    string
		apex    string
		email   string
		noAcme  bool
		wantErr string // "" = success expected
	}{
		{
			name:   "no-acme + apex set + empty email is OK",
			apex:   "example.com",
			email:  "",
			noAcme: true,
		},
		{
			name:    "no-acme + empty apex still fails on apex",
			apex:    "",
			email:   "",
			noAcme:  true,
			wantErr: "--apex-domain is required",
		},
		{
			name:    "ACME mode + empty email fails on email",
			apex:    "example.com",
			email:   "",
			noAcme:  false,
			wantErr: "--acme-email is required",
		},
		{
			name:   "ACME mode + apex + email is OK",
			apex:   "example.com",
			email:  "ops@example.com",
			noAcme: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireFlags(tc.apex, tc.email, tc.noAcme)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("requireFlags(%q, %q, %v) = %v; want nil",
						tc.apex, tc.email, tc.noAcme, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("requireFlags(%q, %q, %v) = nil; want error containing %q",
					tc.apex, tc.email, tc.noAcme, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("requireFlags err = %q; want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
