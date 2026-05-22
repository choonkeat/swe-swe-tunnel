package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/mtls"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// mtlsHarness wires up an in-process tunneld whose public TLS listener
// is gated by a fresh mTLS CA. A second "rejected" CA is also available
// so tests can construct certs that should fail verification.
type mtlsHarness struct {
	t           *testing.T
	tunneld     *httptest.Server
	apex        string
	ca          *mtls.CA
	rejectedCA  *mtls.CA
	serverRoots *x509.CertPool
	registry    *registry
	store       *identity.Store
	logger      *slog.Logger
	host        string
	serverName  string
}

func newMtlsHarness(t *testing.T) *mtlsHarness {
	t.Helper()
	apex := "tunnel.test"

	caDir := t.TempDir()
	if err := mtls.InitCA(caDir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	ca, err := mtls.LoadCA(caDir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	pool, _, err := mtls.LoadCABundle(filepath.Join(caDir, "ca.pem"))
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}

	rejectedDir := t.TempDir()
	if err := mtls.InitCA(rejectedDir, false); err != nil {
		t.Fatalf("rejected InitCA: %v", err)
	}
	rejected, err := mtls.LoadCA(rejectedDir)
	if err != nil {
		t.Fatalf("rejected LoadCA: %v", err)
	}

	store, err := identity.Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	reg := newRegistry()
	ipLim := ratelimit.New(0, time.Hour)
	keyLim := ratelimit.New(0, 24*time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ensurer := &fakeEnsurer{}

	apexHello := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("apex hello"))
	})
	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, store, ensurer, apex, ipLim, keyLim, nil, nil, logger))
	mux.Handle("/", route(reg, apex, nil, logger, apexHello))

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	u := mustURL(t, srv.URL)
	return &mtlsHarness{
		t:           t,
		tunneld:     srv,
		apex:        apex,
		ca:          ca,
		rejectedCA:  rejected,
		serverRoots: roots,
		registry:    reg,
		store:       store,
		logger:      logger,
		host:        u.Host,
		serverName:  u.Hostname(),
	}
}

// browserTLSConfig builds a TLS config for a browser-style client. Pass
// nil to omit the client cert (simulating "no cert presented").
func (h *mtlsHarness) browserTLSConfig(cert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		RootCAs:    h.serverRoots,
		ServerName: h.serverName,
		MinVersion: tls.VersionTLS12,
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return cfg
}

// browserClient builds an http.Client that always dials the tunneld's
// TLS listener, regardless of the request URL's host header.
func (h *mtlsHarness) browserClient(tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", h.host)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// issueP12 mints a fresh keypair + cert for cn against the accepted CA
// and returns a usable tls.Certificate (with a freshly generated key
// inside — this is the browser-user flow).
func (h *mtlsHarness) issueP12(cn string) tls.Certificate {
	h.t.Helper()
	bundle, err := h.ca.IssueClientCert(cn, time.Hour)
	if err != nil {
		h.t.Fatalf("IssueClientCert(%q): %v", cn, err)
	}
	cert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		h.t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// issueAgentCert signs an existing Ed25519 public key into a client
// cert against the accepted CA — the agent flow where identity.key
// doubles as the TLS keypair.
func (h *mtlsHarness) issueAgentCert(cn string, pub ed25519.PublicKey) []byte {
	h.t.Helper()
	pemBytes, err := h.ca.SignClientPubkey(cn, pub, time.Hour)
	if err != nil {
		h.t.Fatalf("SignClientPubkey(%q): %v", cn, err)
	}
	return pemBytes
}

// agentTLSCert pairs a cert PEM with an Ed25519 private key into a
// ready-to-use tls.Certificate. Matches what `swe-swe-tunnel` will do
// at boot with `--client-cert` + `--identity-key`.
func agentTLSCert(t *testing.T, certPEM []byte, priv ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// registerAgent runs the agent half of mTLS + Register: generates a
// keypair, signs a cert for it, dials the tunneld with the cert as TLS
// keypair, registers `unique`, and starts a reverse-proxy goroutine to
// the given backend. Returns the live session + a channel closed when
// the Serve goroutine returns.
func (h *mtlsHarness) registerAgent(ctx context.Context, unique string, backend *url.URL) (*tunnelclient.Session, <-chan struct{}) {
	h.t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	certPEM := h.issueAgentCert("agent-"+unique, pub)
	cert := agentTLSCert(h.t, certPEM, priv)

	agentTLS := &tls.Config{
		RootCAs:      h.serverRoots,
		ServerName:   h.serverName,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	sess, err := tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.tunneld.URL,
		Unique:     unique,
		PrivateKey: priv,
		TLSConfig:  agentTLS,
		Logger:     h.logger,
	})
	if err != nil {
		h.t.Fatalf("agent Connect: %v", err)
	}

	rp := httputil.NewSingleHostReverseProxy(backend)
	origDir := rp.Director
	rp.Director = func(req *http.Request) {
		host := req.Host
		origDir(req)
		req.Host = host
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tunnelclient.Serve(ctx, sess, rp)
	}()
	return sess, done
}

// --------------------------------------------------------------------------
// 1. Browser path: no client cert → handshake refused.
// --------------------------------------------------------------------------

func TestMTLS_BrowserGetWithoutCertRejected(t *testing.T) {
	h := newMtlsHarness(t)
	client := h.browserClient(h.browserTLSConfig(nil))

	_, err := client.Get(h.tunneld.URL + "/")
	if err == nil {
		t.Fatal("Get without client cert: expected TLS error, got success")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "certificate") && !strings.Contains(msg, "tls") {
		t.Errorf("error = %v, want a TLS/certificate alert", err)
	}
}

// --------------------------------------------------------------------------
// 2. Browser path: valid client cert → proxied through, X-Client-* set.
// --------------------------------------------------------------------------

func TestMTLS_BrowserGetWithValidCertProxies(t *testing.T) {
	h := newMtlsHarness(t)

	var mu sync.Mutex
	var observed http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, doneServe := h.registerAgent(ctx, "alpha", backendURL)
	t.Cleanup(func() {
		_ = sess.Close()
		cancel()
		<-doneServe
	})
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("registry never saw the session")
	}

	aliceCert := h.issueP12("alice")
	client := h.browserClient(h.browserTLSConfig(&aliceCert))
	tunneledHost := "1977.alpha-tunnel." + h.apex
	req, _ := http.NewRequest(http.MethodGet, "https://"+tunneledHost+"/", nil)
	req.Host = tunneledHost
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	cn := observed.Get("X-Client-CN")
	fp := observed.Get("X-Client-Cert-Fingerprint")
	mu.Unlock()
	if cn != "alice" {
		t.Errorf("backend saw X-Client-CN = %q, want %q", cn, "alice")
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("backend saw X-Client-Cert-Fingerprint = %q, want prefix sha256:", fp)
	}
}

// --------------------------------------------------------------------------
// 3. Browser path: cert signed by a different CA → handshake refused.
// --------------------------------------------------------------------------

func TestMTLS_BrowserGetWithWrongCAFails(t *testing.T) {
	h := newMtlsHarness(t)

	bundle, err := h.rejectedCA.IssueClientCert("eve", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	eveCert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := h.browserClient(h.browserTLSConfig(&eveCert))

	_, err = client.Get(h.tunneld.URL + "/")
	if err == nil {
		t.Fatal("Get with wrong-CA cert: expected TLS error, got success")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "certificate") && !strings.Contains(msg, "tls") {
		t.Errorf("error = %v, want a TLS/certificate alert", err)
	}
}

// --------------------------------------------------------------------------
// 4. Inbound X-Client-* headers from a malicious client must be stripped
//    and overwritten with the verified peer-cert identity before the
//    request reaches the upstream.
// --------------------------------------------------------------------------

func TestMTLS_HeadersStripped(t *testing.T) {
	h := newMtlsHarness(t)

	var mu sync.Mutex
	var observed http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, doneServe := h.registerAgent(ctx, "alpha", backendURL)
	t.Cleanup(func() {
		_ = sess.Close()
		cancel()
		<-doneServe
	})
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("registry never saw the session")
	}

	aliceCert := h.issueP12("alice")
	client := h.browserClient(h.browserTLSConfig(&aliceCert))
	tunneledHost := "1977.alpha-tunnel." + h.apex
	req, _ := http.NewRequest(http.MethodGet, "https://"+tunneledHost+"/", nil)
	req.Host = tunneledHost
	// A malicious browser tries to inject its own identity headers.
	// The daemon must strip them and re-write with the verified values
	// so an upstream that trusts these headers isn't fooled.
	req.Header.Set("X-Client-CN", "attacker")
	req.Header.Set("X-Client-Cert-Fingerprint", "sha256:deadbeef")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	cn := observed.Get("X-Client-CN")
	fp := observed.Get("X-Client-Cert-Fingerprint")
	mu.Unlock()
	if cn != "alice" {
		t.Errorf("backend saw X-Client-CN = %q, want %q (spoofed header survived)", cn, "alice")
	}
	if fp == "sha256:deadbeef" {
		t.Errorf("backend saw spoofed X-Client-Cert-Fingerprint = %q", fp)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("backend saw X-Client-Cert-Fingerprint = %q, want prefix sha256:", fp)
	}
}

// --------------------------------------------------------------------------
// 5. Agent path: no client cert → tunnelclient.Connect fails at the TLS
//    layer, never reaching Register.
// --------------------------------------------------------------------------

func TestMTLS_AgentConnectWithoutCertRejected(t *testing.T) {
	h := newMtlsHarness(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		RootCAs:    h.serverRoots,
		ServerName: h.serverName,
		MinVersion: tls.VersionTLS12,
		// No Certificates → no client cert.
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.tunneld.URL,
		Unique:     "alpha",
		PrivateKey: priv,
		TLSConfig:  tlsCfg,
		Logger:     h.logger,
	})
	if err == nil {
		t.Fatal("Connect without client cert: expected error")
	}
}

// --------------------------------------------------------------------------
// 6. Agent path: valid cert backed by the same Ed25519 key as the agent's
//    identity → full Register succeeds. Demonstrates the
//    "identity.key IS the TLS key" promise.
// --------------------------------------------------------------------------

func TestMTLS_AgentConnectWithValidCertSucceeds(t *testing.T) {
	h := newMtlsHarness(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, doneServe := h.registerAgent(ctx, "alpha", backendURL)
	t.Cleanup(func() {
		_ = sess.Close()
		cancel()
		<-doneServe
	})

	if want := "alpha-tunnel." + h.apex; sess.Hostname() != want {
		t.Errorf("hostname = %q, want %q", sess.Hostname(), want)
	}
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("registry never saw the session")
	}
}

// --------------------------------------------------------------------------
// 7. Agent path: TLS cert is for keypair A (signed by trusted CA), but
//    the Register payload claims pubkey B and signs with priv B. Both
//    signatures verify on their own — but the daemon must reject
//    because the TLS-authenticated identity disagrees with the
//    Register-claimed one. Deny shape: not_authorized.
// --------------------------------------------------------------------------

func TestMTLS_AgentConnectWithDifferentCertAndKeyFails(t *testing.T) {
	h := newMtlsHarness(t)

	_, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPub := certPriv.Public().(ed25519.PublicKey)
	certPEM := h.issueAgentCert("agent-A", certPub)
	tlsCert := agentTLSCert(t, certPEM, certPriv)

	_, registerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := &tls.Config{
		RootCAs:      h.serverRoots,
		ServerName:   h.serverName,
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.tunneld.URL,
		Unique:     "alpha",
		PrivateKey: registerPriv, // Register signs with B…
		TLSConfig:  tlsCfg,        // …but TLS cert is for A.
		Logger:     h.logger,
	})
	if err == nil {
		t.Fatal("Connect with cert/key mismatch: expected deny")
	}
	var de *tunnelclient.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *tunnelclient.DenyError", err)
	}
	if de.Reason != "not_authorized" {
		t.Errorf("Deny.Reason = %q, want %q", de.Reason, "not_authorized")
	}
}
