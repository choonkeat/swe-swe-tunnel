package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/mtls"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// regPortHarness wires up TWO in-process listeners that share one
// registry, identity store, rate limiters and allowlist — mirroring the
// production layout when --register-listen-without-mtls is set:
//
//   - mtlsSrv: RequireAndVerifyClientCert, full mux (proxy route() +
//     /v1/connect). The browser-facing listener.
//   - regSrv:  VerifyClientCertIfGiven, only /v1/connect + /healthz.
//     The cert-less registration listener.
//
// A tunnel registered through regSrv (no client cert) must be reachable
// through mtlsSrv's proxy, proving the shared registry.
type regPortHarness struct {
	t          *testing.T
	apex       string
	ca         *mtls.CA
	rejectedCA *mtls.CA
	registry   *registry
	store      *identity.Store
	logger     *slog.Logger

	mtlsSrv   *httptest.Server
	mtlsRoots *x509.CertPool
	mtlsHost  string
	mtlsName  string

	regSrv   *httptest.Server
	regRoots *x509.CertPool
	regName  string
}

func newRegPortHarness(t *testing.T, allow *allowlist.Set) *regPortHarness {
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
	skewLim := ratelimit.New(0, time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ensurer := &fakeEnsurer{}

	// Main (browser) listener — strict mTLS, full mux.
	apexHello := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("apex hello"))
	})
	mtlsMux := http.NewServeMux()
	mtlsMux.Handle("/v1/connect", connectHandler(reg, store, ensurer, apex, ipLim, keyLim, skewLim, allow, logger))
	mtlsMux.Handle("/", route(reg, apex, nil, logger, apexHello))
	mtlsSrv := httptest.NewUnstartedServer(mtlsMux)
	mtlsSrv.TLS = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	mtlsSrv.StartTLS()
	t.Cleanup(mtlsSrv.Close)

	// Register listener — cert-less, only /v1/connect + /healthz. The
	// VerifyClientCertIfGiven mode is exactly what registerTLSConfig
	// installs in production (the GetConfigForClient SIGHUP wiring is
	// covered separately by TestRegisterTLSConfig_SIGHUPLiveCA).
	regMux := http.NewServeMux()
	regMux.Handle("/v1/connect", connectHandler(reg, store, ensurer, apex, ipLim, keyLim, skewLim, allow, logger))
	regMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	regSrv := httptest.NewUnstartedServer(regMux)
	regSrv.TLS = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
	regSrv.StartTLS()
	t.Cleanup(regSrv.Close)

	mtlsRoots := x509.NewCertPool()
	mtlsRoots.AddCert(mtlsSrv.Certificate())
	regRoots := x509.NewCertPool()
	regRoots.AddCert(regSrv.Certificate())

	mu := mustURL(t, mtlsSrv.URL)
	ru := mustURL(t, regSrv.URL)

	return &regPortHarness{
		t:          t,
		apex:       apex,
		ca:         ca,
		rejectedCA: rejected,
		registry:   reg,
		store:      store,
		logger:     logger,
		mtlsSrv:    mtlsSrv,
		mtlsRoots:  mtlsRoots,
		mtlsHost:   mu.Host,
		mtlsName:   mu.Hostname(),
		regSrv:     regSrv,
		regRoots:   regRoots,
		regName:    ru.Hostname(),
	}
}

// certlessTLS is an agent TLS config that presents NO client cert.
func (h *regPortHarness) certlessTLS() *tls.Config {
	return &tls.Config{
		RootCAs:    h.regRoots,
		ServerName: h.regName,
		MinVersion: tls.VersionTLS12,
	}
}

// registerCertless dials the cert-less register listener, registers
// `unique` with no client cert, and serves a reverse proxy to backend.
func (h *regPortHarness) registerCertless(ctx context.Context, unique string, priv ed25519.PrivateKey, backend *url.URL) (*tunnelclient.Session, <-chan struct{}) {
	h.t.Helper()
	sess, err := tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.regSrv.URL,
		Unique:     unique,
		PrivateKey: priv,
		TLSConfig:  h.certlessTLS(),
		Logger:     h.logger,
	})
	if err != nil {
		h.t.Fatalf("cert-less Connect: %v", err)
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

// browserClient dials the mTLS listener; pass a cert to satisfy
// RequireAndVerifyClientCert.
func (h *regPortHarness) browserClient(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{
		RootCAs:    h.mtlsRoots,
		ServerName: h.mtlsName,
		MinVersion: tls.VersionTLS12,
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", h.mtlsHost)
			},
		},
		Timeout: 5 * time.Second,
	}
}

func (h *regPortHarness) issueBrowserCert(cn string) tls.Certificate {
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

// writeAllowFile drops a base64-RawStd allowlist file listing pubs.
func writeAllowFile(t *testing.T, dir string, pubs ...ed25519.PublicKey) {
	t.Helper()
	var b strings.Builder
	for _, p := range pubs {
		b.WriteString(base64.RawStdEncoding.EncodeToString(p))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "allow.pub"), []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
}

// --------------------------------------------------------------------------
// 1. Cross-listener: register cert-less on the register port, reach the
//    tunnel through the mTLS proxy. Proves the shared registry.
// --------------------------------------------------------------------------

func TestRegisterPort_CertlessRegisterReachableViaMTLSProxy(t *testing.T) {
	h := newRegPortHarness(t, nil)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	backendURL := mustURL(t, backend.URL)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, done := h.registerCertless(ctx, "alpha", priv, backendURL)
	t.Cleanup(func() {
		_ = sess.Close()
		cancel()
		<-done
	})
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("registry never saw the cert-less session")
	}

	// Browser must still present a valid client cert to the mTLS port.
	aliceCert := h.issueBrowserCert("alice")
	client := h.browserClient(&aliceCert)
	host := "1977.alpha-tunnel." + h.apex
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("browser Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-ok" {
		t.Errorf("body = %q, want %q", body, "backend-ok")
	}
}

// --------------------------------------------------------------------------
// 2. The proxy route() is NOT mounted on the register port: a tunnel-proxy
//    Host sent there is never reverse-proxied (404), so the browser data
//    plane can't be reached cert-less.
// --------------------------------------------------------------------------

func TestRegisterPort_ProxyHostNotServedOnRegisterPort(t *testing.T) {
	h := newRegPortHarness(t, nil)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("backend-ok"))
	}))
	defer backend.Close()
	backendURL := mustURL(t, backend.URL)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, done := h.registerCertless(ctx, "beta", priv, backendURL)
	t.Cleanup(func() {
		_ = sess.Close()
		cancel()
		<-done
	})
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("beta-tunnel") != nil }) {
		t.Fatal("registry never saw the cert-less session")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: h.certlessTLS(),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", mustURL(t, h.regSrv.URL).Host)
			},
		},
		Timeout: 5 * time.Second,
	}
	host := "1977.beta-tunnel." + h.apex
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (proxy must not be served on the register port)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "backend-ok") {
		t.Error("register port reverse-proxied to the backend; proxy route() must be unreachable there")
	}
}

// --------------------------------------------------------------------------
// 3. A client cert signed by an UNtrusted CA is still rejected at the
//    handshake — VerifyClientCertIfGiven verifies when a cert is given.
// --------------------------------------------------------------------------

func TestRegisterPort_UntrustedClientCertRejected(t *testing.T) {
	h := newRegPortHarness(t, nil)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	certPEM, err := h.rejectedCA.SignClientPubkey("agent-x", pub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := agentTLSCert(t, certPEM, priv)

	tlsCfg := h.certlessTLS()
	tlsCfg.Certificates = []tls.Certificate{cert}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.regSrv.URL,
		Unique:     "gamma",
		PrivateKey: priv,
		TLSConfig:  tlsCfg,
		Logger:     h.logger,
	})
	if err == nil {
		t.Fatal("Connect with untrusted client cert: expected handshake rejection")
	}
}

// --------------------------------------------------------------------------
// 4. Opportunistic cert binding: a cert-BEARING agent whose Register
//    pubkey differs from its cert pubkey is denied (cert_key_mismatch),
//    same as on the mTLS port. Cert-less agents skip this check; agents
//    that bring a cert still get it.
// --------------------------------------------------------------------------

func TestRegisterPort_CertKeyMismatchDenied(t *testing.T) {
	h := newRegPortHarness(t, nil)

	_, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPub := certPriv.Public().(ed25519.PublicKey)
	certPEM, err := h.ca.SignClientPubkey("agent-A", certPub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := agentTLSCert(t, certPEM, certPriv)

	_, registerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg := h.certlessTLS()
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.regSrv.URL,
		Unique:     "delta",
		PrivateKey: registerPriv, // Register signs with B…
		TLSConfig:  tlsCfg,        // …but the TLS cert is for A.
		Logger:     h.logger,
	})
	if err == nil {
		t.Fatal("Connect with cert/key mismatch on register port: expected deny")
	}
	var de *tunnelclient.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *tunnelclient.DenyError", err)
	}
	if de.Reason != "not_authorized" {
		t.Errorf("Deny.Reason = %q, want %q", de.Reason, "not_authorized")
	}
}

// --------------------------------------------------------------------------
// 5. The allowlist still gates the register port: a non-allowlisted key is
//    denied even cert-less, while an allowlisted key registers.
// --------------------------------------------------------------------------

func TestRegisterPort_AllowlistGatesCertlessRegister(t *testing.T) {
	dir := t.TempDir()
	_, allowedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeAllowFile(t, dir, allowedPriv.Public().(ed25519.PublicKey))
	allow, err := allowlist.Load(dir)
	if err != nil {
		t.Fatalf("allowlist.Load: %v", err)
	}
	h := newRegPortHarness(t, allow)

	// Non-allowlisted key → not_authorized.
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  h.regSrv.URL,
		Unique:     "stranger",
		PrivateKey: strangerPriv,
		TLSConfig:  h.certlessTLS(),
		Logger:     h.logger,
	})
	if err == nil {
		t.Fatal("non-allowlisted cert-less register: expected deny")
	}
	var de *tunnelclient.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *tunnelclient.DenyError", err)
	}
	if de.Reason != "not_authorized" {
		t.Errorf("Deny.Reason = %q, want %q", de.Reason, "not_authorized")
	}

	// Allowlisted key → registers.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer backend.Close()
	sess, done := h.registerCertless(ctx2, "friend", allowedPriv, mustURL(t, backend.URL))
	t.Cleanup(func() {
		_ = sess.Close()
		cancel2()
		<-done
	})
	if !waitFor(t, 5*time.Second, func() bool { return h.registry.get("friend-tunnel") != nil }) {
		t.Fatal("allowlisted cert-less register never reached the registry")
	}
}

// --------------------------------------------------------------------------
// 6. Boot guard: --register-listen-without-mtls requires both --mtls-ca
//    and --allowlist-dir.
// --------------------------------------------------------------------------

func TestValidateRegisterListen(t *testing.T) {
	cases := []struct {
		name         string
		addr         string
		mtlsCA       string
		allowlistDir string
		wantErr      string // "" = success expected
	}{
		{name: "empty addr is off (no other flags required)"},
		{name: "empty addr ignores other flags", mtlsCA: "/ca.pem"},
		{
			name:    "set without mtls-ca fails",
			addr:    ":8443",
			mtlsCA:  "",
			wantErr: "requires --mtls-ca",
		},
		{
			name:         "set with mtls-ca but no allowlist fails",
			addr:         ":8443",
			mtlsCA:       "/ca.pem",
			allowlistDir: "",
			wantErr:      "requires --allowlist-dir",
		},
		{
			name:         "set with both is OK",
			addr:         ":8443",
			mtlsCA:       "/ca.pem",
			allowlistDir: "/etc/allow",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRegisterListen(tc.addr, tc.mtlsCA, tc.allowlistDir)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("validateRegisterListen(%q,%q,%q) = %v; want nil",
						tc.addr, tc.mtlsCA, tc.allowlistDir, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRegisterListen(%q,%q,%q) = nil; want error containing %q",
					tc.addr, tc.mtlsCA, tc.allowlistDir, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %q; want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 7. registerTLSConfig: VerifyClientCertIfGiven + a CA pool read PER
//    handshake (through GetConfigForClient), so SIGHUP CA reloads take
//    effect on the register port too.
// --------------------------------------------------------------------------

func TestRegisterTLSConfig_SIGHUPLiveCA(t *testing.T) {
	caDirA := t.TempDir()
	if err := mtls.InitCA(caDirA, false); err != nil {
		t.Fatal(err)
	}
	caDirB := t.TempDir()
	if err := mtls.InitCA(caDirB, false); err != nil {
		t.Fatal(err)
	}
	certA := parseCA(t, filepath.Join(caDirA, "ca.pem"))
	certB := parseCA(t, filepath.Join(caDirB, "ca.pem"))

	target := filepath.Join(t.TempDir(), "trusted.pem")
	copyFile(t, filepath.Join(caDirA, "ca.pem"), target)
	b, err := loadMtlsBundle(target)
	if err != nil {
		t.Fatalf("loadMtlsBundle: %v", err)
	}

	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
	cfg := registerTLSConfig(getCert, b)
	if cfg.GetConfigForClient == nil {
		t.Fatal("registerTLSConfig: GetConfigForClient is nil (no per-handshake pool read)")
	}

	c1, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if c1.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", c1.ClientAuth)
	}
	if !poolTrusts(c1.ClientCAs, certA) {
		t.Error("pool does not trust CA A before reload")
	}
	if poolTrusts(c1.ClientCAs, certB) {
		t.Error("pool unexpectedly trusts CA B before reload")
	}

	// SIGHUP: swap the file to CA B and reload the bundle.
	copyFile(t, filepath.Join(caDirB, "ca.pem"), target)
	if err := b.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// A fresh handshake re-reads the pool through GetConfigForClient.
	c2, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Fatalf("GetConfigForClient after reload: %v", err)
	}
	if !poolTrusts(c2.ClientCAs, certB) {
		t.Error("after reload, fresh config does not trust CA B")
	}
	if poolTrusts(c2.ClientCAs, certA) {
		t.Error("after reload, fresh config still trusts CA A")
	}
}
