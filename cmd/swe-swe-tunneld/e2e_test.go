package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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

	"golang.org/x/net/websocket"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// e2eSuite owns the in-process tunneld plus the dependencies a test client
// needs to connect.
type e2eSuite struct {
	t        *testing.T
	tunneld  *httptest.Server
	apex     string
	registry *registry
	store    *identity.Store
	ensurer  *fakeEnsurer
	logger   *slog.Logger
	tlsCfg   *tls.Config
	// allowDir is set only when the suite was built with newE2ESuiteWithAllowlist.
	// Tests use it to add/remove key files between Reload calls.
	allow    *allowlist.Set
	allowDir string
}

func newE2ESuite(t *testing.T) *e2eSuite {
	t.Helper()
	return newE2ESuiteWith(t, nil, "")
}

// newE2ESuiteWithAllowlist builds the same in-process tunneld as
// newE2ESuite but with the gate enabled. The returned suite carries the
// directory path so tests can drop/remove key files and trigger
// reloadAllowlistAndRevoke directly (signal delivery is a separate
// concern unit-tested elsewhere).
func newE2ESuiteWithAllowlist(t *testing.T, allowedPubs ...ed25519.PublicKey) *e2eSuite {
	t.Helper()
	dir := t.TempDir()
	for i, pub := range allowedPubs {
		b64 := base64.RawStdEncoding.EncodeToString(pub)
		name := filepath.Join(dir, fmt.Sprintf("k%d.pub", i))
		if err := os.WriteFile(name, []byte(b64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := allowlist.Load(dir)
	if err != nil {
		t.Fatalf("allowlist.Load: %v", err)
	}
	return newE2ESuiteWith(t, set, dir)
}

func newE2ESuiteWith(t *testing.T, allow *allowlist.Set, allowDir string) *e2eSuite {
	t.Helper()
	apex := "tunnel.test"
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
	mux.Handle("/v1/connect", connectHandler(reg, store, ensurer, apex, ipLim, keyLim, allow, logger))
	mux.Handle("/", route(reg, apex, apexHello))

	tunneld := httptest.NewTLSServer(mux)
	t.Cleanup(tunneld.Close)

	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: mustURL(t, tunneld.URL).Hostname(),
		MinVersion: tls.VersionTLS12,
	}

	return &e2eSuite{
		t:        t,
		tunneld:  tunneld,
		apex:     apex,
		registry: reg,
		store:    store,
		ensurer:  ensurer,
		logger:   logger,
		tlsCfg:   tlsCfg,
		allow:    allow,
		allowDir: allowDir,
	}
}

// addAllowedKey drops a key file for pub into the suite's allowlist
// directory under the given filename. Caller is responsible for
// triggering a reload.
func (s *e2eSuite) addAllowedKey(name string, pub ed25519.PublicKey) {
	s.t.Helper()
	if s.allowDir == "" {
		s.t.Fatal("addAllowedKey on a suite without allowlist")
	}
	b64 := base64.RawStdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(s.allowDir, name), []byte(b64+"\n"), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

// removeAllowedKey deletes the named file from the allowlist directory.
func (s *e2eSuite) removeAllowedKey(name string) {
	s.t.Helper()
	if err := os.Remove(filepath.Join(s.allowDir, name)); err != nil {
		s.t.Fatal(err)
	}
}

// reloadAllowlist re-reads the allowlist directory and drops any live
// sessions whose pubkey is no longer authorized. Equivalent in effect
// to a SIGHUP delivered to the daemon, but called directly to keep the
// test off the OS signal-delivery path.
func (s *e2eSuite) reloadAllowlist() {
	s.t.Helper()
	if s.allow == nil {
		s.t.Fatal("reloadAllowlist on a suite without allowlist")
	}
	reloadAllowlistAndRevoke(s.allow, s.registry, s.logger)
}

// dialAndRegister runs the real tunnelclient.Connect against the suite's
// tunneld with the given unique + private key.
func (s *e2eSuite) dialAndRegister(ctx context.Context, unique string, priv ed25519.PrivateKey) (*tunnelclient.Session, error) {
	return tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  s.tunneld.URL,
		Unique:     unique,
		PrivateKey: priv,
		TLSConfig:  s.tlsCfg,
		Logger:     s.logger,
	})
}

// httpClient returns an http.Client whose Transport always dials the actual
// tunneld TLS listener regardless of the request URL's host. Lets tests
// rewrite Host to a tunneled hostname.
func (s *e2eSuite) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.tlsCfg.Clone(),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", mustURL(s.t, s.tunneld.URL).Host)
			},
		},
		Timeout: 5 * time.Second,
	}
}

// servePassthrough runs Serve in a goroutine with a proxy that forwards
// everything to the given backend URL (regardless of the request's port
// label, which keeps these tests independent of port-binding flakiness).
// Returns a channel signalling Serve return.
func (s *e2eSuite) servePassthrough(ctx context.Context, sess *tunnelclient.Session, backend *url.URL) <-chan struct{} {
	rp := httputil.NewSingleHostReverseProxy(backend)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		hostBefore := req.Host
		originalDirector(req)
		req.Host = hostBefore
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tunnelclient.Serve(ctx, sess, rp)
	}()
	return done
}

// --------------------------------------------------------------------------
// e2e scenarios
// --------------------------------------------------------------------------

// TestE2E_FreshRegistrationAndProxying covers the "no prior knowledge of this
// unique" path: client generates a key, server issues a cert (via the fake
// ensurer), persists the identity, RegisterOK, then proxy traffic flows.
// Plus apex fallback, WebSocket round-trip, and offline-503 page after the
// client disconnects.
func TestE2E_FreshRegistrationAndProxying(t *testing.T) {
	s := newE2ESuite(t)

	// Backend: HTTP echo + WS echo.
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s xfh=%s xfp=%s",
			r.Host, r.URL.Path,
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"),
		)
	})
	backendMux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		_, _ = io.Copy(ws, ws)
	}))
	backend := httptest.NewServer(backendMux)
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := s.dialAndRegister(ctx, "alpha", priv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if want := "alpha-tunnel." + s.apex; sess.Hostname() != want {
		t.Errorf("hostname = %q, want %q", sess.Hostname(), want)
	}
	// On a brand-new unique, the ensurer must have been invoked once for
	// the per-session cert.
	if got := s.ensurer.Calls(); len(got) != 1 || got[0] != "alpha-tunnel" {
		t.Errorf("ensurer calls = %v, want [alpha-tunnel]", got)
	}
	// And the identity row must exist.
	if got, err := s.store.Get(ctx, "alpha"); err != nil {
		t.Errorf("identity row missing: %v", err)
	} else if !bytes.Equal(got.Pubkey, priv.Public().(ed25519.PublicKey)) {
		t.Error("stored pubkey doesn't match the connecting client")
	}

	doneServe := s.servePassthrough(ctx, sess, backendURL)
	if !waitFor(t, 5*time.Second, func() bool { return s.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("registry never saw the new session")
	}

	httpClient := s.httpClient()
	tunneledHost := "1977.alpha-tunnel." + s.apex

	t.Run("HTTP", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://"+tunneledHost+"/some-path", nil)
		req.Host = tunneledHost
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		for _, want := range []string{
			"host=" + tunneledHost,
			"xfh=" + tunneledHost,
			"xfp=https",
		} {
			if !strings.Contains(bodyStr, want) {
				t.Errorf("body missing %q: %q", want, bodyStr)
			}
		}
	})

	t.Run("ApexFallback", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://"+s.apex+"/", nil)
		req.Host = s.apex
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "apex hello" {
			t.Errorf("apex body = %q, want %q", body, "apex hello")
		}
	})

	t.Run("WebSocket", func(t *testing.T) {
		cfg, err := websocket.NewConfig("wss://"+tunneledHost+"/ws", "https://test")
		if err != nil {
			t.Fatal(err)
		}
		cfg.TlsConfig = s.tlsCfg.Clone()

		var d net.Dialer
		rawConn, err := d.DialContext(ctx, "tcp", mustURL(t, s.tunneld.URL).Host)
		if err != nil {
			t.Fatal(err)
		}
		tlsConn := tls.Client(rawConn, cfg.TlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		ws, err := websocket.NewClient(cfg, tlsConn)
		if err != nil {
			t.Fatalf("websocket.NewClient: %v", err)
		}
		defer ws.Close()

		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("ping-%d", i)
			if err := websocket.Message.Send(ws, msg); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
			var got string
			if err := websocket.Message.Receive(ws, &got); err != nil {
				t.Fatalf("recv %d: %v", i, err)
			}
			if got != msg {
				t.Errorf("recv %d: got %q, want %q", i, got, msg)
			}
		}
	})

	t.Run("Offline", func(t *testing.T) {
		_ = sess.Close()
		cancel()

		select {
		case <-doneServe:
		case <-time.After(2 * time.Second):
			t.Fatal("Serve goroutine didn't return")
		}
		if !waitFor(t, 2*time.Second, func() bool { return s.registry.get("alpha-tunnel") == nil }) {
			t.Fatal("registry never released the session")
		}

		req, _ := http.NewRequest(http.MethodGet, "https://"+tunneledHost+"/", nil)
		req.Host = tunneledHost
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("offline status = %d, want 502", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "Tunnel offline") {
			t.Errorf("offline body = %q, want it to contain 'Tunnel offline'", body)
		}
	})
}

// TestE2E_ReconnectSameKey covers the idempotent reconnect path: pre-seed
// the identity store, then have a client with the SAME key connect again.
// Expect no ensurer call (cert already exists), Touch updates last_seen,
// and the session is registered.
func TestE2E_ReconnectSameKey(t *testing.T) {
	s := newE2ESuite(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	// Pre-seed: pretend "beta" was registered earlier with this key.
	earlier := time.Now().Add(-time.Hour)
	if err := s.store.Put(context.Background(), "beta", pub, earlier); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := s.dialAndRegister(ctx, "beta", priv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sess.Close()

	if got := s.ensurer.Calls(); len(got) != 0 {
		t.Errorf("ensurer should not be called on idempotent reconnect, got %v", got)
	}
	got, err := s.store.Get(ctx, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSeenAt.Unix() <= earlier.Unix() {
		t.Errorf("LastSeenAt = %v, want > %v (Touch should have run)", got.LastSeenAt, earlier)
	}
}

// TestE2E_ImpostorRejected covers the deny path: pre-seed the store with
// key1, then have the client connect with a different key2 and the same
// unique. Server replies Challenge → client signs with key2 → server verifies
// with stored key1 → Deny "key_mismatch". The tunnelclient.Connect call must
// surface that error and leave the store untouched.
func TestE2E_ImpostorRejected(t *testing.T) {
	s := newE2ESuite(t)
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)

	if err := s.store.Put(context.Background(), "gamma",
		priv1.Public().(ed25519.PublicKey), time.Now()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := s.dialAndRegister(ctx, "gamma", priv2)
	if err == nil {
		t.Fatal("expected Connect to error")
	}
	if !strings.Contains(err.Error(), "key_mismatch") {
		t.Errorf("err = %v, want it to contain 'key_mismatch'", err)
	}

	// Stored pubkey should still be priv1.
	got, getErr := s.store.Get(ctx, "gamma")
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !bytes.Equal(got.Pubkey, priv1.Public().(ed25519.PublicKey)) {
		t.Error("stored pubkey was modified after a failed proof")
	}
}

// TestE2E_DenyOnBadUnique covers a client-visible Deny: the server validates
// the unique regex and rejects malformed names with a Deny that the client
// must surface as an error from Connect.
func TestE2E_DenyOnBadUnique(t *testing.T) {
	s := newE2ESuite(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// "Bad.Unique" violates the regex. tunnelclient.Connect validates
	// client-side too — it returns the local error before sending. To
	// exercise the SERVER-side rejection, we'd need to bypass that, which
	// isn't worth a test-only escape hatch. Confirm the client-side guard
	// here.
	_, err := s.dialAndRegister(ctx, "Bad.Unique", priv)
	if err == nil {
		t.Fatal("expected error for invalid unique")
	}
	if !strings.Contains(err.Error(), "invalid unique") {
		t.Errorf("err = %v, want it to contain 'invalid unique'", err)
	}
}

// TestE2E_RateLimitedIP confirms that an exhausted per-IP register budget
// turns into a Deny that surfaces from Connect.
func TestE2E_RateLimitedIP(t *testing.T) {
	// Custom suite with a 0/hour limit (tighter than the default disabled).
	apex := "tunnel.test"
	store, err := identity.Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	reg := newRegistry()
	ipLim := ratelimit.New(1, time.Hour)
	if !ipLim.Allow("127.0.0.1") {
		t.Fatal("first hit should pass")
	}
	keyLim := ratelimit.New(0, 24*time.Hour)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ensurer := &fakeEnsurer{}

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, store, ensurer, apex, ipLim, keyLim, nil, logger))
	mux.Handle("/", route(reg, apex, http.NotFoundHandler()))

	tunneld := httptest.NewTLSServer(mux)
	defer tunneld.Close()

	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: mustURL(t, tunneld.URL).Hostname(),
		MinVersion: tls.VersionTLS12,
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  tunneld.URL,
		Unique:     "delta",
		PrivateKey: priv,
		TLSConfig:  tlsCfg,
		Logger:     logger,
	})
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
	if !strings.Contains(err.Error(), "rate_limited:ip") {
		t.Errorf("err = %v, want it to contain 'rate_limited:ip'", err)
	}
	// Note: ensurer must NOT have been called — the deny path returns early.
	if got := ensurer.Calls(); len(got) != 0 {
		t.Errorf("ensurer should not be called when rate-limited, got %v", got)
	}
}

// --------------------------------------------------------------------------
// Concurrency: a session shutdown initiated mid-flight should not leak
// goroutines, and the registry must release the entry.
// --------------------------------------------------------------------------

func TestE2E_SessionCloseRemovesFromRegistry(t *testing.T) {
	s := newE2ESuite(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := s.dialAndRegister(ctx, "epsilon", priv)
	if err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	doneServe := s.servePassthrough(ctx, sess, backendURL)
	if !waitFor(t, 5*time.Second, func() bool { return s.registry.get("epsilon-tunnel") != nil }) {
		t.Fatal("registry never saw the session")
	}

	_ = sess.Close()
	cancel()
	select {
	case <-doneServe:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve didn't return after Close+cancel")
	}

	if !waitFor(t, 2*time.Second, func() bool { return s.registry.get("epsilon-tunnel") == nil }) {
		t.Error("registry still has session after close")
	}
}

// --------------------------------------------------------------------------
// Deregister: end-to-end via tunnelclient.Session.Deregister
// --------------------------------------------------------------------------

// TestE2E_Deregister_HappyPath covers the full release-ownership flow:
// connect → deregister → identity row gone, route returns 502 immediately,
// AND a fresh client with a DIFFERENT key can re-claim the same unique
// without going through Challenge/Proof (because the row is gone).
func TestE2E_Deregister_HappyPath(t *testing.T) {
	s := newE2ESuite(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := s.dialAndRegister(ctx, "zeta", priv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Run the data-plane goroutine so registry observes the session.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	doneServe := s.servePassthrough(ctx, sess, backendURL)
	if !waitFor(t, 5*time.Second, func() bool { return s.registry.get("zeta-tunnel") != nil }) {
		t.Fatal("registry never saw the session")
	}

	// Deregister.
	deregCtx, deregCancel := context.WithTimeout(ctx, 5*time.Second)
	defer deregCancel()
	if err := sess.Deregister(deregCtx); err != nil {
		t.Fatalf("Deregister: %v", err)
	}

	// Server tears down the session after DeregisterOK; client must close.
	_ = sess.Close()
	select {
	case <-doneServe:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve goroutine didn't return after Deregister + Close")
	}

	// Identity row gone.
	if _, err := s.store.Get(ctx, "zeta"); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("identity row should be gone, got err = %v", err)
	}
	// Registry releases the session.
	if !waitFor(t, 2*time.Second, func() bool { return s.registry.get("zeta-tunnel") == nil }) {
		t.Error("registry never released the session after Deregister")
	}
	// Route returns offline page (registered-shaped host, no live session).
	httpClient := s.httpClient()
	tunneledHost := "1977.zeta-tunnel." + s.apex
	req, _ := http.NewRequest(http.MethodGet, "https://"+tunneledHost+"/", nil)
	req.Host = tunneledHost
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status after deregister = %d, want 502", resp.StatusCode)
	}

	// A DIFFERENT client (different key) can now claim "zeta" without a
	// Challenge — because the identity row was deleted.
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	sess2, err := s.dialAndRegister(ctx, "zeta", priv2)
	if err != nil {
		t.Fatalf("re-register after deregister with NEW key: %v", err)
	}
	defer sess2.Close()
	got, err := s.store.Get(ctx, "zeta")
	if err != nil {
		t.Fatalf("store.Get after re-register: %v", err)
	}
	if !bytes.Equal(got.Pubkey, priv2.Public().(ed25519.PublicKey)) {
		t.Error("re-register should have stored the NEW pubkey (no challenge required)")
	}
}

// TestE2E_Deregister_RejectedAfterRekeyByImpostor confirms the security
// property: an attacker who has *somehow* hijacked the public hostname
// (via Register from a different key; would normally fail the
// Challenge/Proof flow) cannot also Deregister the legitimate owner's
// row. We exercise the Deregister-side defense: a session authenticated
// as one unique cannot deregister a different unique. Since
// dialAndRegister always claims a single unique per session, the only
// way to hit "unique mismatch" is to forge a Deregister payload by hand
// — which we do here by skipping the client API and writing the frame
// directly through the *yamux.Stream*. But that requires reaching into
// internals we don't expose. Simpler: confirm the negative directly
// — that the legitimate `Session.Deregister(ctx)` call signs with the
// session's own unique, which the server accepts.
//
// (The attack vector "deregister someone else's name" is already
// covered by the server-side unit test
// TestRunControlLoop_UniqueMismatch_DenyAndContinue in
// deregister_test.go; here we just confirm the client API doesn't
// accidentally claim a foreign unique.)
func TestE2E_Deregister_ClientSignsOwnUnique(t *testing.T) {
	s := newE2ESuite(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessA, err := s.dialAndRegister(ctx, "owner-a", priv)
	if err != nil {
		t.Fatal(err)
	}
	defer sessA.Close()

	if sessA.Hostname() != "owner-a-tunnel."+s.apex {
		t.Fatalf("hostname = %q", sessA.Hostname())
	}

	// Deregister via the public API succeeds — the API has no way to claim
	// a different unique.
	if err := sessA.Deregister(ctx); err != nil {
		t.Errorf("legitimate deregister failed: %v", err)
	}
}

// TestE2E_Deregister_ContextCancel confirms that cancelling the context
// passed to Deregister unblocks the read side, returning a wrapped
// context error rather than hanging.
func TestE2E_Deregister_ContextCancel(t *testing.T) {
	s := newE2ESuite(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := s.dialAndRegister(ctx, "eta", priv)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Cancel BEFORE calling Deregister. The write may still succeed (small
	// frame), but the read for the response should fail fast on ctx done.
	deregCtx, deregCancel := context.WithCancel(ctx)
	deregCancel()

	err = sess.Deregister(deregCtx)
	if err == nil {
		// In rare scheduling, the server may have already replied OK before
		// we attempted the read — so success is also tolerable. We only
		// fail if it hangs or returns the wrong shape of error.
		return
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("Deregister error = %v, want context-canceled wrapping", err)
	}
}

// --------------------------------------------------------------------------
// helpers shared with register_test.go
// --------------------------------------------------------------------------

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// errorContains is a small string-match helper.
func errorContains(err error, substr string) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errors.New(substr)) || strings.Contains(err.Error(), substr)
}

var _ = errorContains // keep available for future tests

// --------------------------------------------------------------------------
// Allowlist gate (e2e variants)
// --------------------------------------------------------------------------

// TestE2E_Allowlist_Denied: client whose key isn't in the allowlist
// gets a permanent DenyError("not_authorized") from Connect, no session
// is registered, and the apex route still serves the fallback page (the
// gate does not affect non-tunnel traffic).
func TestE2E_Allowlist_Denied(t *testing.T) {
	allowedPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := newE2ESuiteWithAllowlist(t, allowedPub)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.dialAndRegister(ctx, "alpha", priv)
	if err == nil {
		t.Fatal("Connect with unallowed key: expected error, got nil")
	}
	var de *tunnelclient.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("Connect error = %v, want *DenyError", err)
	}
	if de.Reason != "not_authorized" {
		t.Errorf("Deny.Reason = %q, want %q", de.Reason, "not_authorized")
	}
	// Apex hello must still serve — gate only affects /v1/connect.
	resp, err := s.httpClient().Get(s.tunneld.URL + "/")
	if err != nil {
		t.Fatalf("apex GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "apex hello") {
		t.Errorf("apex body = %q, want 'apex hello'", string(body))
	}
}

// TestE2E_Allowlist_Allowed: same setup but the client's key is in the
// allowlist — Connect succeeds and traffic flows through the tunnel.
func TestE2E_Allowlist_Allowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := newE2ESuiteWithAllowlist(t, pub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := s.dialAndRegister(ctx, "alpha", priv)
	if err != nil {
		t.Fatalf("Connect with allowed key: %v", err)
	}
	defer sess.Close()
	if want := "alpha-tunnel." + s.apex; sess.Hostname() != want {
		t.Errorf("hostname = %q, want %q", sess.Hostname(), want)
	}
}

// TestE2E_Allowlist_AddAndAllow: client is initially denied; operator
// drops a key file into the directory and triggers a reload; client's
// next Connect succeeds. Models the chat-driven onboarding flow.
func TestE2E_Allowlist_AddAndAllow(t *testing.T) {
	s := newE2ESuiteWithAllowlist(t /* empty — deny everyone */)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := s.dialAndRegister(ctx, "alpha", priv); err == nil {
		t.Fatal("first Connect: expected denial, got nil")
	}

	// Operator adds the key on disk, then signals reload.
	s.addAllowedKey("alice.pub", pub)
	s.reloadAllowlist()

	// Retry — should succeed now.
	sess, err := s.dialAndRegister(ctx, "alpha", priv)
	if err != nil {
		t.Fatalf("Connect after add+reload: %v", err)
	}
	defer sess.Close()
}

// TestE2E_Allowlist_LiveRevoke is the test that proves the chat-driven
// revoke story works end-to-end:
//
//  1. Key K is in the allowlist; client registers and the session is live.
//  2. Operator removes K from disk and triggers reload.
//  3. RevokeMissing closes the live session within a small bound.
//  4. The client observes session closure (CloseChan fires).
//
// We don't drive a follow-up Connect attempt here — that would just
// re-exercise TestE2E_Allowlist_Denied. The novel assertion is "live
// session dropped" within a deterministic bound.
func TestE2E_Allowlist_LiveRevoke(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := newE2ESuiteWithAllowlist(t, pub)
	s.addAllowedKey("alice.pub", pub) // give the file a stable filename for removal
	// We added a duplicate key under a fresh name; reload picks it up so
	// removing both files later means deny-all.
	s.reloadAllowlist()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sess, err := s.dialAndRegister(ctx, "alpha", priv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sess.Close()

	// Confirm the session is live by checking the registry.
	if !waitFor(t, time.Second, func() bool { return s.registry.get("alpha-tunnel") != nil }) {
		t.Fatal("session not visible in registry after Connect")
	}

	// Operator revokes alice.pub AND the suite's bootstrap k0.pub —
	// after both are gone the directory is empty (deny-all).
	s.removeAllowedKey("alice.pub")
	s.removeAllowedKey("k0.pub")
	s.reloadAllowlist()

	// Server-side: registry should be cleaned within ~100ms (RevokeMissing
	// closes outside the lock; the connectHandler defer prunes on
	// CloseChan).
	select {
	case <-sess.CloseChan():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("client did not observe session close within 500ms after revoke")
	}
}
