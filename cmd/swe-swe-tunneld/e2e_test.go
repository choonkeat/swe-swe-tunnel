package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	"golang.org/x/net/websocket"

	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// TestE2E_HTTPAndWebSocketThroughTunnel boots an in-process tunneld + tunnel
// client + backend echo server in one test, then drives HTTP and WS requests
// through the full chain.
//
//	test client → httptest TLS server (tunneld mux) → yamux → tunnelclient
//	            → custom proxy → backend echo
//
// It asserts:
//   - Successful HTTP round-trip with Host preserved + X-Forwarded-Host set.
//   - Apex fallback for non-tunnel hosts.
//   - WebSocket upgrade flows through and round-trips a frame.
//   - 502 "Tunnel offline" page returned after the client disconnects.
func TestE2E_HTTPAndWebSocketThroughTunnel(t *testing.T) {
	// ----- Backend: echoes request shape over HTTP, echoes WS frames -----
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s xfh=%s xfp=%s",
			r.Host, r.URL.Path,
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Proto"),
		)
	})
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		_, _ = io.Copy(ws, ws)
	}))
	backend := httptest.NewServer(mux)
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	// ----- Tunneld: connectHandler + route + apex hello -----
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

	apexHello := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("apex hello"))
	})
	tunneldMux := http.NewServeMux()
	tunneldMux.Handle("/v1/connect",
		connectHandler(reg, store, &fakeEnsurer{}, apex, ipLim, keyLim, logger))
	tunneldMux.Handle("/", route(reg, apex, apexHello))

	tunneld := httptest.NewTLSServer(tunneldMux)
	defer tunneld.Close()

	// Trust tunneld's self-signed cert without InsecureSkipVerify.
	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tunneldHost := mustURL(t, tunneld.URL).Hostname()
	clientTLS := &tls.Config{
		RootCAs:    roots,
		ServerName: tunneldHost,
		MinVersion: tls.VersionTLS12,
	}

	// ----- Tunnel client: use the real tunnelclient package -----
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  tunneld.URL,
		Unique:     "alpha",
		PrivateKey: priv,
		TLSConfig:  clientTLS,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("tunnelclient.Connect: %v", err)
	}
	if sess.Hostname() != "alpha-tunnel."+apex {
		t.Errorf("hostname = %q, want alpha-tunnel.%s", sess.Hostname(), apex)
	}

	// Custom proxy on the client side so test doesn't have to plumb a fixed
	// `127.0.0.1:1977` listener: just route everything to the backend URL.
	clientProxy := httputil.NewSingleHostReverseProxy(backendURL)
	originalDirector := clientProxy.Director
	clientProxy.Director = func(req *http.Request) {
		// Preserve the inbound Host so the backend's echo can see it.
		hostBefore := req.Host
		originalDirector(req)
		req.Host = hostBefore
	}

	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		_ = tunnelclient.Serve(ctx, sess, clientProxy)
	}()

	// Wait for the registry to know about us.
	if !waitFor(t, 5*time.Second, func() bool {
		return reg.get("alpha-tunnel") != nil
	}) {
		t.Fatal("registry never saw the new session")
	}

	// HTTP client that always dials tunneld's actual address regardless of
	// Host (so we can rewrite Host to a tunneled hostname).
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: tunneldHost, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", mustURL(t, tunneld.URL).Host)
			},
		},
		Timeout: 5 * time.Second,
	}

	// ----- HTTP through tunnel -----
	t.Run("HTTP", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://1977.alpha-tunnel."+apex+"/some-path", nil)
		req.Host = "1977.alpha-tunnel." + apex
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
		wantHost := "host=1977.alpha-tunnel." + apex
		if !strings.Contains(bodyStr, wantHost) {
			t.Errorf("backend didn't see %q in body: %q", wantHost, bodyStr)
		}
		if !strings.Contains(bodyStr, "xfh=1977.alpha-tunnel."+apex) {
			t.Errorf("backend didn't see X-Forwarded-Host: %q", bodyStr)
		}
		if !strings.Contains(bodyStr, "xfp=https") {
			t.Errorf("backend didn't see X-Forwarded-Proto=https: %q", bodyStr)
		}
	})

	// ----- Apex fallback -----
	t.Run("ApexFallback", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://"+apex+"/", nil)
		req.Host = apex
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

	// ----- WebSocket through tunnel -----
	t.Run("WebSocket", func(t *testing.T) {
		// websocket.NewConfig wants a `wss://` URL whose Host the server will
		// see in the upgrade request. We override the dial+TLS to actually
		// reach tunneld.
		cfg, err := websocket.NewConfig("wss://1977.alpha-tunnel."+apex+"/ws", "https://test")
		if err != nil {
			t.Fatal(err)
		}
		cfg.TlsConfig = &tls.Config{RootCAs: roots, ServerName: tunneldHost, MinVersion: tls.VersionTLS12}

		var d net.Dialer
		rawConn, err := d.DialContext(ctx, "tcp", mustURL(t, tunneld.URL).Host)
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

	// ----- Tunnel-offline page after client disconnects -----
	t.Run("Offline", func(t *testing.T) {
		_ = sess.Close()
		cancel()
		serveWG.Wait()

		// Wait for the registry to drop the session.
		if !waitFor(t, 2*time.Second, func() bool {
			return reg.get("alpha-tunnel") == nil
		}) {
			t.Fatal("registry never released the session")
		}

		// Re-issue the request; expect a 502 page.
		req, _ := http.NewRequest(http.MethodGet, "https://1977.alpha-tunnel."+apex+"/", nil)
		req.Host = "1977.alpha-tunnel." + apex
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
