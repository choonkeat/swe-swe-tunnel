package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunnelclient"
)

// TestPreRegisterTimeout_TearDownStalledConn is the regression test
// for the slow-loris DoS: a peer that completes the HTTP Upgrade and
// the yamux handshake but never opens a stream must NOT hold the
// connection indefinitely. After preRegisterTimeout the server should
// close the conn so its goroutine, FD, and yamux state are reclaimed.
//
// Without the fix, the yamux session sits in AcceptStream forever
// (yamux keepalives keep the TCP conn alive for a cooperating peer)
// and unauthenticated attackers can exhaust the server's FD/memory
// budget at the rate at which they open new TCP conns.
func TestPreRegisterTimeout_TearDownStalledConn(t *testing.T) {
	// Shorten the timeout so the test finishes quickly. Restore on exit
	// so we don't leak the override into other tests.
	prev := preRegisterTimeout
	preRegisterTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preRegisterTimeout = prev })

	tunneld, tlsCfg := buildPreRegisterTestServer(t)
	host := mustURL(t, tunneld.URL).Host

	// Dial + Upgrade.
	conn, _ := dialAndUpgrade(t, host, tlsCfg)
	defer conn.Close()

	// Wrap the conn in yamux client; do NOT open a stream. A
	// cooperating-but-malicious yamux peer keeps the keepalive going
	// indefinitely. The server-side preRegisterTimeout is what must
	// rescue us.
	cli, err := yamux.Client(conn, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	defer cli.Close()

	// Wait for the server-side close. Reading from the session
	// returns when the peer GoAway/closes; with the timeout fix this
	// should fire within ~preRegisterTimeout + jitter.
	closed := make(chan struct{})
	go func() {
		<-cli.CloseChan()
		close(closed)
	}()

	deadline := time.Duration(float64(preRegisterTimeout) * 5) // generous slack
	select {
	case <-closed:
		// success
	case <-time.After(deadline):
		t.Fatalf("server did not close stalled pre-register conn within %v "+
			"(timeout = %v); slow-loris DoS regressed",
			deadline, preRegisterTimeout)
	}
}

// TestPreRegisterTimeout_LegitClientNotAffected verifies the deadline
// is cleared on the post-Register path: a real client that completes
// Register can hold the session for longer than preRegisterTimeout
// without the conn being torn down. Otherwise our fix would itself be
// a DoS against legitimate sessions.
func TestPreRegisterTimeout_LegitClientNotAffected(t *testing.T) {
	prev := preRegisterTimeout
	preRegisterTimeout = 200 * time.Millisecond
	t.Cleanup(func() { preRegisterTimeout = prev })

	tunneld, tlsCfg := buildPreRegisterTestServer(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess, err := tunnelclient.Connect(ctx, tunnelclient.Options{
		ServerURL:  tunneld.URL,
		Unique:     "legit",
		PrivateKey: priv,
		TLSConfig:  tlsCfg,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer sess.Close()

	// Hold the session for several preRegisterTimeout intervals.
	// CloseChan firing within that window means the server tore us
	// down — a regression. CloseChan staying open is the pass case.
	hold := time.Duration(float64(preRegisterTimeout) * 5)
	select {
	case <-sess.CloseChan():
		t.Fatalf("legit session was torn down within %v of Register; "+
			"post-Register deadline-clear regressed", hold)
	case <-time.After(hold):
		// success: still alive
	}
}

// TestPreRegisterTimeout_ManyStalledConnsAreReclaimed is a broader
// shape check: many parked conns should all be reclaimed, not just
// the first one. This catches regressions where the timeout fires for
// the goroutine that hits AcceptStream first but stragglers leak.
func TestPreRegisterTimeout_ManyStalledConnsAreReclaimed(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short")
	}
	prev := preRegisterTimeout
	preRegisterTimeout = 100 * time.Millisecond
	t.Cleanup(func() { preRegisterTimeout = prev })

	tunneld, tlsCfg := buildPreRegisterTestServer(t)
	host := mustURL(t, tunneld.URL).Host

	const n = 25
	closed := make(chan struct{}, n)
	var openCount atomic.Int32

	for i := 0; i < n; i++ {
		go func() {
			conn, _ := dialAndUpgrade(t, host, tlsCfg)
			if conn == nil {
				return
			}
			openCount.Add(1)
			cli, err := yamux.Client(conn, nil)
			if err != nil {
				_ = conn.Close()
				return
			}
			<-cli.CloseChan()
			closed <- struct{}{}
			_ = conn.Close()
		}()
	}

	// Wait for all connections to be torn down.
	deadline := time.After(time.Duration(float64(preRegisterTimeout) * 10))
	got := 0
	for got < n {
		select {
		case <-closed:
			got++
		case <-deadline:
			t.Fatalf("only %d of %d stalled conns reclaimed within deadline; "+
				"opened=%d", got, n, openCount.Load())
		}
	}
}

// --- helpers --------------------------------------------------------

func buildPreRegisterTestServer(t *testing.T) (*httptest.Server, *tls.Config) {
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

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(reg, store, &fakeEnsurer{}, apex, ipLim, keyLim, logger))
	mux.Handle("/", route(reg, apex, http.NotFoundHandler()))

	tunneld := httptest.NewTLSServer(mux)
	t.Cleanup(tunneld.Close)

	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: mustURL(t, tunneld.URL).Hostname(),
		MinVersion: tls.VersionTLS12,
	}
	return tunneld, tlsCfg
}

// dialAndUpgrade performs the TLS dial + POST /v1/connect Upgrade
// dance and returns the bare conn (yamux not yet wrapped). Returns
// nil on failure rather than calling t.Fatal so callers can decide
// the policy in a goroutine context.
func dialAndUpgrade(t *testing.T, hostPort string, tlsCfg *tls.Config) (net.Conn, *bufio.Reader) {
	t.Helper()
	rawConn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		t.Logf("dial: %v", err)
		return nil, nil
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		t.Logf("tls handshake: %v", err)
		return nil, nil
	}
	req, _ := http.NewRequest(http.MethodPost,
		"https://"+hostPort+"/v1/connect", http.NoBody)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", control.UpgradeProtocol)
	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		t.Logf("write upgrade: %v", err)
		return nil, nil
	}
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = tlsConn.Close()
		t.Logf("read upgrade resp: %v", err)
		return nil, nil
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = tlsConn.Close()
		t.Logf("upgrade status = %s", resp.Status)
		return nil, nil
	}
	// bufferedConn wrapper unnecessary here; tests don't need to read
	// past the upgrade response, but they DO need the bufio.Reader
	// returned in case future tests want to read yamux bytes through
	// it.
	return &readerConn{Conn: tlsConn, r: br}, br
}

type readerConn struct {
	net.Conn
	r io.Reader
}

func (rc *readerConn) Read(p []byte) (int, error) { return rc.r.Read(p) }

// silence unused-warning if helpers move around.
var _ = errors.New
