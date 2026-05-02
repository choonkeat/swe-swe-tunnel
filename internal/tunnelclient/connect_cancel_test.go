package tunnelclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/tunneldfake"
)

// stallServer wraps an httptest TLS server whose handler can be wired to
// block at any of the three protocol phases the client steps through
// after a successful TCP+TLS dial:
//
//  1. HTTP upgrade read   — handler never writes the 101 response
//  2. Yamux handshake     — handler writes 101 + hijacks, then sleeps
//                            (no yamux.Server on its end)
//  3. Register read       — handler completes 101 + yamux + AcceptStream,
//                            then sleeps without replying to Register
//
// `release` is closed by Cleanup; the handler observes it to unstick any
// goroutine the test left waiting and avoid leaking past the test.
type stallServer struct {
	srv     *httptest.Server
	tlsCfg  *tls.Config
	release chan struct{}
}

func newStallServer(t *testing.T, phase string) *stallServer {
	t.Helper()
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connect", func(w http.ResponseWriter, r *http.Request) {
		switch phase {
		case "upgrade":
			// Block before writing any response. The client's
			// http.ReadResponse stays parked on the TLS conn read.
			<-release
			return
		case "yamux", "register":
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, brw, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, "hijack: "+err.Error(), http.StatusInternalServerError)
				return
			}
			defer conn.Close()
			resp := "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: " + control.UpgradeProtocol + "\r\n" +
				"Connection: Upgrade\r\n\r\n"
			if _, err := brw.WriteString(resp); err != nil {
				return
			}
			if err := brw.Flush(); err != nil {
				return
			}
			if phase == "yamux" {
				// 101 is on the wire; never start a yamux server. The
				// client's yamux.Client handshake reads block.
				<-release
				return
			}
			// phase == "register": speak yamux up to AcceptStream, then
			// stop. The client gets to send Register and then blocks on
			// reading the RegisterOK response.
			yam, err := yamux.Server(conn, nil)
			if err != nil {
				return
			}
			defer yam.Close()
			stream, err := yam.AcceptStream()
			if err != nil {
				return
			}
			defer stream.Close()
			<-release
		default:
			t.Fatalf("unknown stall phase %q", phase)
		}
	})

	srv := httptest.NewTLSServer(mux)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parse server URL: %v", err)
	}
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	}

	s := &stallServer{srv: srv, tlsCfg: tlsCfg, release: release}
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return s
}

func (s *stallServer) URL() string           { return s.srv.URL }
func (s *stallServer) TLSConfig() *tls.Config { return s.tlsCfg }

// TestConnect_CtxCancelDuringUpgradeRead — stalls before the server
// writes the 101 response. Without the closeOnCancel watcher, the
// client's http.ReadResponse would block indefinitely on the TLS conn
// because that Read does not observe ctx cancellation.
func TestConnect_CtxCancelDuringUpgradeRead(t *testing.T) {
	s := newStallServer(t, "upgrade")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connectDone := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, Options{
			ServerURL:  s.URL(),
			Unique:     "stall",
			PrivateKey: freshKey(t),
			TLSConfig:  s.TLSConfig(),
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		connectDone <- err
	}()

	// Give the goroutine a moment to actually park in the blocking read,
	// otherwise we'd be racing the dial itself.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-connectDone:
		if err == nil {
			t.Fatal("Connect returned nil; expected error from ctx cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return within 2s of ctx cancel — closeOnCancel watcher is broken")
	}
}

// TestConnect_CtxCancelDuringYamuxRead — stalls after the 101 but
// before any yamux server is started. The client's yamux.Client handshake
// reads stay blocked.
func TestConnect_CtxCancelDuringYamuxRead(t *testing.T) {
	s := newStallServer(t, "yamux")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connectDone := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, Options{
			ServerURL:  s.URL(),
			Unique:     "stall",
			PrivateKey: freshKey(t),
			TLSConfig:  s.TLSConfig(),
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		connectDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-connectDone:
		if err == nil {
			t.Fatal("Connect returned nil; expected error from ctx cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return within 2s of ctx cancel during yamux phase")
	}
}

// TestConnect_CtxCancelDuringRegisterRead — stalls after yamux comes up
// and the Register frame has been received. This is the empirical bug
// shape from 2026-05-02: tunneld holds the RegisterOK while LE issuance
// runs (~2-3 min). Without the watcher, the user's SIGINT was queued but
// the goroutine was parked in control.ReadFrame on the yamux stream.
func TestConnect_CtxCancelDuringRegisterRead(t *testing.T) {
	s := newStallServer(t, "register")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connectDone := make(chan error, 1)
	go func() {
		_, err := Connect(ctx, Options{
			ServerURL:  s.URL(),
			Unique:     "stall",
			PrivateKey: freshKey(t),
			TLSConfig:  s.TLSConfig(),
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		connectDone <- err
	}()

	// Slightly longer wait so the yamux handshake + Register write
	// actually completes server-side before we cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-connectDone:
		if err == nil {
			t.Fatal("Connect returned nil; expected error from ctx cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect did not return within 2s of ctx cancel during register phase — this is the original Ctrl-C bug")
	}
}

// TestConnect_NoGoroutineLeakOnHappyPath is the regression gate for the
// closeOnCancel watcher's exit on success: when Connect returns
// successfully and the Session is closed, no goroutine attached to the
// dialed conn should remain. We measure NumGoroutine before/after
// against a fast in-process tunneldfake.
//
// Some slop is unavoidable — runtime/scheduler goroutines drift across
// test runs — so we allow a small delta. The pre-fix code path leaked
// one goroutine per Connect (the never-completing watcher). A larger
// regression than that is the failure mode we want to catch.
func TestConnect_NoGoroutineLeakOnHappyPath(t *testing.T) {
	f, err := tunneldfake.Start(tunneldfake.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Warm-up Connect to spin up any one-shot package init goroutines so
	// they don't pollute the baseline count.
	{
		ctx, cancel := context.WithCancel(context.Background())
		sess, err := Connect(ctx, Options{
			ServerURL:  f.URL(),
			Unique:     "warmup",
			PrivateKey: freshKey(t),
			TLSConfig:  f.TLSConfig(),
			Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			cancel()
			t.Fatalf("warmup Connect: %v", err)
		}
		_ = sess.Close()
		cancel()
	}

	// Let any background goroutines from the warmup wind down.
	time.Sleep(100 * time.Millisecond)

	const iterations = 5
	baseline := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sess, err := Connect(ctx, Options{
				ServerURL:  f.URL(),
				Unique:     "leak-" + string(rune('a'+i)),
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Errorf("Connect[%d]: %v", i, err)
				return
			}
			_ = sess.Close()
		}(i)
	}
	wg.Wait()

	// Yield + small sleep to let conn-close goroutines unwind.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	final := runtime.NumGoroutine()
	// Allow a small drift for runtime housekeeping. Pre-fix, each Connect
	// leaked ~1 goroutine (watcher waiting forever on ctx.Done), so 5
	// iterations would have produced 5+ extra. Anything in that range
	// is a clear regression.
	if final-baseline > iterations {
		t.Errorf("goroutine leak: baseline=%d final=%d delta=%d (more than 1 per Connect — closeOnCancel watcher not exiting on success)",
			baseline, final, final-baseline)
	}
}
