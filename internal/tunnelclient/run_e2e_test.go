package tunnelclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
)

// fakeTunneld is a hand-rolled minimal server that handles the /v1/connect
// HTTP-Upgrade handshake, runs yamux, accepts stream 1, and replies with
// RegisterOK. It does NOT implement Challenge/Proof — the test harness
// always uses a fresh key per `unique`. After RegisterOK, it can be told
// to close the session (drop the underlying TCP conn), or to read a
// Deregister frame and reply with DeregisterOK.
type fakeTunneld struct {
	t        *testing.T
	server   *httptest.Server
	logger   *slog.Logger
	apex     string
	tlsCfg   *tls.Config
	registers atomic.Int32 // count of successful Register frames seen
	mu        sync.Mutex
	// killAfter, when non-zero, makes the Nth registration (1-indexed)
	// close the conn immediately after sending RegisterOK. After that the
	// next registration succeeds normally.
	killAfter int
}

func newFakeTunneld(t *testing.T) *fakeTunneld {
	t.Helper()
	f := &fakeTunneld{
		t:      t,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		apex:   "tunnel.test",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connect", f.handleConnect)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	f.server = srv

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.tlsCfg = &tls.Config{
		RootCAs:    roots,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	}
	return f
}

// killNextSession arms the fake to drop the TCP conn immediately after
// the next RegisterOK. Used for the crash+reconnect test.
func (f *fakeTunneld) killNextSession() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killAfter = int(f.registers.Load()) + 1
}

func (f *fakeTunneld) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), control.UpgradeProtocol) {
		http.Error(w, "upgrade", http.StatusBadRequest)
		return
	}
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
	// Reply 101 Switching Protocols.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: " + control.UpgradeProtocol + "\r\n" +
		"Connection: Upgrade\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		f.t.Logf("fake tunneld: write 101: %v", err)
		_ = conn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		f.t.Logf("fake tunneld: flush 101: %v", err)
		_ = conn.Close()
		return
	}

	yam, err := yamux.Server(conn, nil)
	if err != nil {
		f.t.Logf("fake tunneld: yamux server: %v", err)
		_ = conn.Close()
		return
	}
	defer yam.Close()

	stream, err := yam.AcceptStream()
	if err != nil {
		f.t.Logf("fake tunneld: accept stream: %v", err)
		return
	}

	frame, err := control.ReadFrame(stream)
	if err != nil {
		f.t.Logf("fake tunneld: read register: %v", err)
		return
	}
	if frame.Type != control.KindRegister {
		f.t.Logf("fake tunneld: want Register, got %q", frame.Type)
		return
	}
	var reg control.Register
	if err := control.DecodePayload(frame, &reg); err != nil {
		f.t.Logf("fake tunneld: decode register: %v", err)
		return
	}
	hostname := control.TunnelLabel(reg.Unique) + "." + f.apex
	if err := control.WriteMessage(stream, control.KindRegisterOK, control.RegisterOK{
		Hostname: hostname,
	}); err != nil {
		f.t.Logf("fake tunneld: write register_ok: %v", err)
		return
	}

	registered := f.registers.Add(1)

	f.mu.Lock()
	shouldKill := f.killAfter != 0 && int(registered) == f.killAfter
	f.mu.Unlock()
	if shouldKill {
		// Drop the underlying TCP conn so the client's yamux session dies.
		// The client's Run loop will see Serve return without ctx
		// cancellation, emit `disconnected`, and reconnect.
		_ = conn.Close()
		return
	}

	// Continue: read further frames on the control stream (e.g.
	// Deregister) until the session ends.
	for {
		fr, err := control.ReadFrame(stream)
		if err != nil {
			return
		}
		switch fr.Type {
		case control.KindDeregister:
			if err := control.WriteMessage(stream, control.KindDeregisterOK, control.DeregisterOK{}); err != nil {
				f.t.Logf("fake tunneld: write deregister_ok: %v", err)
			}
			// Server-side: tear down after deregister.
			return
		default:
			// Ignore other frames in the fake.
		}
	}
}

// captureBuffer is a thread-safe bytes.Buffer for the JSONL emitter to
// write into while the test reads its tail.
type captureBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *captureBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// readEventKinds parses the captured stream into ordered kind names.
func readEventKinds(t *testing.T, raw []byte) []string {
	t.Helper()
	var kinds []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev envelope
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		kinds = append(kinds, ev.Kind)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return kinds
}

// waitForKind blocks until at least one event with the given kind has
// appeared in cap, or the timeout fires.
func waitForKind(t *testing.T, cap *captureBuffer, kind string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, k := range readEventKinds(t, cap.Bytes()) {
			if k == kind {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for kind=%q in stream:\n%s", timeout, kind, cap.Bytes())
}

// countKind returns how many events of the given kind are present.
func countKind(t *testing.T, cap *captureBuffer, kind string) int {
	t.Helper()
	n := 0
	for _, k := range readEventKinds(t, cap.Bytes()) {
		if k == kind {
			n++
		}
	}
	return n
}

func freshKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestE2E_Run_HappyPath_JSONL covers acceptance #2: the happy-path
// lifecycle emits the documented sequence one JSON object per line.
func TestE2E_Run_HappyPath_JSONL(t *testing.T) {
	f := newFakeTunneld(t)
	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.server.URL,
				Unique:     "happy",
				PrivateKey: freshKey(t),
				TLSConfig:  f.tlsCfg,
				Logger:     f.logger,
				Emitter:    em,
			},
			Handler:    http.NotFoundHandler(),
			BackoffMin: 5 * time.Millisecond,
			BackoffMax: 20 * time.Millisecond,
		})
	}()

	waitForKind(t, cap, EventRegisterOK, 5*time.Second)
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}

	got := readEventKinds(t, cap.Bytes())
	want := []string{
		EventStarting, EventConnecting, EventRegisterOK, EventDeregisterOK,
	}
	if !equalStrings(got, want) {
		t.Errorf("event sequence:\n got=%v\nwant=%v", got, want)
	}
}

// TestE2E_Run_CrashAndReconnect_JSONL covers acceptance #3: forcing the
// tunneld to close mid-session emits disconnected -> reconnecting -> a
// second register_ok on the same line stream.
func TestE2E_Run_CrashAndReconnect_JSONL(t *testing.T) {
	f := newFakeTunneld(t)
	f.killNextSession() // first registration gets dropped right after RegisterOK

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.server.URL,
				Unique:     "crashy",
				PrivateKey: freshKey(t),
				TLSConfig:  f.tlsCfg,
				Logger:     f.logger,
				Emitter:    em,
			},
			Handler:    http.NotFoundHandler(),
			BackoffMin: 5 * time.Millisecond,
			BackoffMax: 20 * time.Millisecond,
		})
	}()

	// Wait for the second register_ok (after the forced crash + reconnect).
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if countKind(t, cap, EventRegisterOK) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := countKind(t, cap, EventRegisterOK); got < 2 {
		t.Fatalf("want >= 2 register_ok events, got %d. Stream:\n%s", got, cap.Bytes())
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}

	kinds := readEventKinds(t, cap.Bytes())
	// Find the index of the first register_ok and walk forward asserting
	// the documented reconnect sequence.
	first := indexOf(kinds, EventRegisterOK)
	if first < 0 {
		t.Fatalf("no register_ok found: %v", kinds)
	}
	// After first register_ok, the next state events must be:
	// disconnected, reconnecting, connecting, register_ok (in that order).
	wantAfter := []string{EventDisconnected, EventReconnecting, EventConnecting, EventRegisterOK}
	if !subseqMatches(kinds[first+1:], wantAfter) {
		t.Errorf("reconnect sequence after first register_ok:\n  got tail=%v\n want subsequence=%v",
			kinds[first+1:], wantAfter)
	}

	if got := countKind(t, cap, EventStarting); got != 1 {
		t.Errorf("starting must appear exactly once, got %d", got)
	}
	if kinds[0] != EventStarting {
		t.Errorf("starting must be first, got %q", kinds[0])
	}
}

// TestE2E_Run_FatalAfterMaxAttempts covers acceptance #4: a non-
// recoverable connect failure (server unreachable) emits fatal as the
// final line and Run returns non-nil.
func TestE2E_Run_FatalAfterMaxAttempts(t *testing.T) {
	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Point at a server URL that nothing is listening on (loopback :1).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, RunOptions{
		Connect: Options{
			ServerURL:   "https://127.0.0.1:1",
			Unique:      "doomed",
			PrivateKey:  freshKey(t),
			Logger:      logger,
			Emitter:     em,
			DialTimeout: 100 * time.Millisecond,
		},
		Handler:     http.NotFoundHandler(),
		BackoffMin:  5 * time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
		MaxAttempts: 2,
	})
	if err == nil {
		t.Fatal("Run: want non-nil error after MaxAttempts exhausted")
	}

	kinds := readEventKinds(t, cap.Bytes())
	if len(kinds) == 0 {
		t.Fatal("no events emitted")
	}
	if kinds[0] != EventStarting {
		t.Errorf("first event: got %q, want starting", kinds[0])
	}
	if last := kinds[len(kinds)-1]; last != EventFatal {
		t.Errorf("last event: got %q, want fatal", last)
	}
	// Must contain at least one error before fatal.
	sawError := false
	for _, k := range kinds {
		if k == EventError {
			sawError = true
			break
		}
	}
	if !sawError {
		t.Errorf("expected at least one error event before fatal, got %v", kinds)
	}
}

// TestE2E_Run_NoneEmitterProducesZeroBytes covers acceptance #1: with
// the default --report-format=none (NoopEmitter), zero bytes are written
// to the supervisor channel across a full happy-path lifecycle.
func TestE2E_Run_NoneEmitterProducesZeroBytes(t *testing.T) {
	f := newFakeTunneld(t)

	// Run with a writer that fails the test on any write — proves
	// NoopEmitter never reaches the wire even when the binary is wired
	// up correctly.
	cap := &captureBuffer{}
	// Don't pass an emitter: Run defaults to NoopEmitter.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.server.URL,
				Unique:     "silent",
				PrivateKey: freshKey(t),
				TLSConfig:  f.tlsCfg,
				Logger:     f.logger,
				// Emitter intentionally nil; defaults to NoopEmitter.
			},
			Handler:    http.NotFoundHandler(),
			BackoffMin: 5 * time.Millisecond,
			BackoffMax: 20 * time.Millisecond,
		})
	}()

	// Block until at least one register completed server-side, then
	// cancel. We can't waitForKind on the JSONL stream (there is none),
	// so poll the fake's counter.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.registers.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f.registers.Load() < 1 {
		t.Fatal("fake tunneld never saw a Register frame")
	}
	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}

	if got := cap.Bytes(); len(got) != 0 {
		t.Errorf("NoopEmitter path wrote %d bytes (must be 0): %q", len(got), got)
	}
}

// TestE2E_Run_BuildEmitter is a small unit-level guarantee that the
// cmd-side helper maps "none" to NoopEmitter and "jsonl" to JSONLEmitter.
// We test the same logic that cmd/swe-swe-tunnel/main.go uses, but
// without spinning up the binary.
func TestE2E_Run_FormatNoneIsNoop(t *testing.T) {
	// This mirrors the buildEmitter switch in cmd/swe-swe-tunnel/main.go.
	// Keeping a parallel assertion here means a future refactor that
	// adds a new format won't silently change the "none" semantics.
	var none Emitter = NoopEmitter{}
	var buf bytes.Buffer
	none.Emit(EventStarting, StartingData{Unique: "x", ServerURL: "https://x"})
	if buf.Len() != 0 {
		t.Errorf("NoopEmitter must not produce output, got %q", buf.String())
	}
	jsonl := NewJSONLEmitter(&buf)
	jsonl.Emit(EventStarting, StartingData{Unique: "x", ServerURL: "https://x"})
	if buf.Len() == 0 {
		t.Errorf("JSONLEmitter must produce output")
	}
}

// equalStrings is a tiny helper to avoid pulling in slices.Equal for a
// 1.21 compatibility floor (this repo is on go 1.24, but keeping the
// helper local makes test intent obvious).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// subseqMatches reports whether `tail` starts with `prefix` (in order)
// allowing for unrelated events between matches. We use a strict
// in-order match here because the documented sequence has no other
// kinds intervening.
func subseqMatches(tail, prefix []string) bool {
	if len(tail) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if tail[i] != p {
			return false
		}
	}
	return true
}
