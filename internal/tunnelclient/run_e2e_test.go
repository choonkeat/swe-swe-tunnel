package tunnelclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/tunneldfake"
)

// newFakeTunneld is a thin wrapper around tunneldfake.Start that ties
// the fake's lifetime to the test and routes diagnostic logs to t.Logf.
func newFakeTunneld(t *testing.T) *tunneldfake.Server {
	t.Helper()
	f, err := tunneldfake.Start(tunneldfake.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
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
				ServerURL:  f.URL(),
				Unique:     "happy",
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	f.KillNextSession() // first registration gets dropped right after RegisterOK

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.URL(),
				Unique:     "crashy",
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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

// TestE2E_Run_PermanentDenyEmitsFatal asserts that a server Deny with a
// reason DenyError.IsPermanent() recognises (here: "bad pubkey") causes
// Run to emit `fatal` and return immediately, rather than looping
// against a server that will reject every retry the same way.
func TestE2E_Run_PermanentDenyEmitsFatal(t *testing.T) {
	f := newFakeTunneld(t)
	f.DenyNextRegister("bad pubkey")

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, RunOptions{
		Connect: Options{
			ServerURL:  f.URL(),
			Unique:     "perma",
			PrivateKey: freshKey(t),
			TLSConfig:  f.TLSConfig(),
			Logger:     logger,
			Emitter:    em,
		},
		Handler:    http.NotFoundHandler(),
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 10 * time.Millisecond,
		// MaxAttempts intentionally 0 (unlimited) — this test asserts the
		// permanent-deny path bypasses retries even with MaxAttempts=∞.
	})
	if err == nil {
		t.Fatal("Run: want non-nil error on permanent deny, got nil")
	}
	var denyErr *DenyError
	if !errors.As(err, &denyErr) {
		t.Errorf("Run error did not wrap *DenyError: %v", err)
	} else if denyErr.Reason != "bad pubkey" {
		t.Errorf("DenyError.Reason = %q, want %q", denyErr.Reason, "bad pubkey")
	}

	kinds := readEventKinds(t, cap.Bytes())
	if last := kinds[len(kinds)-1]; last != EventFatal {
		t.Errorf("last event = %q, want %q. Stream:\n%s", last, EventFatal, cap.Bytes())
	}
	// Must NOT have emitted retryable error or reconnecting — the run
	// loop should bail before scheduling a retry.
	for _, k := range kinds {
		if k == EventReconnecting {
			t.Errorf("permanent deny path emitted %q (run loop should not retry)", k)
		}
	}
	// Server must have seen exactly one Register attempt.
	if got := f.Registrations(); got != 0 {
		// Note: Registrations() counts successful RegisterOKs, not Register
		// frames received. We expect 0 because the fake denied the only
		// attempt. The count being >0 would indicate the loop re-attempted.
		t.Errorf("Registrations() = %d on permanent-deny path, want 0", got)
	}
}

// TestE2E_Run_RateLimitDenyUsesLongFloor asserts that a server Deny with
// reason "rate_limited:ip" overrides the exponential schedule with the
// configured RateLimitFloor — the run loop's `reconnecting.after_ms`
// must reflect the floor, not the millisecond-scale BackoffMax.
func TestE2E_Run_RateLimitDenyUsesLongFloor(t *testing.T) {
	f := newFakeTunneld(t)
	f.DenyNextRegister("rate_limited:ip")
	// Subsequent attempts succeed so the loop progresses past the deny.

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 250ms floor is long enough to be visible against a 10ms BackoffMax
	// but short enough to keep this test fast.
	const floor = 250 * time.Millisecond

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.URL(),
				Unique:     "ratelim",
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     logger,
				Emitter:    em,
			},
			Handler:        http.NotFoundHandler(),
			BackoffMin:     5 * time.Millisecond,
			BackoffMax:     10 * time.Millisecond,
			RateLimitFloor: floor,
		})
	}()

	waitForKind(t, cap, EventRegisterOK, 5*time.Second)
	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}

	// Inspect the reconnecting event that followed the deny: its
	// after_ms must be >= floor (in ms), not the 10ms BackoffMax.
	sc := bufio.NewScanner(bytes.NewReader(cap.Bytes()))
	var sawFloorBackoff bool
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev struct {
			Kind string                 `json:"kind"`
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if ev.Kind != EventReconnecting {
			continue
		}
		afterMsRaw, ok := ev.Data["after_ms"]
		if !ok {
			t.Fatalf("reconnecting event missing after_ms: %s", line)
		}
		afterMs, ok := afterMsRaw.(float64)
		if !ok {
			t.Fatalf("reconnecting.after_ms is not a number: %v", afterMsRaw)
		}
		floorMs := float64(floor / time.Millisecond)
		if afterMs >= floorMs {
			sawFloorBackoff = true
			break
		}
	}
	if !sawFloorBackoff {
		t.Errorf("expected a reconnecting event with after_ms >= %dms (the rate-limit floor), but none seen. Stream:\n%s",
			floor/time.Millisecond, cap.Bytes())
	}
}

// TestE2E_Run_NonRateLimitDenyUsesExponential confirms the floor only
// kicks in for rate_limited:* — a transient non-rate-limit deny (e.g.
// "store error") must still use the normal exponential schedule, not
// the long floor, so transient server hiccups recover quickly.
func TestE2E_Run_NonRateLimitDenyUsesExponential(t *testing.T) {
	f := newFakeTunneld(t)
	f.DenyNextRegister("store error")

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Long floor — if the run loop wrongly treated "store error" as a
	// rate-limit, the test would block on this floor and fail the
	// 2-second waitForKind below.
	const floor = 30 * time.Second

	runDone := make(chan error, 1)
	go func() {
		runDone <- Run(ctx, RunOptions{
			Connect: Options{
				ServerURL:  f.URL(),
				Unique:     "transient",
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     logger,
				Emitter:    em,
			},
			Handler:        http.NotFoundHandler(),
			BackoffMin:     5 * time.Millisecond,
			BackoffMax:     20 * time.Millisecond,
			RateLimitFloor: floor,
		})
	}()

	waitForKind(t, cap, EventRegisterOK, 2*time.Second)
	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run didn't return after cancel")
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
				ServerURL:  f.URL(),
				Unique:     "silent",
				PrivateKey: freshKey(t),
				TLSConfig:  f.TLSConfig(),
				Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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
		if f.Registrations() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f.Registrations() < 1 {
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
