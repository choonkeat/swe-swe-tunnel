package tunnelclient

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a deterministic, monotonically increasing time so
// emitted RFC3339Nano timestamps are stable across runs.
func fixedClock() func() time.Time {
	t := time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now := t
		t = t.Add(time.Millisecond)
		return now
	}
}

// parseLines decodes JSON-lines into envelopes. Any non-JSON line fails
// the test.
func parseLines(t *testing.T, raw []byte) []envelope {
	t.Helper()
	var out []envelope
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev envelope
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

func TestJSONLEmitterEnvelopeShape(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()

	e.Emit(EventStarting, StartingData{Unique: "alpha", ServerURL: "https://tunnel.example.com"})

	lines := parseLines(t, buf.Bytes())
	if got := len(lines); got != 1 {
		t.Fatalf("want 1 line, got %d", got)
	}
	ev := lines[0]
	if ev.V != 1 {
		t.Errorf("v: want 1, got %d", ev.V)
	}
	if ev.Kind != EventStarting {
		t.Errorf("kind: want %q, got %q", EventStarting, ev.Kind)
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.TS); err != nil {
		t.Errorf("ts %q is not RFC3339Nano: %v", ev.TS, err)
	}
	var data StartingData
	if err := json.Unmarshal(ev.Data, &data); err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if data.Unique != "alpha" || data.ServerURL != "https://tunnel.example.com" {
		t.Errorf("data mismatch: %+v", data)
	}
}

func TestJSONLEmitterEachKindRoundTrips(t *testing.T) {
	cases := []struct {
		kind string
		data any
		want any
	}{
		{EventStarting, StartingData{Unique: "alpha", ServerURL: "https://x"}, &StartingData{}},
		{EventConnecting, ConnectingData{ServerURL: "https://x", Attempt: 1}, &ConnectingData{}},
		{EventRegisterOK, RegisterOKData{Hostname: "alpha-tunnel.x", Unique: "alpha"}, &RegisterOKData{}},
		{EventRelabel, RelabelData{Hostname: "alpha2-tunnel.x", OldHostname: "alpha-tunnel.x"}, &RelabelData{}},
		{EventDisconnected, DisconnectedData{Reason: "control stream EOF"}, &DisconnectedData{}},
		{EventReconnecting, ReconnectingData{AfterMs: 1000, Attempt: 2}, &ReconnectingData{}},
		{EventDeregisterOK, DeregisterOKData{Unique: "alpha"}, &DeregisterOKData{}},
		{EventError, ErrorData{Message: "boom", Retryable: true}, &ErrorData{}},
		{EventFatal, FatalData{Message: "fatal", ExitCode: 1}, &FatalData{}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			var buf bytes.Buffer
			e := NewJSONLEmitter(&buf)
			e.now = fixedClock()
			e.Emit(tc.kind, tc.data)

			lines := parseLines(t, buf.Bytes())
			if len(lines) != 1 {
				t.Fatalf("want 1 line, got %d", len(lines))
			}
			if err := json.Unmarshal(lines[0].Data, tc.want); err != nil {
				t.Fatalf("decode %s data: %v", tc.kind, err)
			}
			// Re-marshal both sides to canonical JSON and compare. Avoids
			// reflect.DeepEqual on pointer-vs-value mismatches.
			gotJSON, _ := json.Marshal(tc.want)
			origJSON, _ := json.Marshal(tc.data)
			if !bytes.Equal(gotJSON, origJSON) {
				t.Errorf("%s round-trip mismatch:\norig: %s\ngot:  %s", tc.kind, origJSON, gotJSON)
			}
		})
	}
}

// TestJSONLEmitterScriptedLifecycle drives a full happy path through the
// emitter and asserts the kind sequence matches the documented invariants:
// starting -> connecting -> register_ok -> disconnected -> reconnecting
// -> connecting -> register_ok -> deregister_ok.
func TestJSONLEmitterScriptedLifecycle(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()

	e.Emit(EventStarting, StartingData{Unique: "alpha", ServerURL: "https://x"})
	e.Emit(EventConnecting, ConnectingData{ServerURL: "https://x", Attempt: 1})
	e.Emit(EventRegisterOK, RegisterOKData{Hostname: "alpha-tunnel.x", Unique: "alpha"})
	e.Emit(EventDisconnected, DisconnectedData{Reason: "control stream EOF"})
	e.Emit(EventReconnecting, ReconnectingData{AfterMs: 1000, Attempt: 2})
	e.Emit(EventConnecting, ConnectingData{ServerURL: "https://x", Attempt: 2})
	e.Emit(EventRegisterOK, RegisterOKData{Hostname: "alpha-tunnel.x", Unique: "alpha"})
	e.Emit(EventDeregisterOK, DeregisterOKData{Unique: "alpha"})

	want := []string{
		EventStarting, EventConnecting, EventRegisterOK,
		EventDisconnected, EventReconnecting, EventConnecting, EventRegisterOK,
		EventDeregisterOK,
	}
	lines := parseLines(t, buf.Bytes())
	if len(lines) != len(want) {
		t.Fatalf("want %d events, got %d", len(want), len(lines))
	}
	for i, w := range want {
		if lines[i].Kind != w {
			t.Errorf("event %d: want %q, got %q", i, w, lines[i].Kind)
		}
	}

	// Ordering invariant: starting is first.
	if lines[0].Kind != EventStarting {
		t.Errorf("starting must be the first line, got %q", lines[0].Kind)
	}
	// Ordering invariant: every register_ok comes after a connecting.
	for i, ev := range lines {
		if ev.Kind == EventRegisterOK {
			if i == 0 || lines[i-1].Kind != EventConnecting {
				t.Errorf("register_ok at index %d not preceded by connecting (prev=%q)", i, lines[i-1].Kind)
			}
		}
	}
	// Ordering invariant: every disconnected is followed by reconnecting
	// (or fatal — not tested here).
	for i, ev := range lines {
		if ev.Kind == EventDisconnected {
			if i+1 >= len(lines) || lines[i+1].Kind != EventReconnecting {
				t.Errorf("disconnected at index %d not followed by reconnecting", i)
			}
		}
	}

	// Timestamps must be monotonically non-decreasing.
	var prev time.Time
	for i, ev := range lines {
		ts, err := time.Parse(time.RFC3339Nano, ev.TS)
		if err != nil {
			t.Fatalf("event %d: bad ts %q: %v", i, ev.TS, err)
		}
		if i > 0 && ts.Before(prev) {
			t.Errorf("event %d ts %s before previous %s", i, ts, prev)
		}
		prev = ts
	}
}

// flushTrackingWriter wraps a bytes.Buffer and counts bytes written
// vs. flushed. The test fails if a Write happens without a subsequent
// Flush before the next Write.
type flushTrackingWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	pending  int  // bytes written since last Flush
	flushed  int  // total Flush calls
	writes   int  // total Write calls
	missed   int  // writes that ended without a flush before next write
	flushErr error
}

func (w *flushTrackingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending > 0 {
		// A previous Write was not followed by a Flush before this one.
		w.missed++
	}
	w.writes++
	w.pending += len(p)
	return w.buf.Write(p)
}

func (w *flushTrackingWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.flushErr != nil {
		return w.flushErr
	}
	w.pending = 0
	w.flushed++
	return nil
}

func (w *flushTrackingWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func TestJSONLEmitterFlushesAfterEveryWrite(t *testing.T) {
	w := &flushTrackingWriter{}
	e := NewJSONLEmitter(w)
	e.now = fixedClock()

	e.Emit(EventStarting, StartingData{Unique: "a", ServerURL: "https://x"})
	e.Emit(EventConnecting, ConnectingData{ServerURL: "https://x", Attempt: 1})
	e.Emit(EventRegisterOK, RegisterOKData{Hostname: "a-tunnel.x", Unique: "a"})

	if w.writes != 3 {
		t.Errorf("writes: want 3, got %d", w.writes)
	}
	if w.flushed != 3 {
		t.Errorf("flushed: want 3 (one per emit), got %d", w.flushed)
	}
	if w.missed != 0 {
		t.Errorf("write without flush before next write: %d times", w.missed)
	}
	// Sanity: emitted bytes still parse.
	if got := len(parseLines(t, w.bytes())); got != 3 {
		t.Errorf("parsed events: want 3, got %d", got)
	}
}

// TestJSONLEmitterUnknownKindForwardCompat: a synthetic "future" kind
// emitted by a hypothetical future producer must not crash a consumer
// that ignores unknown kinds. We simulate the consumer side here.
func TestJSONLEmitterUnknownKindForwardCompat(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()

	// A future kind with arbitrary data shape.
	e.Emit("metrics_v2", map[string]any{"bytes_in": 12345, "bytes_out": 678})
	e.Emit(EventRegisterOK, RegisterOKData{Hostname: "a-tunnel.x", Unique: "a"})

	known := map[string]bool{
		EventStarting: true, EventConnecting: true, EventRegisterOK: true,
		EventRelabel: true, EventDisconnected: true, EventReconnecting: true,
		EventDeregisterOK: true, EventError: true, EventFatal: true,
	}

	var seenKnown []string
	for _, ev := range parseLines(t, buf.Bytes()) {
		if !known[ev.Kind] {
			// Consumer logs and continues. No crash.
			continue
		}
		seenKnown = append(seenKnown, ev.Kind)
	}
	if len(seenKnown) != 1 || seenKnown[0] != EventRegisterOK {
		t.Errorf("forward-compat consumer: want [register_ok], got %v", seenKnown)
	}
}

func TestJSONLEmitterConcurrent(t *testing.T) {
	w := &flushTrackingWriter{}
	e := NewJSONLEmitter(w)
	e.now = fixedClock()

	const goroutines = 16
	const perG = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				e.Emit(EventConnecting, ConnectingData{
					ServerURL: fmt.Sprintf("https://x/%d/%d", g, i),
					Attempt:   i + 1,
				})
			}
		}(g)
	}
	wg.Wait()

	lines := parseLines(t, w.bytes())
	if got, want := len(lines), goroutines*perG; got != want {
		t.Errorf("event count: want %d, got %d", want, got)
	}
	// Every line must parse as a complete JSON object — i.e. no two
	// goroutines interleaved bytes within a line.
	if got := w.missed; got != 0 {
		t.Errorf("interleaved writes detected: %d", got)
	}
	// Every emit must have triggered a flush.
	if w.flushed != w.writes {
		t.Errorf("flushed=%d != writes=%d", w.flushed, w.writes)
	}
}

func TestNoopEmitter(t *testing.T) {
	var n NoopEmitter
	// Must not panic on any input, including nil data.
	n.Emit(EventStarting, nil)
	n.Emit(EventFatal, FatalData{Message: "x", ExitCode: 1})
}

// failingWriter returns an error on every Write. Used to verify that the
// emitter does not panic and reports the failure rather than swallowing.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestJSONLEmitterReportsWriteFailure(t *testing.T) {
	e := NewJSONLEmitter(failingWriter{})
	e.now = fixedClock()
	var got struct {
		kind string
		err  error
	}
	e.onErr = func(kind string, err error) { got.kind = kind; got.err = err }

	e.Emit(EventStarting, StartingData{Unique: "a", ServerURL: "https://x"})

	if got.kind != EventStarting {
		t.Errorf("onErr kind: want %q, got %q", EventStarting, got.kind)
	}
	if got.err == nil || !strings.Contains(got.err.Error(), "pipe closed") {
		t.Errorf("onErr err: want pipe-closed wrap, got %v", got.err)
	}
}

func TestJSONLEmitterRejectsNilData(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()
	var captured error
	e.onErr = func(_ string, err error) { captured = err }

	e.Emit(EventStarting, nil)

	if buf.Len() != 0 {
		t.Errorf("buf should be empty on nil-data emit, got %q", buf.String())
	}
	if captured == nil || !strings.Contains(captured.Error(), "nil data") {
		t.Errorf("want nil-data error, got %v", captured)
	}
}

// Compile-time assertion that NoopEmitter and JSONLEmitter satisfy
// Emitter. Keeps the interface contract explicit.
var (
	_ Emitter = NoopEmitter{}
	_ Emitter = (*JSONLEmitter)(nil)
)

// Sanity: an emitted line is exactly one trailing newline.
func TestJSONLEmitterSingleLineTerminator(t *testing.T) {
	var buf bytes.Buffer
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()
	e.Emit(EventStarting, StartingData{Unique: "a", ServerURL: "https://x"})
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output must end with \\n, got %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("want exactly 1 newline, got %d in %q", strings.Count(out, "\n"), out)
	}
	if strings.Contains(out, "\r") {
		t.Errorf("output must not contain CR, got %q", out)
	}
}

// Sanity: stdout-shaped writer (no Flush method) still gets bytes.
func TestJSONLEmitterPlainWriter(t *testing.T) {
	var buf plainWriter
	e := NewJSONLEmitter(&buf)
	e.now = fixedClock()
	e.Emit(EventStarting, StartingData{Unique: "a", ServerURL: "https://x"})
	if got := len(parseLines(t, buf.b)); got != 1 {
		t.Errorf("plain writer: want 1 event, got %d", got)
	}
}

// plainWriter is io.Writer with no Flush method, mirroring os.Stdout.
type plainWriter struct{ b []byte }

func (w *plainWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

var _ io.Writer = (*plainWriter)(nil)
