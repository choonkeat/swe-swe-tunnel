package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
)

// blockingEnsurer sleeps until the test-supplied channel closes, then
// returns nil. Used to stand in for a real ACME path that would
// normally block on DNS-01 propagation. The test asserts whether
// EnsureName was ever entered.
type blockingEnsurer struct {
	mu      sync.Mutex
	called  bool
	release chan struct{}
}

func (b *blockingEnsurer) EnsureName(ctx context.Context, _ string) error {
	b.mu.Lock()
	b.called = true
	b.mu.Unlock()
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingEnsurer) Called() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.called
}

// graceHarness is a tighter-than-regHarness driver that lets us pass a
// custom ctx into handleRegister directly (regHarness uses
// context.Background, which precludes cancellation tests).
type graceHarness struct {
	t        *testing.T
	server   net.Conn
	client   net.Conn
	ipLim    *ratelimit.SlidingWindow
	keyLim   *ratelimit.SlidingWindow
	ensurer  *blockingEnsurer
	store    *identity.Store
	resultCh chan handleResult
	logBuf   *bytes.Buffer
}

func newGraceHarness(t *testing.T) *graceHarness {
	t.Helper()
	store, err := identity.Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatalf("identity.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	return &graceHarness{
		t:        t,
		server:   server,
		client:   client,
		ipLim:    ratelimit.New(0, time.Hour),
		keyLim:   ratelimit.New(0, 24*time.Hour),
		ensurer:  &blockingEnsurer{release: make(chan struct{})},
		store:    store,
		resultCh: make(chan handleResult, 1),
		logBuf:   &bytes.Buffer{},
	}
}

func (h *graceHarness) start(ctx context.Context) {
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(h.logBuf), nil))
	go func() {
		res, ok := handleRegister(ctx, h.server, h.store, h.ensurer,
			h.ipLim, h.keyLim, nil, nil, logger, "127.0.0.1:54321", nil)
		h.resultCh <- handleResult{res: res, ok: ok}
	}()
}

func (h *graceHarness) sendRegister(unique string, priv ed25519.PrivateKey) {
	h.t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	ts := time.Now().Unix()
	sig := ed25519.Sign(priv, control.RegisterSigningPayload(pub, unique, ts))
	if err := control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version:   control.ProtoVersion,
		Unique:    unique,
		Pubkey:    base64.RawStdEncoding.EncodeToString(pub),
		Timestamp: ts,
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	}); err != nil {
		h.t.Fatalf("WriteMessage Register: %v", err)
	}
}

// TestIssuanceGrace_ClientBailsDuringGrace simulates the
// typo-then-Ctrl-C flow: handleRegister enters the grace window, then
// the request ctx fires (the connectHandler bridge would normally fire
// it on yamux close). Server must NOT call EnsureName, must refund both
// rate-limit budgets, must log an "aborted by client" line.
func TestIssuanceGrace_ClientBailsDuringGrace(t *testing.T) {
	prev := issuanceGrace
	issuanceGrace = 500 * time.Millisecond
	t.Cleanup(func() { issuanceGrace = prev })

	h := newGraceHarness(t)
	// Limit to 1 token each so we can detect refund: a successful
	// CancelLatest puts the budget back to "Allow returns true."
	h.ipLim = ratelimit.New(1, time.Hour)
	h.keyLim = ratelimit.New(1, 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	h.start(ctx)

	_, priv := newKey(t)
	h.sendRegister("typo", priv)

	// Let the server consume the rate-limit tokens and enter the grace.
	time.Sleep(100 * time.Millisecond)

	// Sanity: at this moment the budgets should be exhausted (1 token
	// each, both consumed by the in-flight Register).
	if h.ipLim.Allow("127.0.0.1") {
		t.Error("ipLim still permitting BEFORE bail — handleRegister hasn't consumed yet?")
	}

	// Trigger the bail.
	cancel()

	res := <-h.resultCh
	if res.ok {
		t.Fatal("handleRegister returned ok=true; expected bail during grace")
	}
	if h.ensurer.Called() {
		t.Fatal("EnsureName was called despite client-bail during grace — LE slot would have been burned")
	}

	// Refund check: both budgets must be available again.
	if !h.ipLim.Allow("127.0.0.1") {
		t.Error("ipLim still exhausted after bail — CancelLatest didn't refund the IP token")
	}
	pubB64 := string(priv.Public().(ed25519.PublicKey))
	if !h.keyLim.Allow(pubB64) {
		t.Error("keyLim still exhausted after bail — CancelLatest didn't refund the pubkey token")
	}

	// Log line for operator visibility.
	if !strings.Contains(h.logBuf.String(), "register aborted by client during issuance grace") {
		t.Errorf("expected 'register aborted by client during issuance grace' in log; got:\n%s",
			h.logBuf.String())
	}
}

// TestIssuanceGrace_HappyPathProceedsAfterGrace confirms a client that
// stays connected through the grace gets normal RegisterOK behavior:
// EnsureName is called, no spurious refund, registration completes.
func TestIssuanceGrace_HappyPathProceedsAfterGrace(t *testing.T) {
	prev := issuanceGrace
	issuanceGrace = 200 * time.Millisecond
	t.Cleanup(func() { issuanceGrace = prev })

	h := newGraceHarness(t)
	h.ipLim = ratelimit.New(1, time.Hour)
	h.keyLim = ratelimit.New(1, 24*time.Hour)
	// Release the ensurer immediately so the post-grace path completes.
	close(h.ensurer.release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.start(ctx)

	_, priv := newKey(t)
	h.sendRegister("happy", priv)

	res := <-h.resultCh
	if !res.ok {
		t.Fatalf("handleRegister returned ok=false after grace; log:\n%s", h.logBuf.String())
	}
	if !h.ensurer.Called() {
		t.Fatal("EnsureName was NOT called on happy path after grace")
	}

	// Budgets must remain consumed (no spurious CancelLatest on happy path).
	if h.ipLim.Allow("127.0.0.1") {
		t.Error("ipLim was refunded on happy path — CancelLatest fired when it shouldn't")
	}
	pubB64 := string(priv.Public().(ed25519.PublicKey))
	if h.keyLim.Allow(pubB64) {
		t.Error("keyLim was refunded on happy path — CancelLatest fired when it shouldn't")
	}
}

// TestIssuanceGrace_ZeroDisablesEntirely is the regression gate against
// an accidental future "0 means infinite" interpretation. With grace=0,
// the entire select/timer block is skipped — handleRegister proceeds
// straight to EnsureName as it did before this commit, and no bail
// log line is emitted.
func TestIssuanceGrace_ZeroDisablesEntirely(t *testing.T) {
	// Be explicit about the invariant under test (TestMain sets it to
	// zero by default; this guard makes the test tolerant of test
	// reordering or future TestMain changes).
	prev := issuanceGrace
	issuanceGrace = 0
	t.Cleanup(func() { issuanceGrace = prev })

	h := newGraceHarness(t)
	close(h.ensurer.release) // happy-path ensurer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.start(ctx)

	_, priv := newKey(t)
	h.sendRegister("zero", priv)

	res := <-h.resultCh
	if !res.ok {
		t.Fatalf("handleRegister returned ok=false with grace=0; "+
			"happy path broke. log:\n%s", h.logBuf.String())
	}
	if !h.ensurer.Called() {
		t.Error("EnsureName not called with grace=0 — gate logic regressed")
	}
	// Crucially, no grace-bail log line should ever appear when grace=0.
	if strings.Contains(h.logBuf.String(), "register aborted by client during issuance grace") {
		t.Errorf("grace-bail log appeared with grace=0:\n%s", h.logBuf.String())
	}
}
