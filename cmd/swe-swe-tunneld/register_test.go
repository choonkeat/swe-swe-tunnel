package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
)

// fakeEnsurer is a stub for certEnsurer. Records the labels it was asked to
// ensure; optionally returns the error in `err`.
type fakeEnsurer struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeEnsurer) EnsureName(_ context.Context, label string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, label)
	return f.err
}

func (f *fakeEnsurer) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// regHarness wires handleRegister against an in-memory stream and exposes the
// "client" end for the test to drive.
//
// Lifecycle: newRegHarness builds the wiring; tests may then pre-seed the
// store, swap limiters, or set ensurer.err; finally start() launches the
// handleRegister goroutine.
type regHarness struct {
	t        *testing.T
	server   net.Conn
	client   net.Conn
	store    *identity.Store
	ensurer  *fakeEnsurer
	ipLim    *ratelimit.SlidingWindow
	keyLim   *ratelimit.SlidingWindow
	resultCh chan handleResult
}

type handleResult struct {
	res registerResult
	ok  bool
}

func newRegHarness(t *testing.T) *regHarness {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "ids.db")
	store, err := identity.Open(dbPath)
	if err != nil {
		t.Fatalf("identity.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	return &regHarness{
		t:        t,
		server:   server,
		client:   client,
		store:    store,
		ensurer:  &fakeEnsurer{},
		ipLim:    ratelimit.New(0, time.Hour),
		keyLim:   ratelimit.New(0, 24*time.Hour),
		resultCh: make(chan handleResult, 1),
	}
}

func (h *regHarness) start() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		res, ok := handleRegister(context.Background(), h.server,
			h.store, h.ensurer, h.ipLim, h.keyLim, logger, "127.0.0.1:54321")
		h.resultCh <- handleResult{res: res, ok: ok}
	}()
}

func (h *regHarness) awaitResult() handleResult {
	h.t.Helper()
	select {
	case r := <-h.resultCh:
		return r
	case <-time.After(5 * time.Second):
		h.t.Fatal("handleRegister did not return")
		return handleResult{}
	}
}

// sendRegister builds and sends a Register frame signed by priv.
func (h *regHarness) sendRegister(unique string, priv ed25519.PrivateKey, ts int64) {
	h.t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
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

func (h *regHarness) readFrame() control.Frame {
	h.t.Helper()
	f, err := control.ReadFrame(h.client)
	if err != nil {
		h.t.Fatalf("ReadFrame: %v", err)
	}
	return f
}

func (h *regHarness) expectKind(want control.Kind) control.Frame {
	h.t.Helper()
	f := h.readFrame()
	if f.Type != want {
		var d control.Deny
		_ = control.DecodePayload(f, &d)
		h.t.Fatalf("frame type = %q (Deny.Reason=%q), want %q", f.Type, d.Reason, want)
	}
	return f
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// --------------------------------------------------------------------------
// Happy paths
// --------------------------------------------------------------------------

func TestHandleRegister_FreshRegistration(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_, priv := newKey(t)
	h.sendRegister("alpha", priv, time.Now().Unix())

	res := h.awaitResult()
	if !res.ok {
		t.Fatal("handleRegister returned !ok")
	}
	if res.res.unique != "alpha" || res.res.label != "alpha-tunnel" {
		t.Errorf("got unique=%q label=%q, want alpha / alpha-tunnel",
			res.res.unique, res.res.label)
	}
	if !res.res.newRegistration {
		t.Error("expected newRegistration=true on first register")
	}
	if !bytes.Equal(res.res.pubkey, priv.Public().(ed25519.PublicKey)) {
		t.Error("registerResult.pubkey not set to the connecting client's pubkey")
	}
	if got := h.ensurer.Calls(); len(got) != 1 || got[0] != "alpha-tunnel" {
		t.Errorf("ensurer calls = %v, want [alpha-tunnel]", got)
	}
	got, err := h.store.Get(context.Background(), "alpha")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !bytes.Equal(got.Pubkey, priv.Public().(ed25519.PublicKey)) {
		t.Error("stored pubkey mismatch")
	}
}

func TestHandleRegister_ReconnectIdempotent(t *testing.T) {
	h := newRegHarness(t)
	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	if err := h.store.Put(context.Background(), "alpha", pub, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.start()

	h.sendRegister("alpha", priv, time.Now().Unix())
	res := h.awaitResult()
	if !res.ok || res.res.unique != "alpha" || res.res.newRegistration {
		t.Fatalf("reconnect: got %+v ok=%v, want unique=alpha newRegistration=false ok=true",
			res.res, res.ok)
	}
	if got := h.ensurer.Calls(); len(got) != 0 {
		t.Errorf("ensurer should not be called on idempotent reconnect, got %v", got)
	}
}

// --------------------------------------------------------------------------
// Failure paths
// --------------------------------------------------------------------------

func TestHandleRegister_BadSignature(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	_ = control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version:   control.ProtoVersion,
		Unique:    "alpha",
		Pubkey:    base64.RawStdEncoding.EncodeToString(pub),
		Timestamp: time.Now().Unix(),
		Sig:       base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	expectDeny(t, h, "signature invalid")
}

func TestHandleRegister_BadUnique(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, control.RegisterSigningPayload(pub, "Bad.Unique", time.Now().Unix()))
	_ = control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version:   control.ProtoVersion,
		Unique:    "Bad.Unique",
		Pubkey:    base64.RawStdEncoding.EncodeToString(pub),
		Timestamp: time.Now().Unix(),
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	})
	expectDenyContains(t, h, "invalid unique")
}

func TestHandleRegister_ClockSkewTooFar(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_, priv := newKey(t)
	staleTs := time.Now().Add(-time.Hour).Unix()
	h.sendRegister("alpha", priv, staleTs)
	expectDeny(t, h, "timestamp out of range")
}

func TestHandleRegister_WrongFrameType(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_ = control.WriteMessage(h.client, control.KindProof, control.Proof{Sig: ""})
	expectDenyContains(t, h, "expected register")
}

func TestHandleRegister_VersionMismatch(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, control.RegisterSigningPayload(pub, "alpha", time.Now().Unix()))
	_ = control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version:   999,
		Unique:    "alpha",
		Pubkey:    base64.RawStdEncoding.EncodeToString(pub),
		Timestamp: time.Now().Unix(),
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	})
	expectDenyContains(t, h, "unsupported protocol version")
}

func TestHandleRegister_BadPubkeyEncoding(t *testing.T) {
	h := newRegHarness(t)
	h.start()

	_ = control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version:   control.ProtoVersion,
		Unique:    "alpha",
		Pubkey:    "$$$ not base64",
		Timestamp: time.Now().Unix(),
		Sig:       "aaaa",
	})
	expectDeny(t, h, "bad pubkey")
}

// --------------------------------------------------------------------------
// Challenge / Proof paths
// --------------------------------------------------------------------------

func TestHandleRegister_ChallengeMismatchedKey_Deny(t *testing.T) {
	h := newRegHarness(t)
	_, priv1 := newKey(t)
	if err := h.store.Put(context.Background(), "alpha",
		priv1.Public().(ed25519.PublicKey), time.Now()); err != nil {
		t.Fatal(err)
	}
	h.start()

	_, priv2 := newKey(t)
	h.sendRegister("alpha", priv2, time.Now().Unix())

	chFrame := h.expectKind(control.KindChallenge)
	var ch control.Challenge
	if err := control.DecodePayload(chFrame, &ch); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(ch.Nonce)
	if err != nil || len(nonce) != 32 {
		t.Fatalf("bad nonce: len=%d err=%v", len(nonce), err)
	}

	// Sign with priv2 — wrong key — server stored priv1.
	proofSig := ed25519.Sign(priv2, control.ProofSigningPayload(nonce))
	_ = control.WriteMessage(h.client, control.KindProof, control.Proof{
		Sig: base64.RawStdEncoding.EncodeToString(proofSig),
	})
	expectDeny(t, h, "key_mismatch")

	got, _ := h.store.Get(context.Background(), "alpha")
	if !bytes.Equal(got.Pubkey, priv1.Public().(ed25519.PublicKey)) {
		t.Error("stored pubkey was rotated despite failed proof")
	}
}

func TestHandleRegister_ChallengeWithStoredKey_Rotate(t *testing.T) {
	h := newRegHarness(t)
	_, priv1 := newKey(t)
	_, priv2 := newKey(t)
	if err := h.store.Put(context.Background(), "alpha",
		priv1.Public().(ed25519.PublicKey), time.Now()); err != nil {
		t.Fatal(err)
	}
	h.start()

	// Owner connects with the NEW key (priv2).
	h.sendRegister("alpha", priv2, time.Now().Unix())

	chFrame := h.expectKind(control.KindChallenge)
	var ch control.Challenge
	_ = control.DecodePayload(chFrame, &ch)
	nonce, _ := base64.RawStdEncoding.DecodeString(ch.Nonce)

	// Proof signed with the STORED key (priv1).
	proofSig := ed25519.Sign(priv1, control.ProofSigningPayload(nonce))
	_ = control.WriteMessage(h.client, control.KindProof, control.Proof{
		Sig: base64.RawStdEncoding.EncodeToString(proofSig),
	})

	res := h.awaitResult()
	if !res.ok {
		t.Fatal("rotate: handleRegister returned !ok")
	}
	if res.res.newRegistration {
		t.Error("rotate should not flip newRegistration=true")
	}

	got, _ := h.store.Get(context.Background(), "alpha")
	if !bytes.Equal(got.Pubkey, priv2.Public().(ed25519.PublicKey)) {
		t.Error("stored pubkey was not rotated to new key after successful proof")
	}
}

// --------------------------------------------------------------------------
// Rate limits
// --------------------------------------------------------------------------

func TestHandleRegister_PerIPRateLimit(t *testing.T) {
	h := newRegHarness(t)
	h.ipLim = ratelimit.New(1, time.Hour)
	_ = h.ipLim.Allow("127.0.0.1") // pre-consume budget
	h.start()

	_, priv := newKey(t)
	h.sendRegister("alpha", priv, time.Now().Unix())
	expectDenyWithRetryAfter(t, h, "rate_limited:ip", 1)
}

func TestHandleRegister_PerPubkeyRateLimit(t *testing.T) {
	h := newRegHarness(t)
	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	h.keyLim = ratelimit.New(1, 24*time.Hour)
	_ = h.keyLim.Allow(string(pub))
	h.start()

	h.sendRegister("alpha", priv, time.Now().Unix())
	// 24h window; one slot consumed → retry-after must be ~24h.
	expectDenyWithRetryAfter(t, h, "rate_limited:pubkey", 1)
}

// Idempotent reconnect (existing unique, same pubkey) must NOT consume a
// per-pubkey rate-limit slot — the budget exists to cap how many new uniques
// a keypair can claim, not how often a tunnel can reconnect.
func TestHandleRegister_IdempotentReconnect_DoesNotConsumePubkeyBudget(t *testing.T) {
	h := newRegHarness(t)
	_, priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	if err := h.store.Put(context.Background(), "alpha", pub, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Capacity 1, already exhausted: a new-unique attempt would be denied.
	h.keyLim = ratelimit.New(1, 24*time.Hour)
	_ = h.keyLim.Allow(string(pub))
	h.start()

	h.sendRegister("alpha", priv, time.Now().Unix())
	res := h.awaitResult()
	if !res.ok || res.res.newRegistration {
		t.Fatalf("idempotent reconnect denied or flipped newRegistration: %+v ok=%v", res.res, res.ok)
	}
}

// Challenge/proof flow (existing unique, different pubkey) must NOT consume a
// per-pubkey slot for the *connecting* key. The IP limit still throttles, and
// Proof verification is the cryptographic gate.
func TestHandleRegister_ChallengeFlow_DoesNotConsumePubkeyBudget(t *testing.T) {
	h := newRegHarness(t)
	_, ownerPriv := newKey(t)
	if err := h.store.Put(context.Background(), "alpha",
		ownerPriv.Public().(ed25519.PublicKey), time.Now()); err != nil {
		t.Fatal(err)
	}

	_, attackerPriv := newKey(t)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	// Capacity 1, already exhausted for the attacker's key.
	h.keyLim = ratelimit.New(1, 24*time.Hour)
	_ = h.keyLim.Allow(string(attackerPub))
	h.start()

	h.sendRegister("alpha", attackerPriv, time.Now().Unix())

	// The attacker's pubkey budget is exhausted, but the limiter must not be
	// consulted on this code path: server should reach Challenge.
	chFrame := h.expectKind(control.KindChallenge)
	var ch control.Challenge
	_ = control.DecodePayload(chFrame, &ch)
	nonce, _ := base64.RawStdEncoding.DecodeString(ch.Nonce)

	// Sign with the attacker's wrong key — Proof will fail with key_mismatch,
	// which is the proper defense (cryptographic, not rate-limit).
	proofSig := ed25519.Sign(attackerPriv, control.ProofSigningPayload(nonce))
	_ = control.WriteMessage(h.client, control.KindProof, control.Proof{
		Sig: base64.RawStdEncoding.EncodeToString(proofSig),
	})
	expectDeny(t, h, "key_mismatch")
}

// New-unique attempts under the same key still count: 11 fresh uniques with
// budget 10 must produce one rate_limited:pubkey deny.
func TestHandleRegister_NewUniques_StillCountTowardPubkeyBudget(t *testing.T) {
	_, priv := newKey(t)
	keyLim := ratelimit.New(10, 24*time.Hour)

	// First 10 fresh uniques succeed.
	for i := 0; i < 10; i++ {
		h := newRegHarness(t)
		h.keyLim = keyLim
		h.start()
		unique := "u" + string(rune('a'+i)) + "x"
		h.sendRegister(unique, priv, time.Now().Unix())
		res := h.awaitResult()
		if !res.ok {
			t.Fatalf("attempt %d (unique=%s) denied: %+v", i+1, unique, res)
		}
	}
	// 11th must be rate-limited (budget exhausted).
	h := newRegHarness(t)
	h.keyLim = keyLim
	h.start()
	h.sendRegister("ulast", priv, time.Now().Unix())
	expectDeny(t, h, "rate_limited:pubkey")
}

// --------------------------------------------------------------------------
// Cert ensurer failure
// --------------------------------------------------------------------------

func TestHandleRegister_CertEnsurerFails_NoStore(t *testing.T) {
	h := newRegHarness(t)
	h.ensurer.err = errors.New("ACME outage")
	h.start()

	_, priv := newKey(t)
	h.sendRegister("alpha", priv, time.Now().Unix())
	expectDeny(t, h, "cert issuance failed")

	if _, err := h.store.Get(context.Background(), "alpha"); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("store should not have alpha after cert failure; err = %v", err)
	}
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

func expectDeny(t *testing.T, h *regHarness, wantReason string) {
	t.Helper()
	f := h.expectKind(control.KindDeny)
	var d control.Deny
	if err := control.DecodePayload(f, &d); err != nil {
		t.Fatalf("decode Deny: %v", err)
	}
	if d.Reason != wantReason {
		t.Errorf("Deny.Reason = %q, want %q", d.Reason, wantReason)
	}
	res := h.awaitResult()
	if res.ok {
		t.Error("handleRegister returned ok=true on deny path")
	}
}

func expectDenyContains(t *testing.T, h *regHarness, substr string) {
	t.Helper()
	f := h.expectKind(control.KindDeny)
	var d control.Deny
	_ = control.DecodePayload(f, &d)
	if !bytes.Contains([]byte(d.Reason), []byte(substr)) {
		t.Errorf("Deny.Reason = %q, want substring %q", d.Reason, substr)
	}
	res := h.awaitResult()
	if res.ok {
		t.Error("handleRegister returned ok=true on deny path")
	}
}

// expectDenyWithRetryAfter verifies a rate-limit deny carries a positive
// RetryAfterSec >= minSec. We can't pin the exact value because the
// handler computes it from time.Now() against a real SlidingWindow, so
// the test only asserts the lower bound: a server that forgets to set
// the field returns zero, which fails this check.
func expectDenyWithRetryAfter(t *testing.T, h *regHarness, wantReason string, minSec int) {
	t.Helper()
	f := h.expectKind(control.KindDeny)
	var d control.Deny
	if err := control.DecodePayload(f, &d); err != nil {
		t.Fatalf("decode Deny: %v", err)
	}
	if d.Reason != wantReason {
		t.Errorf("Deny.Reason = %q, want %q", d.Reason, wantReason)
	}
	if d.RetryAfterSec < minSec {
		t.Errorf("Deny.RetryAfterSec = %d, want >= %d", d.RetryAfterSec, minSec)
	}
	res := h.awaitResult()
	if res.ok {
		t.Error("handleRegister returned ok=true on deny path")
	}
}
