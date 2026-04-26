package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
)

// deregHarness drives runControlLoop against an in-memory stream, with a
// pre-seeded identity row simulating the post-RegisterOK state.
type deregHarness struct {
	t        *testing.T
	server   net.Conn
	client   net.Conn
	store    *identity.Store
	unique   string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	resultCh chan bool
}

func newDeregHarness(t *testing.T, unique string) *deregHarness {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "ids.db")
	store, err := identity.Open(dbPath)
	if err != nil {
		t.Fatalf("identity.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), unique, pub, time.Now()); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	return &deregHarness{
		t:        t,
		server:   server,
		client:   client,
		store:    store,
		unique:   unique,
		priv:     priv,
		pub:      pub,
		resultCh: make(chan bool, 1),
	}
}

func (h *deregHarness) start() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		h.resultCh <- runControlLoop(context.Background(), h.server,
			h.store, h.unique, h.pub, logger)
	}()
}

// startWithSessPubkey is for the post-rotation scenario where the session
// pubkey differs from what was originally seeded for `unique`.
func (h *deregHarness) startWithSessPubkey(sessPub ed25519.PublicKey) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		h.resultCh <- runControlLoop(context.Background(), h.server,
			h.store, h.unique, sessPub, logger)
	}()
}

func (h *deregHarness) awaitResult() bool {
	h.t.Helper()
	select {
	case r := <-h.resultCh:
		return r
	case <-time.After(5 * time.Second):
		h.t.Fatal("runControlLoop did not return")
		return false
	}
}

// sendDeregister writes a Deregister frame signed with the given key.
func (h *deregHarness) sendDeregister(unique string, ts int64, signWith ed25519.PrivateKey) {
	h.t.Helper()
	sig := ed25519.Sign(signWith, control.DeregisterSigningPayload(unique, ts))
	if err := control.WriteMessage(h.client, control.KindDeregister, control.Deregister{
		Unique:    unique,
		Timestamp: ts,
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	}); err != nil {
		h.t.Fatalf("write Deregister: %v", err)
	}
}

func (h *deregHarness) readFrame() control.Frame {
	h.t.Helper()
	f, err := control.ReadFrame(h.client)
	if err != nil {
		h.t.Fatalf("ReadFrame: %v", err)
	}
	return f
}

func (h *deregHarness) expectKind(want control.Kind) control.Frame {
	h.t.Helper()
	f := h.readFrame()
	if f.Type != want {
		var d control.Deny
		_ = control.DecodePayload(f, &d)
		h.t.Fatalf("frame type = %q (Deny.Reason=%q), want %q", f.Type, d.Reason, want)
	}
	return f
}

func (h *deregHarness) expectDenyReason(want string) {
	h.t.Helper()
	f := h.expectKind(control.KindDeny)
	var d control.Deny
	if err := control.DecodePayload(f, &d); err != nil {
		h.t.Fatalf("decode Deny: %v", err)
	}
	if d.Reason != want {
		h.t.Errorf("Deny.Reason = %q, want %q", d.Reason, want)
	}
}

// --------------------------------------------------------------------------
// Happy path
// --------------------------------------------------------------------------

func TestRunControlLoop_DeregisterHappyPath(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	h.sendDeregister("alpha", time.Now().Unix(), h.priv)
	h.expectKind(control.KindDeregisterOK)

	if !h.awaitResult() {
		t.Error("runControlLoop returned false; expected true after successful deregister")
	}
	if _, err := h.store.Get(context.Background(), "alpha"); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("alpha row should be gone after deregister, got err=%v", err)
	}
}

// --------------------------------------------------------------------------
// Failure paths — Deny + loop continues (until peer EOFs)
// --------------------------------------------------------------------------

func TestRunControlLoop_UniqueMismatch_DenyAndContinue(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Authenticated as "alpha", try to deregister "beta".
	h.sendDeregister("beta", time.Now().Unix(), h.priv)
	h.expectDenyReason("unique mismatch")

	// Loop should still be alive — confirm by sending a valid Deregister
	// for the right unique and watching it succeed.
	h.sendDeregister("alpha", time.Now().Unix(), h.priv)
	h.expectKind(control.KindDeregisterOK)
	if !h.awaitResult() {
		t.Error("expected true after the second (valid) deregister")
	}
}

func TestRunControlLoop_StaleTimestamp_DenyAndContinue(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	staleTs := time.Now().Add(-time.Hour).Unix()
	h.sendDeregister("alpha", staleTs, h.priv)
	h.expectDenyReason("timestamp out of range")

	// Row must still exist.
	if _, err := h.store.Get(context.Background(), "alpha"); err != nil {
		t.Errorf("alpha row should still exist after stale timestamp Deny: %v", err)
	}

	// And the loop should still be alive.
	h.sendDeregister("alpha", time.Now().Unix(), h.priv)
	h.expectKind(control.KindDeregisterOK)
	_ = h.awaitResult()
}

func TestRunControlLoop_BadSig_DenyAndContinue(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Sign with a different key — sig won't verify against h.pub.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	h.sendDeregister("alpha", time.Now().Unix(), otherPriv)
	h.expectDenyReason("signature invalid")

	if _, err := h.store.Get(context.Background(), "alpha"); err != nil {
		t.Errorf("alpha row should still exist after bad-sig Deny: %v", err)
	}

	// Loop alive.
	h.sendDeregister("alpha", time.Now().Unix(), h.priv)
	h.expectKind(control.KindDeregisterOK)
	_ = h.awaitResult()
}

func TestRunControlLoop_BadSigEncoding_Deny(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Send a Deregister frame whose Sig field isn't valid base64.
	if err := control.WriteMessage(h.client, control.KindDeregister, control.Deregister{
		Unique:    "alpha",
		Timestamp: time.Now().Unix(),
		Sig:       "$$$ not base64",
	}); err != nil {
		t.Fatal(err)
	}
	h.expectDenyReason("bad sig")
	_ = h.client.Close()
	_ = h.awaitResult()
}

func TestRunControlLoop_BadSigLength_Deny(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Sig that decodes cleanly but is the wrong length.
	if err := control.WriteMessage(h.client, control.KindDeregister, control.Deregister{
		Unique:    "alpha",
		Timestamp: time.Now().Unix(),
		Sig:       base64.RawStdEncoding.EncodeToString([]byte("too short")),
	}); err != nil {
		t.Fatal(err)
	}
	h.expectDenyReason("bad sig")
	_ = h.client.Close()
	_ = h.awaitResult()
}

// --------------------------------------------------------------------------
// Loop dispatcher behavior
// --------------------------------------------------------------------------

func TestRunControlLoop_PeerEOF_ReturnsFalse(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Close the client side without sending anything. ReadFrame on the
	// server side will error and the loop should return false (peer hangup).
	_ = h.client.Close()
	if h.awaitResult() {
		t.Error("expected false after peer hangup")
	}
	// alpha row stays — no Deregister was processed.
	if _, err := h.store.Get(context.Background(), "alpha"); err != nil {
		t.Errorf("alpha row should still exist after EOF: %v", err)
	}
}

func TestRunControlLoop_UnexpectedFrame_DenyAndContinue(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	h.start()

	// Send a Register frame post-RegisterOK — that's nonsensical at this
	// stage. Expect Deny but loop keeps reading.
	if err := control.WriteMessage(h.client, control.KindRegister, control.Register{
		Version: control.ProtoVersion,
		Unique:  "alpha",
	}); err != nil {
		t.Fatal(err)
	}
	f := h.expectKind(control.KindDeny)
	var d control.Deny
	_ = control.DecodePayload(f, &d)
	if !bytes.Contains([]byte(d.Reason), []byte("unexpected post-register frame")) {
		t.Errorf("Deny.Reason = %q, want it to contain 'unexpected post-register frame'", d.Reason)
	}

	// Loop alive — finish via peer close.
	_ = h.client.Close()
	_ = h.awaitResult()
}

// --------------------------------------------------------------------------
// Post-rotation scenario: the sessPubkey passed to runControlLoop is the
// CURRENT session key (post-rotate), and Deregister sigs must verify
// against THAT key, not the originally-seeded one.
// --------------------------------------------------------------------------

func TestRunControlLoop_DeregisterAfterRotation_UsesSessionKey(t *testing.T) {
	h := newDeregHarness(t, "alpha")
	// Simulate a rotation: the store has h.pub, but the session was just
	// authenticated as a NEW key (rotPriv/rotPub) via Challenge/Proof —
	// runControlLoop must accept Deregister sigs from the new key.
	rotPub, rotPriv, _ := ed25519.GenerateKey(nil)
	if err := h.store.Rotate(context.Background(), "alpha", rotPub, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.startWithSessPubkey(rotPub)

	// Old key must NOT work.
	h.sendDeregister("alpha", time.Now().Unix(), h.priv)
	h.expectDenyReason("signature invalid")

	// New (rotated) key works.
	h.sendDeregister("alpha", time.Now().Unix(), rotPriv)
	h.expectKind(control.KindDeregisterOK)
	if !h.awaitResult() {
		t.Error("rotated-key deregister should have returned true")
	}
}
