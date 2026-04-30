package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestValidateUnique(t *testing.T) {
	good := []string{"abc", "test-tunnel-test", "a1b", "a-b-c-d", "x12"}
	for _, s := range good {
		if err := ValidateUnique(s); err != nil {
			t.Errorf("ValidateUnique(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{
		"",
		"ab",                    // too short
		"-abc",                  // leading hyphen
		"abc-",                  // trailing hyphen
		"Abc",                   // uppercase
		"abc.def",               // dot
		"abc/def",               // slash
		strings.Repeat("a", 55), // too long
	}
	for _, s := range bad {
		if err := ValidateUnique(s); err == nil {
			t.Errorf("ValidateUnique(%q) = nil, want error", s)
		}
	}
}

func TestTunnelLabel(t *testing.T) {
	if got, want := TunnelLabel("abc"), "abc-tunnel"; got != want {
		t.Errorf("TunnelLabel(abc) = %q, want %q", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Register{Version: 1, Unique: "abc", Pubkey: "pk", Timestamp: 42, Sig: "sg"}
	if err := WriteMessage(&buf, KindRegister, in); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != KindRegister {
		t.Errorf("Type = %q, want %q", f.Type, KindRegister)
	}
	var out Register
	if err := DecodePayload(f, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out != in {
		t.Errorf("round-trip: got %+v, want %+v", out, in)
	}
}

// Deny round-trips both fields, and RetryAfterSec=0 omits from JSON
// (so old clients see exactly the same wire bytes as before this commit).
func TestDenyRoundTrip_WithRetryAfter(t *testing.T) {
	var buf bytes.Buffer
	in := Deny{Reason: "rate_limited:ip", RetryAfterSec: 42}
	if err := WriteMessage(&buf, KindDeny, in); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var out Deny
	if err := DecodePayload(f, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out != in {
		t.Errorf("round-trip: got %+v, want %+v", out, in)
	}
}

// Backwards-compat assertion: a Deny payload from an OLD server (no
// retry_after_seconds field) decodes cleanly and yields zero on the new
// field — so the new client falls back to its own RateLimitFloor.
func TestDeny_OldServerJSON_DecodesWithZero(t *testing.T) {
	// Wire bytes a pre-commit-2 server would write.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{
		Type:    KindDeny,
		Payload: []byte(`{"reason":"rate_limited:ip"}`),
	}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var out Deny
	if err := DecodePayload(f, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out.Reason != "rate_limited:ip" {
		t.Errorf("Reason = %q", out.Reason)
	}
	if out.RetryAfterSec != 0 {
		t.Errorf("RetryAfterSec = %d, want 0 for old-server payload", out.RetryAfterSec)
	}
}

// Forward-compat assertion: an OLD client unmarshalling a NEW server's
// payload (with retry_after_seconds present) gets the Reason without
// blowing up. The unknown field is silently ignored by encoding/json,
// which is the contract this test pins.
func TestDeny_NewServerJSON_OldClientIgnoresExtra(t *testing.T) {
	// Old client only knows about Reason — model it as a struct without
	// the new field.
	type oldDeny struct {
		Reason string `json:"reason"`
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, KindDeny, Deny{Reason: "rate_limited:ip", RetryAfterSec: 99}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var out oldDeny
	if err := DecodePayload(f, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if out.Reason != "rate_limited:ip" {
		t.Errorf("Reason = %q, want rate_limited:ip", out.Reason)
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 1024*1024)
	_, err := ReadFrame(bytes.NewReader(hdr))
	if err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Errorf("expected frame-too-large, got %v", err)
	}
}

func TestRegisterSigningRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const unique = "abc"
	ts := int64(1714137600)
	payload := RegisterSigningPayload(pub, unique, ts)
	sig := ed25519.Sign(priv, payload)
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("self-verify failed")
	}
	// Sanity: changing any field invalidates the signature.
	if ed25519.Verify(pub, RegisterSigningPayload(pub, "abd", ts), sig) {
		t.Error("signature should not verify for a different unique")
	}
	if ed25519.Verify(pub, RegisterSigningPayload(pub, unique, ts+1), sig) {
		t.Error("signature should not verify for a different timestamp")
	}
	// And: the base64 round-trip used on the wire.
	b64 := base64.RawStdEncoding.EncodeToString(sig)
	decoded, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil || !bytes.Equal(decoded, sig) {
		t.Fatalf("base64 round-trip lossy: %v", err)
	}
}

func TestProofSigningInputDistinct(t *testing.T) {
	// Reusing a Register signature as a Proof should fail because the domain
	// separator differs.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	regPayload := RegisterSigningPayload(pub, "abc", 1)
	regSig := ed25519.Sign(priv, regPayload)

	proofPayload := ProofSigningPayload([]byte{1, 2, 3, 4})
	if ed25519.Verify(pub, proofPayload, regSig) {
		t.Error("Register sig should not satisfy Proof verification — domain separators must differ")
	}
}

func TestDeregisterSigningInputDistinct(t *testing.T) {
	// A Deregister payload must not be satisfiable by a Register or Proof
	// signature even when the underlying fields collide. Domain separators
	// guarantee this.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const unique = "abc"
	const ts = int64(42)

	deregPayload := DeregisterSigningPayload(unique, ts)
	deregSig := ed25519.Sign(priv, deregPayload)
	if !ed25519.Verify(pub, deregPayload, deregSig) {
		t.Fatal("self-verify failed")
	}

	// Register sig over the same fields must not satisfy Deregister.
	regSig := ed25519.Sign(priv, RegisterSigningPayload(pub, unique, ts))
	if ed25519.Verify(pub, deregPayload, regSig) {
		t.Error("Register sig should not satisfy Deregister verification")
	}
	// And vice versa.
	if ed25519.Verify(pub, RegisterSigningPayload(pub, unique, ts), deregSig) {
		t.Error("Deregister sig should not satisfy Register verification")
	}
	// Proof sig (whose payload is just nonce-bytes) shouldn't satisfy either.
	proofSig := ed25519.Sign(priv, ProofSigningPayload([]byte("any 32 bytes here ........... abc")))
	if ed25519.Verify(pub, deregPayload, proofSig) {
		t.Error("Proof sig should not satisfy Deregister verification")
	}

	// Sanity: changing any field invalidates a Deregister sig.
	if ed25519.Verify(pub, DeregisterSigningPayload("abd", ts), deregSig) {
		t.Error("Deregister sig should not verify for a different unique")
	}
	if ed25519.Verify(pub, DeregisterSigningPayload(unique, ts+1), deregSig) {
		t.Error("Deregister sig should not verify for a different timestamp")
	}
}

func TestDeregisterOKRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, KindDeregisterOK, DeregisterOK{}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	f, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != KindDeregisterOK {
		t.Errorf("Type = %q, want %q", f.Type, KindDeregisterOK)
	}
	var out DeregisterOK
	if err := DecodePayload(f, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
}
