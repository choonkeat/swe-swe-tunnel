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
