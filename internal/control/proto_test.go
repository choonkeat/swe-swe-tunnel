package control

import (
	"bytes"
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
		"ab",                      // too short
		"-abc",                    // leading hyphen
		"abc-",                    // trailing hyphen
		"Abc",                     // uppercase
		"abc.def",                 // dot
		"abc/def",                 // slash
		strings.Repeat("a", 55),   // too long
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
	in := ClientHello{Version: 1, Unique: "abc"}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var out ClientHello
	if err := ReadFrame(&buf, &out); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if out != in {
		t.Errorf("round-trip: got %+v, want %+v", out, in)
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	// length header for 1 GiB
	hdr := []byte{0x40, 0x00, 0x00, 0x00}
	var v any
	err := ReadFrame(bytes.NewReader(hdr), &v)
	if err == nil || !strings.Contains(err.Error(), "frame too large") {
		t.Errorf("expected frame-too-large, got %v", err)
	}
}
