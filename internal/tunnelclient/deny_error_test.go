package tunnelclient

import (
	"errors"
	"fmt"
	"testing"
)

func TestDenyError_Error_WithOp(t *testing.T) {
	got := (&DenyError{Reason: "rate_limited:ip", Op: "register"}).Error()
	want := "server denied register: rate_limited:ip"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestDenyError_Error_WithoutOp(t *testing.T) {
	got := (&DenyError{Reason: "bad pubkey"}).Error()
	want := "server denied: bad pubkey"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestDenyError_IsRateLimit(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		{"rate_limited:ip", true},
		{"rate_limited:pubkey", true},
		{"rate_limited:foo", true}, // future-proof: any rate_limited:* prefix
		{"bad pubkey", false},
		{"", false},
		{"signature invalid", false},
	}
	for _, tc := range cases {
		if got := (&DenyError{Reason: tc.reason}).IsRateLimit(); got != tc.want {
			t.Errorf("IsRateLimit(%q) = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

func TestDenyError_IsPermanent(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		// Permanent — these reflect a misconfigured client; retrying won't help.
		{"bad pubkey", true},
		{"bad sig", true},
		{"key_mismatch", true},
		{"unique mismatch", true},
		{"signature invalid", true},
		{"bad register payload", true},
		{"bad deregister payload", true},
		{"bad proof payload", true},
		{"bad proof sig", true},
		{"unsupported protocol version 999", true},
		{"invalid unique \"X.Y\": must match ^[a-z]...", true},
		{"expected register, got \"foo\"", true},
		{"cert not provisioned", true},                  // --no-acme; operator owns issuance
		{"cert not provisioned for alpha-tunnel", true}, // tolerate label suffix too

		// Transient — should retry (or rate-limit, handled separately).
		{"rate_limited:ip", false},
		{"rate_limited:pubkey", false},
		{"timestamp out of range", false}, // clock skew may resolve
		{"cert issuance failed", false},   // server-side LE outage
		{"store error", false},            // server-side DB issue
		{"internal error", false},         // server-side bug
		{"", false},
	}
	for _, tc := range cases {
		if got := (&DenyError{Reason: tc.reason}).IsPermanent(); got != tc.want {
			t.Errorf("IsPermanent(%q) = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

// errors.As must be able to unwrap a DenyError through fmt.Errorf("%w") —
// this is the path the run loop uses to inspect Connect's return value
// (Connect wraps registerWithServer's error with "register: %w").
func TestDenyError_UnwrappableViaErrorsAs(t *testing.T) {
	inner := &DenyError{Reason: "rate_limited:ip", Op: "register"}
	wrapped := fmt.Errorf("register: %w", inner)

	var de *DenyError
	if !errors.As(wrapped, &de) {
		t.Fatal("errors.As did not unwrap *DenyError from fmt.Errorf %w chain")
	}
	if de.Reason != "rate_limited:ip" || de.Op != "register" {
		t.Errorf("unwrapped DenyError = %+v, want Reason=rate_limited:ip Op=register", de)
	}
}
