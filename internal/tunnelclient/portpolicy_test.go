package tunnelclient

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
)

// TestPortDispatchHandler_RejectsDisallowedPort is the security test for
// finding #1: a port not in the allowlist must produce 404 BEFORE the
// upstream dial. We don't even need a backend; the handler must short-
// circuit.
func TestPortDispatchHandler_RejectsDisallowedPort(t *testing.T) {
	policy, err := portpolicy.Parse("1977,3000-3099")
	if err != nil {
		t.Fatal(err)
	}

	h := PortDispatchHandler("127.0.0.1", policy, discardLogger())

	for _, port := range []string{"22", "5432", "6379", "2375", "27017"} {
		t.Run("port="+port, func(t *testing.T) {
			host := port + ".alpha-tunnel.example.com"
			req := httptest.NewRequest("GET", "http://"+host+"/", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != 404 {
				t.Errorf("port %s: status = %d, want 404", port, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "port not allowed") {
				t.Errorf("port %s: body = %q, want 'port not allowed'", port, rec.Body.String())
			}
		})
	}
}

// TestPortDispatchHandler_PermitsAllowedPort verifies the gate doesn't
// over-block: a port inside the allowlist proceeds to the upstream
// dial. We don't need to assert success — only that we get past the
// 404 check (the request will fail at dial because no backend listens,
// which produces 502).
func TestPortDispatchHandler_PermitsAllowedPort(t *testing.T) {
	policy, err := portpolicy.Parse("3000-3099")
	if err != nil {
		t.Fatal(err)
	}

	h := PortDispatchHandler("127.0.0.1", policy, discardLogger())

	host := "3050.alpha-tunnel.example.com"
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 404 {
		t.Errorf("allowed port 3050 returned 404; want pass-through to upstream (502 ok)")
	}
}

// TestPortDispatchHandler_NilPolicyDeniesAll ensures we fail closed
// when no policy is supplied — a buggy caller forgetting to pass one
// must NOT result in unrestricted forwarding.
func TestPortDispatchHandler_NilPolicyDeniesAll(t *testing.T) {
	h := PortDispatchHandler("127.0.0.1", nil, discardLogger())
	host := "3000.alpha-tunnel.example.com"
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("nil policy: status = %d, want 404 (fail closed)", rec.Code)
	}
}
