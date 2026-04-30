package tunnelclient

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsePortPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		spec        string
		wantErr     bool
		wantPermit  []int
		wantReject  []int
	}{
		"empty-deny-all": {
			spec:       "",
			wantPermit: nil,
			wantReject: []int{80, 443, 1977, 3000, 8080},
		},
		"all-allows-everything": {
			spec:       "all",
			wantPermit: []int{1, 22, 80, 443, 1977, 3000, 65535},
		},
		"all-case-insensitive": {
			spec:       "ALL",
			wantPermit: []int{22, 1977},
		},
		"single-port": {
			spec:       "1977",
			wantPermit: []int{1977},
			wantReject: []int{22, 1976, 1978, 3000},
		},
		"multiple-singles": {
			spec:       "1977,3000,8080",
			wantPermit: []int{1977, 3000, 8080},
			wantReject: []int{22, 80, 443, 5432, 6379},
		},
		"range": {
			spec:       "3000-3099",
			wantPermit: []int{3000, 3050, 3099},
			wantReject: []int{2999, 3100, 22, 8080},
		},
		"mixed": {
			spec:       "1977,3000-3099,8080",
			wantPermit: []int{1977, 3000, 3099, 8080},
			wantReject: []int{22, 1976, 3100, 8081},
		},
		"defaults-do-not-permit-dangerous-ports": {
			spec:       DefaultPortSpec,
			wantPermit: []int{1977, 3000, 4000, 8080},
			// SSH, Postgres, Redis, Docker daemon, MySQL, Mongo etc.
			// must NOT be in the default policy.
			wantReject: []int{22, 23, 25, 2375, 2376, 3306, 5432, 6379, 11211, 27017},
		},
		"whitespace-tolerant": {
			spec:       " 1977 , 3000 - 3099 ",
			wantPermit: []int{1977, 3000, 3099},
		},
		"reject-zero": {
			spec:    "0",
			wantErr: true,
		},
		"reject-negative": {
			spec:    "-1",
			wantErr: true,
		},
		"reject-too-large": {
			spec:    "65536",
			wantErr: true,
		},
		"reject-non-integer": {
			spec:    "abc",
			wantErr: true,
		},
		"reject-bad-range": {
			spec:    "100-50",
			wantErr: true,
		},
		"reject-malformed-range": {
			spec:    "100-",
			wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ParsePortPolicy(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePortPolicy(%q) = nil err, want error", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortPolicy(%q) err = %v", tc.spec, err)
			}
			for _, port := range tc.wantPermit {
				if !p.Permits(port) {
					t.Errorf("Permits(%d) = false; want true (spec=%q, policy=%s)", port, tc.spec, p.String())
				}
			}
			for _, port := range tc.wantReject {
				if p.Permits(port) {
					t.Errorf("Permits(%d) = true; want false (spec=%q, policy=%s)", port, tc.spec, p.String())
				}
			}
		})
	}
}

func TestParsePortPolicy_NilSafe(t *testing.T) {
	var p *PortPolicy
	if p.Permits(1977) {
		t.Error("nil policy must reject all ports")
	}
}

func TestParsePortPolicy_String(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		expect string
	}{
		{"all", "all ports (unrestricted)"},
		{"", "deny-all (empty policy)"},
	} {
		p, _ := ParsePortPolicy(tc.spec)
		if got := p.String(); got != tc.expect {
			t.Errorf("String() spec=%q got=%q want=%q", tc.spec, got, tc.expect)
		}
	}
	if (*PortPolicy)(nil).String() != "deny-all (nil policy)" {
		t.Error("nil String() mismatch")
	}
}

// TestPortDispatchHandler_RejectsDisallowedPort is the security test for
// finding #1: a port not in the allowlist must produce 404 BEFORE the
// upstream dial. We don't even need a backend; the handler must short-
// circuit.
func TestPortDispatchHandler_RejectsDisallowedPort(t *testing.T) {
	policy, err := ParsePortPolicy("1977,3000-3099")
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
	policy, err := ParsePortPolicy("3000-3099")
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
