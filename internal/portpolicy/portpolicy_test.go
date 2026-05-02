package portpolicy

import (
	"testing"
)

func TestParse(t *testing.T) {
	for name, tc := range map[string]struct {
		spec       string
		wantErr    bool
		wantPermit []int
		wantReject []int
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
		"defaults-include-9898-and-not-dangerous-ports": {
			spec:       DefaultSpec,
			wantPermit: []int{1977, 3000, 4000, 8080, 9898},
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
			p, err := Parse(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = nil err, want error", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) err = %v", tc.spec, err)
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

func TestParse_NilSafe(t *testing.T) {
	var p *PortPolicy
	if p.Permits(1977) {
		t.Error("nil policy must reject all ports")
	}
}

func TestParse_String(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		expect string
	}{
		{"all", "all ports (unrestricted)"},
		{"", "deny-all (empty policy)"},
	} {
		p, _ := Parse(tc.spec)
		if got := p.String(); got != tc.expect {
			t.Errorf("String() spec=%q got=%q want=%q", tc.spec, got, tc.expect)
		}
	}
	if (*PortPolicy)(nil).String() != "deny-all (nil policy)" {
		t.Error("nil String() mismatch")
	}
}
