package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
)

// TestRoute_Fallback covers hosts that should fall through to the apex hello
// handler: the apex itself, single-label hosts, hosts whose session label
// doesn't end in "-tunnel", and unrelated hostnames.
func TestRoute_Fallback(t *testing.T) {
	reg := newRegistry()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("fallback"))
	})
	h := route(reg, "example.com", nil, nil, fallback)

	hosts := []string{
		"example.com",
		"example.com:443",
		"register.example.com",         // no -tunnel suffix on session label
		"abc.register.example.com",     // session label "register" not -tunnel
		"abc-tunnel.example.com",       // no port label (single label rest)
		"www.example.com",             // not the apex
	}
	for _, host := range hosts {
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != "fallback" {
			t.Errorf("host %q: expected fallback, got %q (status %d)", host, got, rec.Code)
		}
	}
}

// TestRoute_TunnelOffline confirms a registered-shaped host with no live
// session returns the 502 offline page.
func TestRoute_TunnelOffline(t *testing.T) {
	reg := newRegistry()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("fallback should not run")
	})
	h := route(reg, "example.com", nil, nil, fallback)

	req := httptest.NewRequest("GET", "http://1977.test-tunnel.example.com/", nil)
	req.Host = "1977.test-tunnel.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Tunnel offline") {
		t.Errorf("expected 'Tunnel offline' in body, got %q", rec.Body.String())
	}
}

// TestRoute_PortAllowlistGate covers the server-side port-policy gate
// added per tasks/2026-05-02-server-side-port-allowlist.md. The gate
// runs BEFORE the registry lookup, so a denied request never even
// looks for a session — this is what stops the tunnel client from
// having to repeat the policy.
func TestRoute_PortAllowlistGate(t *testing.T) {
	reg := newRegistry()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("fallback should not run for {port}.{label}-tunnel.{apex} hosts")
	})
	ports, err := portpolicy.LoadInline("1977,9898", "test")
	if err != nil {
		t.Fatal(err)
	}
	h := route(reg, "example.com", ports, nil, fallback)

	cases := map[string]struct {
		host       string
		wantStatus int
		wantBody   string // substring
	}{
		"in-policy-but-no-session": {
			host:       "9898.test-tunnel.example.com",
			wantStatus: http.StatusBadGateway, // tunnelOffline
			wantBody:   "Tunnel offline",
		},
		"out-of-policy-port": {
			host:       "22.test-tunnel.example.com",
			wantStatus: http.StatusNotFound,
			wantBody:   "port not allowed",
		},
		"non-numeric-port-label": {
			host:       "www.test-tunnel.example.com",
			wantStatus: http.StatusNotFound,
			wantBody:   "port not allowed",
		},
		"port-zero-rejected": {
			host:       "0.test-tunnel.example.com",
			wantStatus: http.StatusNotFound,
			wantBody:   "port not allowed",
		},
		"port-out-of-range-rejected": {
			host:       "65536.test-tunnel.example.com",
			wantStatus: http.StatusNotFound,
			wantBody:   "port not allowed",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestRoute_NilPortsDisablesGate documents the nil-ports semantics:
// a route() built with ports=nil is permissive (used by tests that
// don't care about the port gate). Production main.go never passes
// nil — it always builds a portpolicy.Set.
func TestRoute_NilPortsDisablesGate(t *testing.T) {
	reg := newRegistry()
	fallback := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("fallback should not run")
	})
	h := route(reg, "example.com", nil, nil, fallback)

	// Port 22 would normally be denied; with nil ports it falls
	// through to the registry lookup (and then tunnelOffline since
	// no session is registered).
	req := httptest.NewRequest("GET", "http://22.test-tunnel.example.com/", nil)
	req.Host = "22.test-tunnel.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("nil ports + no session: status = %d, want 502 (offline)", rec.Code)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Foo.Bar.com":     "foo.bar.com",
		"foo.com:443":     "foo.com",
		"foo.com.":        "foo.com",
		"foo.com":         "foo.com",
		"FOO.com:8080":    "foo.com",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
