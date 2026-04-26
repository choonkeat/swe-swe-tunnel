package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	h := route(reg, "example.com", fallback)

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
	h := route(reg, "example.com", fallback)

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
