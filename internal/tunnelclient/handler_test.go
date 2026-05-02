package tunnelclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPortDispatchHandler_RoutesByLeftmostLabel(t *testing.T) {
	// Two backends; the handler should pick the right one based on the
	// leftmost label of the request's Host (which doubles as the port).
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-1"))
	}))
	defer upstream1.Close()
	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("upstream-2"))
	}))
	defer upstream2.Close()

	u1, _ := url.Parse(upstream1.URL)
	u2, _ := url.Parse(upstream2.URL)
	port1 := u1.Port()
	port2 := u2.Port()

	// PortDispatchHandler builds {target}:{port}. Use 127.0.0.1 as target.
	h := PortDispatchHandler("127.0.0.1", discardLogger())

	for name, tc := range map[string]struct {
		host       string
		wantStatus int
		wantBody   string
	}{
		"port1": {
			host:       port1 + ".alpha-tunnel.example.com",
			wantStatus: 200,
			wantBody:   "upstream-1",
		},
		"port2": {
			host:       port2 + ".alpha-tunnel.example.com",
			wantStatus: 200,
			wantBody:   "upstream-2",
		},
		"missing-port-label": {
			host:       "alpha-tunnel.example.com",
			wantStatus: 400,
		},
		"non-numeric-port": {
			host:       "abc.alpha-tunnel.example.com",
			wantStatus: 400,
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantBody != "" {
				body, _ := io.ReadAll(rec.Body)
				if !strings.Contains(string(body), tc.wantBody) {
					t.Errorf("body = %q, want to contain %q", string(body), tc.wantBody)
				}
			}
		})
	}
}

func TestPortDispatchHandler_PreservesXForwarded(t *testing.T) {
	got := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	port := mustParseURL(t, upstream.URL).Port()
	h := PortDispatchHandler("127.0.0.1", discardLogger())

	req := httptest.NewRequest("GET", "http://"+port+".alpha-tunnel.example.com/", nil)
	req.Host = port + ".alpha-tunnel.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", port+".alpha-tunnel.example.com")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}

	hdr := <-got
	if hdr.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("X-Forwarded-Proto upstream = %q, want https", hdr.Get("X-Forwarded-Proto"))
	}
	if hdr.Get("X-Forwarded-Host") == "" {
		t.Errorf("X-Forwarded-Host should be propagated")
	}
	if hdr.Get("X-Forwarded-For") != "203.0.113.7" {
		t.Errorf("X-Forwarded-For = %q, want 203.0.113.7", hdr.Get("X-Forwarded-For"))
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestPortDispatchHandler_RejectsMalformedHost covers the only
// rejections the client still owns after the server-side port
// allowlist landed (commit 3 of the port-allowlist task): host
// must carry a numeric leftmost label, otherwise we can't form a
// {target}:{port} dial address. Returns 400 (bad request from the
// caller) rather than 404 (gate decision) so it's distinguishable
// from a server-side "port not allowed" deny.
func TestPortDispatchHandler_RejectsMalformedHost(t *testing.T) {
	h := PortDispatchHandler("127.0.0.1", discardLogger())
	cases := map[string]struct {
		host       string
		wantStatus int
		wantBody   string
	}{
		"single-label-host-no-port": {
			// portFromHost returns "" on a single-label host (no dot
			// → no leftmost label to peel off).
			host:       "localhost",
			wantStatus: http.StatusBadRequest,
			wantBody:   "missing port label",
		},
		"non-numeric-port-label": {
			host:       "www.alpha-tunnel.example.com",
			wantStatus: http.StatusBadRequest,
			wantBody:   "non-numeric port label",
		},
		"multi-label-no-numeric-prefix": {
			host:       "alpha-tunnel.example.com",
			wantStatus: http.StatusBadRequest,
			wantBody:   "non-numeric port label",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tc.host+"/", nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}
