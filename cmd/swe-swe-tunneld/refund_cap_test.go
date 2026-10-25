package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"

	"github.com/choonkeat/swe-swe-tunnel/internal/cert"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
)

func TestMayRefund(t *testing.T) {
	if !mayRefund(nil, "1.2.3.4") {
		t.Error("nil limiter: want refund")
	}
	if mayRefund(ratelimit.New(0, time.Hour), "1.2.3.4") {
		t.Error("disabled limiter (0): want no refund")
	}
	l := ratelimit.New(1, time.Hour)
	if !mayRefund(l, "1.2.3.4") || mayRefund(l, "1.2.3.4") {
		t.Error("limit 1: want first refund only")
	}
	if !mayRefund(l, "5.6.7.8") {
		t.Error("limit is per IP: other IP should still get a refund")
	}
}

// Permanent cert failures must burn the budget: retrying cannot
// succeed, so refunding would make each attempt free.
func TestHandleRegister_CertFail_PermanentNotRefunded(t *testing.T) {
	cases := []struct {
		name string
		err  error
		deny string
	}{
		{"no-acme not provisioned", errors.New("cert not provisioned for alpha-tunnel"), "cert not provisioned"},
		{"server order cap", fmt.Errorf("ensure: %w", cert.ErrOrderLimit), "cert issuance failed"},
		{"LE rate limited", fmt.Errorf("obtain: %w", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited"}), "cert issuance failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegHarness(t)
			h.ipLim = ratelimit.New(1, time.Hour)
			h.keyLim = ratelimit.New(1, 24*time.Hour)
			h.ensurer.err = tc.err
			h.start()

			_, priv := newKey(t)
			pub := priv.Public().(ed25519.PublicKey)
			h.sendRegister("alpha", priv, time.Now().Unix())
			expectDeny(t, h, tc.deny)

			if h.ipLim.RetryAfter("127.0.0.1") == 0 {
				t.Error("IP budget was refunded for a permanent failure")
			}
			if h.keyLim.RetryAfter(string(pub)) == 0 {
				t.Error("pubkey budget was refunded for a permanent failure")
			}
		})
	}
}

// Transient cert failures are refunded only up to the per-IP refund
// budget. Past it, attempts burn and the IP limit takes over.
func TestHandleRegister_CertFail_RefundCappedPerIP(t *testing.T) {
	ipLim := ratelimit.New(3, time.Hour)
	refundLim := ratelimit.New(2, time.Hour)

	attempt := func(unique string) {
		t.Helper()
		h := newRegHarness(t)
		h.ipLim = ipLim
		h.skewLim = refundLim
		h.ensurer.err = errors.New("dns flake")
		h.start()
		_, priv := newKey(t)
		h.sendRegister(unique, priv, time.Now().Unix())
		expectDeny(t, h, "cert issuance failed")
	}

	// 2 refunded + 3 burned = 5 attempts before the IP budget is gone.
	for i := 0; i < 5; i++ {
		attempt(fmt.Sprintf("name%d", i))
	}

	h := newRegHarness(t)
	h.ipLim = ipLim
	h.skewLim = refundLim
	h.start()
	_, priv := newKey(t)
	h.sendRegister("final", priv, time.Now().Unix())
	expectDeny(t, h, "rate_limited:ip")
}

// One budget covers every refund path: skew denies use it up, then a
// transient cert failure is not refunded.
func TestHandleRegister_RefundBudgetSharedWithSkew(t *testing.T) {
	ipLim := ratelimit.New(5, time.Hour)
	refundLim := ratelimit.New(1, time.Hour)

	h := newRegHarness(t)
	h.ipLim = ipLim
	h.skewLim = refundLim
	h.start()
	_, priv := newKey(t)
	h.sendRegister("alpha", priv, time.Now().Add(-time.Hour).Unix())
	expectDeny(t, h, "timestamp out of range")

	h = newRegHarness(t)
	h.ipLim = ipLim
	h.skewLim = refundLim
	h.ensurer.err = errors.New("dns flake")
	h.start()
	h.sendRegister("alpha", priv, time.Now().Unix())
	expectDeny(t, h, "cert issuance failed")

	// 2 attempts, 1 refunded → 1 sample left in the IP window.
	if got := countUsed(ipLim, "127.0.0.1", 5); got != 1 {
		t.Errorf("IP samples used = %d, want 1", got)
	}
}

// --register-rate-skew-deny-per-hour=0 is documented as "no refund".
func TestHandleRegister_RefundDisabledMeansNoRefund(t *testing.T) {
	h := newRegHarness(t)
	h.ipLim = ratelimit.New(1, time.Hour)
	h.skewLim = ratelimit.New(0, time.Hour)
	h.start()
	_, priv := newKey(t)
	h.sendRegister("alpha", priv, time.Now().Add(-time.Hour).Unix())
	expectDeny(t, h, "timestamp out of range")
	if h.ipLim.RetryAfter("127.0.0.1") == 0 {
		t.Error("refund happened with the refund budget set to 0")
	}
}

// countUsed reports how many of max slots key has used, by probing
// with Allow and undoing each probe.
func countUsed(l *ratelimit.SlidingWindow, key string, max int) int {
	free := 0
	for l.Allow(key) {
		free++
	}
	for i := 0; i < free; i++ {
		l.CancelLatest(key)
	}
	return max - free
}

// End to end over TLS + yamux: an attacker looping Register for new
// names while issuance keeps failing gets rate_limited:ip once the
// refund budget and the IP budget are spent. Before the fix every
// attempt was refunded and the loop never stopped.
func TestE2E_CertFailureLoop_EscalatesToRateLimit(t *testing.T) {
	apex := "tunnel.test"
	store, err := identity.Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ipLim := ratelimit.New(3, time.Hour)
	keyLim := ratelimit.New(0, 24*time.Hour)
	refundLim := ratelimit.New(2, time.Hour)
	ensurer := &fakeEnsurer{err: errors.New("dns flake")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mux := http.NewServeMux()
	mux.Handle("/v1/connect", connectHandler(newRegistry(), store, ensurer, apex, ipLim, keyLim, refundLim, nil, logger))
	tunneld := httptest.NewTLSServer(mux)
	defer tunneld.Close()

	roots := x509.NewCertPool()
	roots.AddCert(tunneld.Certificate())
	tlsCfg := &tls.Config{RootCAs: roots, ServerName: mustURL(t, tunneld.URL).Hostname(), MinVersion: tls.VersionTLS12}
	host := mustURL(t, tunneld.URL).Host

	var reasons []string
	for i := 0; i < 6; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		reasons = append(reasons, sendStaleRegister(t, host, tlsCfg, fmt.Sprintf("name%d", i), pub, priv, time.Now().Unix()))
	}
	for i := 0; i < 5; i++ {
		if reasons[i] != "cert issuance failed" {
			t.Fatalf("attempt %d: %q, want 'cert issuance failed' (all: %v)", i+1, reasons[i], reasons)
		}
	}
	if reasons[5] != "rate_limited:ip" {
		t.Fatalf("attempt 6: %q, want rate_limited:ip (all: %v)", reasons[5], reasons)
	}
	if got := len(ensurer.Calls()); got != 5 {
		t.Errorf("EnsureName called %d times, want 5", got)
	}
}
