package cert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/go-acme/lego/v4/acme"
)

func TestIsPermanent(t *testing.T) {
	rl := &acme.ProblemDetails{Type: acmeRateLimited, Detail: "too many certificates"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transient", errors.New("dns propagation timeout"), false},
		{"order limit", fmt.Errorf("ensure: %w", ErrOrderLimit), true},
		{"LE rate limited (typed)", fmt.Errorf("obtain cert: obtain: %w", rl), true},
		{"LE rate limited (joined text)", errors.New("alpha: acme: error: 429 :: POST :: " + acmeRateLimited + " :: too many"), true},
		{"other ACME problem", fmt.Errorf("obtain: %w", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:dns"}), false},
		{"no-acme not provisioned", errors.New("cert not provisioned for alpha-tunnel"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPermanent(tc.err); got != tc.want {
				t.Errorf("IsPermanent(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestManager_OrderLimit_HourlyCap(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)
	m.SetOrderLimit(2, 0)
	var calls atomic.Int32
	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("dns flake") // failed orders still count
	}
	for _, label := range []string{"a-tunnel", "b-tunnel"} {
		if err := m.EnsureName(context.Background(), label); err == nil || errors.Is(err, ErrOrderLimit) {
			t.Fatalf("%s: err = %v, want the obtain error", label, err)
		}
	}
	if err := m.EnsureName(context.Background(), "c-tunnel"); !errors.Is(err, ErrOrderLimit) {
		t.Fatalf("3rd distinct name: err = %v, want ErrOrderLimit", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("obtain called %d times, want 2 (3rd must not reach ACME)", got)
	}
}

func TestManager_OrderLimit_Concurrent(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)
	m.SetOrderLimit(0, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		close(entered)
		<-release
		return makeCert(t, sans...), nil
	}
	done := make(chan error, 1)
	go func() { done <- m.EnsureName(context.Background(), "a-tunnel") }()
	<-entered

	// A different name while the slot is busy fails fast.
	if err := m.EnsureName(context.Background(), "b-tunnel"); !errors.Is(err, ErrOrderLimit) {
		t.Fatalf("while busy: err = %v, want ErrOrderLimit", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first order: %v", err)
	}
}

func TestManager_OrderLimit_CachedCertDoesNotCount(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)
	m.SetOrderLimit(1, 0)
	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		writeCertPair(t, m.certDir(), baseName, sans...)
		return makeCert(t, sans...), nil
	}
	if err := m.EnsureName(context.Background(), "a-tunnel"); err != nil {
		t.Fatal(err)
	}
	// Same name again is served from disk and must not hit the cap.
	for i := 0; i < 3; i++ {
		if err := m.EnsureName(context.Background(), "a-tunnel"); err != nil {
			t.Fatalf("cached call %d: %v", i, err)
		}
	}
}
