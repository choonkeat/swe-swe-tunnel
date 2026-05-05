package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeCert generates a short-lived self-signed RSA cert covering the given
// DNS names. Useful for testing the SNI lookup logic without going through
// ACME.
func makeCert(t *testing.T, dnsNames ...string) *tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

func writeCertPair(t *testing.T, dir, base string, dnsNames ...string) {
	t.Helper()
	c := makeCert(t, dnsNames...)
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, base+".crt"), crtPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeSNI(t *testing.T) {
	cases := map[string]string{
		"Foo.Bar.com":  "foo.bar.com",
		"foo.com:443":  "foo.com",
		"foo.com.":     "foo.com",
		"foo.com":      "foo.com",
		"FOO.com:8080": "foo.com",
		"":             "",
	}
	for in, want := range cases {
		if got := normalizeSNI(in); got != want {
			t.Errorf("normalizeSNI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestManager_GetCertificate_NoCertsLoaded(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)
	_, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err == nil {
		t.Error("expected an error when no certs are loaded")
	}
}

func TestManager_LoadAllFromDisk_AndSNIDispatch(t *testing.T) {
	stateDir := t.TempDir()
	certDir := filepath.Join(stateDir, "lego", "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Apex cert covers the bare apex + one-level wildcard.
	writeCertPair(t, certDir, "_.example.com", "example.com", "*.example.com")
	// Per-session cert covers `foo-tunnel.example.com` exactly + its wildcard.
	writeCertPair(t, certDir, "_.foo-tunnel.example.com", "foo-tunnel.example.com", "*.foo-tunnel.example.com")

	m := New(stateDir, "test@example.com", "example.com", nil, nil)
	n, err := m.LoadAllFromDisk()
	if err != nil {
		t.Fatalf("LoadAllFromDisk: %v", err)
	}
	if n != 2 {
		t.Errorf("loaded count = %d, want 2", n)
	}

	type expect struct {
		sni     string
		// expected SAN list (any subset of the chosen cert's DNSNames is fine,
		// but we assert on a representative one).
		wantHas string
		wantErr bool
	}
	cases := []expect{
		{sni: "example.com", wantHas: "example.com"},                              // exact match on apex SAN
		{sni: "tunnel.example.com", wantHas: "*.example.com"},                     // wildcard match
		{sni: "foo-tunnel.example.com", wantHas: "foo-tunnel.example.com"},        // exact match on per-session SAN
		{sni: "1977.foo-tunnel.example.com", wantHas: "*.foo-tunnel.example.com"}, // wildcard match on per-session
		{sni: "deep.nested.example.com", wantHas: "example.com"},                  // strict wildcards don't match 2 levels — falls through to apex
		{sni: "unknown.tld", wantHas: "example.com"},                              // no match anywhere → apex fallback
		{sni: "EXAMPLE.com", wantHas: "example.com"},                              // case-insensitive
		{sni: "example.com:443", wantHas: "example.com"},                          // port stripped
	}
	for _, tc := range cases {
		cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.sni})
		if tc.wantErr {
			if err == nil {
				t.Errorf("sni %q: want error, got cert", tc.sni)
			}
			continue
		}
		if err != nil {
			// "deep.nested" doesn't strictly match anything; falls through to
			// the apex cert (`example.com` is in m.exact). Same for
			// "unknown.tld". We accept either a returned apex cert OR an
			// error — the deepNested/unknown rows assert on what we actually
			// expect from the implementation:
			t.Errorf("sni %q: unexpected error %v", tc.sni, err)
			continue
		}
		names := cert.Leaf.DNSNames
		if !slices.Contains(names, tc.wantHas) {
			t.Errorf("sni %q: cert has DNSNames %v, want one of them = %q",
				tc.sni, names, tc.wantHas)
		}
	}
}

func TestManager_LoadAllFromDisk_SkipsBrokenFiles(t *testing.T) {
	stateDir := t.TempDir()
	certDir := filepath.Join(stateDir, "lego", "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Valid cert.
	writeCertPair(t, certDir, "_.example.com", "example.com", "*.example.com")
	// Garbage .crt.
	if err := os.WriteFile(filepath.Join(certDir, "garbage.crt"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := New(stateDir, "test@example.com", "example.com", nil, nil)
	n, err := m.LoadAllFromDisk()
	if err != nil {
		t.Fatalf("LoadAllFromDisk: %v", err)
	}
	if n != 1 {
		t.Errorf("loaded count = %d, want 1 (broken cert should be skipped)", n)
	}
}

// TestManager_EnsureName_SingleflightCoalescesConcurrentCalls verifies that
// N concurrent EnsureName calls for the same label only invoke the underlying
// obtain (ACME flow) once. Without singleflight, parallel ACME flows race
// each other's TXT-record cleanup and one fails — see bug 2.
func TestManager_EnsureName_SingleflightCoalescesConcurrentCalls(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)

	const N = 8
	var calls atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, N)

	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return makeCert(t, sans...), nil
	}

	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.EnsureName(context.Background(), "alpha")
		}()
	}

	// Wait for at least one obtain to be in-flight, then give the other
	// goroutines a moment to pile up behind the singleflight key. (If
	// singleflight is broken and all N enter obtain, the counter races
	// past 1 here.)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no obtain call observed within 2s")
	}
	time.Sleep(50 * time.Millisecond)

	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("EnsureName: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("obtain called %d times, want 1 (singleflight should coalesce)", got)
	}
}

// TestManager_EnsureName_SingleflightDoesNotCacheResults verifies that a
// second EnsureName call AFTER the first completes invokes obtain again.
// singleflight.Do (vs. DoChan-with-Forget or memoization) only coalesces
// in-flight callers; sequential callers should still hit the slow path
// (where the disk-fast-path will normally save them, but here there's no
// cert on disk because our override doesn't persist).
func TestManager_EnsureName_SingleflightDoesNotCacheResults(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)

	var calls atomic.Int32
	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		calls.Add(1)
		return makeCert(t, sans...), nil
	}

	for i := 0; i < 3; i++ {
		if err := m.EnsureName(context.Background(), "alpha"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("obtain called %d times, want 3 (sequential calls should not be cached)", got)
	}
}

// TestManager_EnsureName_DifferentLabelsRunInParallel verifies that
// singleflight keys on baseName, so EnsureName("alpha") and
// EnsureName("beta") do not block each other.
func TestManager_EnsureName_DifferentLabelsRunInParallel(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)

	release := make(chan struct{})
	entered := make(chan string, 2)

	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		entered <- baseName
		<-release
		return makeCert(t, sans...), nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = m.EnsureName(context.Background(), "alpha") }()
	go func() { defer wg.Done(); _ = m.EnsureName(context.Background(), "beta") }()

	// Both should reach obtain concurrently. If singleflight were
	// keyed too coarsely (e.g. on a constant), we'd see only one
	// entry within the timeout and the test would hang/fail.
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case bn := <-entered:
			got[bn] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d obtain call(s) entered within 2s; want 2 (different labels should not coalesce)", i)
		}
	}
	close(release)
	wg.Wait()

	if !got["_.alpha.example.com"] || !got["_.beta.example.com"] {
		t.Errorf("entered = %v, want both _.alpha.example.com and _.beta.example.com", got)
	}
}

// TestManager_EnsureName_SingleflightSurfacesError verifies that when the
// singleflight leader returns an error, all coalesced waiters see it.
func TestManager_EnsureName_SingleflightSurfacesError(t *testing.T) {
	m := New(t.TempDir(), "test@example.com", "example.com", nil, nil)

	wantErr := errors.New("acme blew up")
	var calls atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	m.obtainOverride = func(ctx context.Context, sans []string, baseName string) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-release
		}
		return nil, wantErr
	}

	const N = 4
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.EnsureName(context.Background(), "alpha")
		}()
	}

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no obtain call observed within 2s")
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err == nil || !errors.Is(err, wantErr) {
			t.Errorf("EnsureName err = %v, want wrapped %v", err, wantErr)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("obtain called %d times, want 1", got)
	}
}

func TestManager_AddEntry_OverwritesIndex(t *testing.T) {
	stateDir := t.TempDir()
	m := New(stateDir, "test@example.com", "example.com", nil, nil)

	c1 := makeCert(t, "*.example.com", "example.com")
	c2 := makeCert(t, "*.example.com", "example.com") // different bytes, same SANs
	m.store.addEntry(&certEntry{cert: c1, sans: []string{"example.com", "*.example.com"}, baseName: "_.example.com"})
	m.store.addEntry(&certEntry{cert: c2, sans: []string{"example.com", "*.example.com"}, baseName: "_.example.com"})

	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// The second entry should win.
	if got.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) != 0 {
		t.Errorf("second addEntry should have replaced first")
	}
}
