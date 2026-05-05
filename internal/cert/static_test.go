package cert

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newTestStaticLoader(t *testing.T) (*StaticLoader, string) {
	t.Helper()
	stateDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sl := NewStaticLoader(stateDir, "example.com", logger)
	return sl, filepath.Join(stateDir, "lego", "certificates")
}

func TestStaticLoader_LoadAllFromDisk_PopulatesSNI(t *testing.T) {
	sl, certDir := newTestStaticLoader(t)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCertPair(t, certDir, "_.example.com", "example.com", "*.example.com")
	writeCertPair(t, certDir, "_.foo-tunnel.example.com",
		"foo-tunnel.example.com", "*.foo-tunnel.example.com")

	n, err := sl.LoadAllFromDisk()
	if err != nil {
		t.Fatalf("LoadAllFromDisk: %v", err)
	}
	if n != 2 {
		t.Errorf("loaded count = %d, want 2", n)
	}

	cases := []struct {
		sni     string
		wantHas string
	}{
		{"example.com", "example.com"},
		{"tunnel.example.com", "*.example.com"},
		{"foo-tunnel.example.com", "foo-tunnel.example.com"},
		{"1977.foo-tunnel.example.com", "*.foo-tunnel.example.com"},
		{"unknown.tld", "example.com"}, // apex fallback
	}
	for _, tc := range cases {
		cert, err := sl.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.sni})
		if err != nil {
			t.Errorf("sni %q: %v", tc.sni, err)
			continue
		}
		if !slices.Contains(cert.Leaf.DNSNames, tc.wantHas) {
			t.Errorf("sni %q: cert SANs %v want one to be %q",
				tc.sni, cert.Leaf.DNSNames, tc.wantHas)
		}
	}
}

func TestStaticLoader_EnsureName_MissingReturnsClearError(t *testing.T) {
	sl, _ := newTestStaticLoader(t)
	err := sl.EnsureName(context.Background(), "alpha")
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
	want := "cert not provisioned for alpha"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to contain %q", err.Error(), want)
	}
}

func TestStaticLoader_EnsureName_EmptyLabelRejected(t *testing.T) {
	sl, _ := newTestStaticLoader(t)
	err := sl.EnsureName(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty label")
	}
}

func TestStaticLoader_EnsureName_NoOpWhenAlreadyLoaded(t *testing.T) {
	sl, certDir := newTestStaticLoader(t)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCertPair(t, certDir, "_.alpha.example.com",
		"alpha.example.com", "*.alpha.example.com")
	if _, err := sl.LoadAllFromDisk(); err != nil {
		t.Fatal(err)
	}
	if err := sl.EnsureName(context.Background(), "alpha"); err != nil {
		t.Errorf("EnsureName for already-loaded label: %v", err)
	}
}

func TestStaticLoader_EnsureName_LastChanceDiskRead(t *testing.T) {
	// LoadAllFromDisk has not been called; a cert lands on disk after
	// boot but before any SIGHUP. EnsureName should still pick it up.
	sl, certDir := newTestStaticLoader(t)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCertPair(t, certDir, "_.beta.example.com",
		"beta.example.com", "*.beta.example.com")

	if err := sl.EnsureName(context.Background(), "beta"); err != nil {
		t.Fatalf("EnsureName(beta): %v", err)
	}

	cert, err := sl.GetCertificate(&tls.ClientHelloInfo{ServerName: "1977.beta.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate after on-demand load: %v", err)
	}
	if !slices.Contains(cert.Leaf.DNSNames, "*.beta.example.com") {
		t.Errorf("cert SANs %v missing *.beta.example.com", cert.Leaf.DNSNames)
	}
}

func TestStaticLoader_LoadAllFromDisk_ReloadRefreshes(t *testing.T) {
	// SIGHUP semantics: dropping a fresh file on disk and re-running
	// LoadAllFromDisk should publish the new cert via GetCertificate.
	sl, certDir := newTestStaticLoader(t)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCertPair(t, certDir, "_.gamma.example.com",
		"gamma.example.com", "*.gamma.example.com")
	if _, err := sl.LoadAllFromDisk(); err != nil {
		t.Fatal(err)
	}
	first, err := sl.GetCertificate(&tls.ClientHelloInfo{ServerName: "gamma.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite the pair with a new cert.
	writeCertPair(t, certDir, "_.gamma.example.com",
		"gamma.example.com", "*.gamma.example.com")
	if _, err := sl.LoadAllFromDisk(); err != nil {
		t.Fatal(err)
	}
	second, err := sl.GetCertificate(&tls.ClientHelloInfo{ServerName: "gamma.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// Each makeCert call generates a fresh random key, so the raw DER
	// bytes differ even though the SAN list and serial are the same.
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Errorf("cert was not refreshed after disk overwrite + LoadAllFromDisk")
	}
}

func TestStaticLoader_GetCertificate_NoCertsLoadedReturnsError(t *testing.T) {
	sl, _ := newTestStaticLoader(t)
	_, err := sl.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err == nil {
		t.Error("expected error when no certs are loaded")
	}
}

func TestStaticLoader_LoadAllFromDisk_SkipsBrokenFiles(t *testing.T) {
	sl, certDir := newTestStaticLoader(t)
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCertPair(t, certDir, "_.example.com", "example.com", "*.example.com")
	if err := os.WriteFile(filepath.Join(certDir, "garbage.crt"),
		[]byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := sl.LoadAllFromDisk()
	if err != nil {
		t.Fatalf("LoadAllFromDisk: %v", err)
	}
	if n != 1 {
		t.Errorf("loaded count = %d, want 1", n)
	}
}
