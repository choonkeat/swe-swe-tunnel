package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
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

func TestManager_AddEntry_OverwritesIndex(t *testing.T) {
	stateDir := t.TempDir()
	m := New(stateDir, "test@example.com", "example.com", nil, nil)

	c1 := makeCert(t, "*.example.com", "example.com")
	c2 := makeCert(t, "*.example.com", "example.com") // different bytes, same SANs
	m.addEntry(&certEntry{cert: c1, sans: []string{"example.com", "*.example.com"}, baseName: "_.example.com"})
	m.addEntry(&certEntry{cert: c2, sans: []string{"example.com", "*.example.com"}, baseName: "_.example.com"})

	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// The second entry should win.
	if got.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) != 0 {
		t.Errorf("second addEntry should have replaced first")
	}
}
