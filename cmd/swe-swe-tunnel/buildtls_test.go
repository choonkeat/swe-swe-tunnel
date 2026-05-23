package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBuildTLSConfig_None: with no --client-cert and no --insecure,
// buildTLSConfig returns (nil, nil) so the dial uses Go's default
// tls config and the server's normal cert verifies against the
// system trust store. This is the unchanged-default path.
func TestBuildTLSConfig_None(t *testing.T) {
	cfg, err := buildTLSConfig("", "", false)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("cfg = %+v, want nil", cfg)
	}
}

// TestBuildTLSConfig_InsecureOnly: --insecure without --client-cert
// returns a config with InsecureSkipVerify=true and no client
// certificates. Preserves today's --insecure-only behaviour.
func TestBuildTLSConfig_InsecureOnly(t *testing.T) {
	cfg, err := buildTLSConfig("", "", true)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg = nil, want non-nil")
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("Certificates len = %d, want 0", len(cfg.Certificates))
	}
}

// TestBuildTLSConfig_MTLS_PairsCertAndIdentityKey is the agent-mTLS
// flow contract: --client-cert + --identity-key produce a
// tls.Certificate that pairs the cert with the existing identity
// private key. The agent's identity.key is reused as the TLS key
// (RFC 8410 / Ed25519 X.509). No --client-key flag exists.
func TestBuildTLSConfig_MTLS_PairsCertAndIdentityKey(t *testing.T) {
	dir := t.TempDir()
	// Generate keypair + cert that lives entirely in this test.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPath := writeSelfSignedCert(t, dir, "agent-01", pub, priv)
	keyPath := writeIdentityKey(t, dir, priv)

	cfg, err := buildTLSConfig(certPath, keyPath, false)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg = nil, want non-nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false (mTLS does not imply insecure)")
	}
}

// TestBuildTLSConfig_KeyMismatchFailsFast covers the operator
// misconfiguration where --client-cert and --identity-key are
// drawn from different keypairs: tls.X509KeyPair rejects, and the
// caller bubbles a clear error rather than booting a useless agent
// that will fail every TLS handshake.
func TestBuildTLSConfig_KeyMismatchFailsFast(t *testing.T) {
	dir := t.TempDir()
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	// Cert is for pubA, but the agent's "identity key" is privB.
	certPath := writeSelfSignedCert(t, dir, "agent-01", pubA, privA)
	keyPath := writeIdentityKey(t, dir, privB)

	_, err := buildTLSConfig(certPath, keyPath, false)
	if err == nil {
		t.Fatal("buildTLSConfig: expected error on cert/key mismatch")
	}
}

// TestBuildTLSConfig_MissingCertFile bubbles the I/O error instead of
// returning a silently empty config that would later mystery-fail at
// dial time.
func TestBuildTLSConfig_MissingCertFile(t *testing.T) {
	if _, err := buildTLSConfig("/does/not/exist.pem", "/also/missing", false); err == nil {
		t.Fatal("buildTLSConfig: expected error on missing files")
	}
}

// writeSelfSignedCert produces a tiny self-signed Ed25519 cert just
// for unit-testing the keypair-loading path. Not a real CA-issued
// cert — the test only needs tls.X509KeyPair to succeed.
func writeSelfSignedCert(t *testing.T, dir, cn string, pub ed25519.PublicKey, priv ed25519.PrivateKey) string {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, cn+".crt")
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeIdentityKey writes a PKCS8-PEM Ed25519 private key matching
// what tunnelclient.LoadIdentity expects.
func writeIdentityKey(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	path := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
