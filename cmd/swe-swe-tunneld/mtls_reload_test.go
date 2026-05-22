package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/choonkeat/swe-swe-tunnel/internal/mtls"
)

// TestMtlsBundle_LoadAndPool confirms the boot path: a freshly-written
// CA file loads, the returned pool contains the cert, and Count() and
// Path() report the truth.
func TestMtlsBundle_LoadAndPool(t *testing.T) {
	dir := t.TempDir()
	if err := mtls.InitCA(dir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	caPath := filepath.Join(dir, "ca.pem")

	b, err := loadMtlsBundle(caPath)
	if err != nil {
		t.Fatalf("loadMtlsBundle: %v", err)
	}
	if b.Path() != caPath {
		t.Errorf("Path = %q, want %q", b.Path(), caPath)
	}
	if b.Count() != 1 {
		t.Errorf("Count = %d, want 1", b.Count())
	}
	if b.Pool() == nil {
		t.Fatal("Pool returned nil")
	}
	caCert := parseCA(t, caPath)
	if !poolTrusts(b.Pool(), caCert) {
		t.Error("pool does not trust the CA it was loaded from")
	}
}

// TestMtlsBundle_LoadMissingFails asserts the boot loud-fail path: a
// missing CA file must surface as an error so main can exit non-zero,
// not silently fall back to an empty pool.
func TestMtlsBundle_LoadMissingFails(t *testing.T) {
	_, err := loadMtlsBundle(filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if err == nil {
		t.Fatal("loadMtlsBundle(missing): expected error, got nil")
	}
}

// TestMtlsBundle_ReloadReflectsNewFile is the SIGHUP path: a bundle
// loaded from CA-A then swapped on disk to CA-B must, after Reload,
// hand out a pool that trusts CA-B instead of CA-A.
func TestMtlsBundle_ReloadReflectsNewFile(t *testing.T) {
	caDirA := t.TempDir()
	if err := mtls.InitCA(caDirA, false); err != nil {
		t.Fatal(err)
	}
	caDirB := t.TempDir()
	if err := mtls.InitCA(caDirB, false); err != nil {
		t.Fatal(err)
	}
	certA := parseCA(t, filepath.Join(caDirA, "ca.pem"))
	certB := parseCA(t, filepath.Join(caDirB, "ca.pem"))

	target := filepath.Join(t.TempDir(), "trusted.pem")
	copyFile(t, filepath.Join(caDirA, "ca.pem"), target)

	b, err := loadMtlsBundle(target)
	if err != nil {
		t.Fatalf("loadMtlsBundle: %v", err)
	}
	if !poolTrusts(b.Pool(), certA) {
		t.Fatal("initial pool does not trust CA A")
	}
	if poolTrusts(b.Pool(), certB) {
		t.Fatal("initial pool unexpectedly trusts CA B")
	}

	// Swap the file to CA B and reload.
	copyFile(t, filepath.Join(caDirB, "ca.pem"), target)
	if err := b.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !poolTrusts(b.Pool(), certB) {
		t.Error("after reload, pool does not trust CA B")
	}
	if poolTrusts(b.Pool(), certA) {
		t.Error("after reload, pool still trusts CA A")
	}
}

// TestMtlsBundle_ReloadKeepsPreviousOnError covers the safety
// contract: if the file vanishes between loads, Reload returns an
// error and the prior pool stays intact. This is the same shape as
// the allowlist reload arm.
func TestMtlsBundle_ReloadKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	if err := mtls.InitCA(dir, false); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")

	b, err := loadMtlsBundle(caPath)
	if err != nil {
		t.Fatalf("loadMtlsBundle: %v", err)
	}
	caCert := parseCA(t, caPath)
	if !poolTrusts(b.Pool(), caCert) {
		t.Fatal("initial pool does not trust CA")
	}

	// Vanish the file mid-flight.
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}
	if err := b.Reload(); err == nil {
		t.Fatal("Reload after file removed: expected error, got nil")
	}
	// Prior pool must still be intact.
	if !poolTrusts(b.Pool(), caCert) {
		t.Error("after failed reload, prior pool was lost")
	}
}

// TestReloadMtlsBundle_HookLogsAndSwaps exercises the SIGHUP wrapper
// directly. Happy path → INFO log + new pool. Failure path → ERROR
// log + prior pool preserved.
func TestReloadMtlsBundle_HookLogsAndSwaps(t *testing.T) {
	caDirA := t.TempDir()
	if err := mtls.InitCA(caDirA, false); err != nil {
		t.Fatal(err)
	}
	caDirB := t.TempDir()
	if err := mtls.InitCA(caDirB, false); err != nil {
		t.Fatal(err)
	}
	certA := parseCA(t, filepath.Join(caDirA, "ca.pem"))
	certB := parseCA(t, filepath.Join(caDirB, "ca.pem"))

	target := filepath.Join(t.TempDir(), "trusted.pem")
	copyFile(t, filepath.Join(caDirA, "ca.pem"), target)
	b, err := loadMtlsBundle(target)
	if err != nil {
		t.Fatalf("loadMtlsBundle: %v", err)
	}

	// Nil bundle is a no-op (matches the inert SIGHUP arm when mTLS
	// is off).
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloadMtlsBundle(nil, logger)

	// Happy path: swap to CA B, run the hook, expect "mTLS CA reloaded"
	// in the log and CA B trusted in the pool.
	copyFile(t, filepath.Join(caDirB, "ca.pem"), target)
	buf := &bytes.Buffer{}
	logger = slog.New(slog.NewTextHandler(buf, nil))
	reloadMtlsBundle(b, logger)
	if !strings.Contains(buf.String(), "mTLS CA reloaded") {
		t.Errorf("log missing 'mTLS CA reloaded': %s", buf.String())
	}
	if !poolTrusts(b.Pool(), certB) {
		t.Error("after hook, pool does not trust CA B")
	}

	// Failure path: vanish the file, run the hook, expect "mTLS CA
	// reload failed" + prior pool (CA B) preserved.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	reloadMtlsBundle(b, logger)
	if !strings.Contains(buf.String(), "mTLS CA reload failed") {
		t.Errorf("log missing 'mTLS CA reload failed': %s", buf.String())
	}
	if !poolTrusts(b.Pool(), certB) {
		t.Error("after failed hook, prior pool was lost")
	}
	if poolTrusts(b.Pool(), certA) {
		t.Error("after failed hook, pool drifted back to CA A")
	}
}

// parseCA reads the first CERTIFICATE block at path. Used as the
// "candidate" cert for poolTrusts.
func parseCA(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert in %s: %v", path, err)
	}
	return cert
}

// poolTrusts reports whether pool would verify ca's signature.
// InitCA mints CAs with a constant Subject CN, so we can't tell them
// apart by Subject alone — but x509.Verify uses the actual signing
// key, which is unique per CA. A self-signed CA verifies against a
// pool iff the pool contains *that exact* CA.
func poolTrusts(pool *x509.CertPool, ca *x509.Certificate) bool {
	if pool == nil {
		return false
	}
	_, err := ca.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}

// copyFile is a tiny test helper: read src, write to dst with mode 0644.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatal(err)
	}
}
