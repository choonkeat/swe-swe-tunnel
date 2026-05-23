package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestMtlsInit_CreatesCA covers the happy path: `mtls-init` with no
// flags writes ca.key (0600) + ca.pem into {state-dir}/mtls and the
// cert parses as a self-signed Ed25519 CA.
func TestMtlsInit_CreatesCA(t *testing.T) {
	stateDir := t.TempDir()
	var out bytes.Buffer
	code := runMtlsInit(nil, stateDir, &out, quietLogger())
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q", code, out.String())
	}

	caDir := filepath.Join(stateDir, "mtls")
	keyInfo, err := os.Stat(filepath.Join(caDir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("ca.key perm = %v, want 0600", keyInfo.Mode().Perm())
	}

	certBytes, err := os.ReadFile(filepath.Join(caDir, "ca.pem"))
	if err != nil {
		t.Fatalf("ca.pem: %v", err)
	}
	blk, _ := pem.Decode(certBytes)
	if blk == nil {
		t.Fatal("ca.pem not PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("CA pubkey type = %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if !cert.IsCA {
		t.Error("CA cert IsCA=false")
	}
}

// TestMtlsInit_RefusesOverwrite confirms idempotency: running the
// command twice without --force errors out (so an operator can't
// silently rotate every issued cert), and --force lets them through.
func TestMtlsInit_RefusesOverwrite(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("first init: %d", code)
	}
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code == 0 {
		t.Error("second init without --force: expected non-zero exit")
	}
	if code := runMtlsInit([]string{"--force"}, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Errorf("init --force: exit = %d, want 0", code)
	}
}

// TestMtlsInit_CustomDir confirms --dir overrides the default
// {state-dir}/mtls path. Useful when the operator's CA lives
// elsewhere (out-of-tree, /etc/swe-swe-tunnel/, etc.).
func TestMtlsInit_CustomDir(t *testing.T) {
	stateDir := t.TempDir()
	customDir := filepath.Join(t.TempDir(), "alt-ca")
	if code := runMtlsInit([]string{"--dir", customDir}, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init --dir: %d", code)
	}
	if _, err := os.Stat(filepath.Join(customDir, "ca.pem")); err != nil {
		t.Errorf("ca.pem in --dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "mtls", "ca.pem")); !os.IsNotExist(err) {
		t.Errorf("default dir was unexpectedly populated: err=%v", err)
	}
}

// TestMtlsIssue_RoundTrip exercises the full browser-user flow:
// init the CA, issue a p12 for "alice", decode the p12 with the
// printed passphrase, and confirm the cert chains to the CA and the
// CN matches. Mirrors what a browser would do after import.
func TestMtlsIssue_RoundTrip(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}

	outFile := filepath.Join(t.TempDir(), "alice.p12")
	var stdout bytes.Buffer
	code := runMtlsIssue([]string{"--cn", "alice", "-o", outFile}, stateDir, &stdout, quietLogger())
	if code != 0 {
		t.Fatalf("issue: exit = %d; stdout=%q", code, stdout.String())
	}

	// The passphrase appears on its own line in stdout. Scan rather
	// than match-exact since other status lines may precede it.
	pass := extractPrefix(stdout.String(), "passphrase: ")
	if pass == "" {
		t.Fatalf("no 'passphrase: ' line in stdout:\n%s", stdout.String())
	}

	p12Bytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read p12: %v", err)
	}
	priv, cert, caCerts, err := pkcs12.DecodeChain(p12Bytes, pass)
	if err != nil {
		t.Fatalf("p12 decode with printed passphrase: %v", err)
	}
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Errorf("p12 priv key type = %T, want ed25519.PrivateKey", priv)
	}
	if cert.Subject.CommonName != "alice" {
		t.Errorf("p12 cert CN = %q, want %q", cert.Subject.CommonName, "alice")
	}
	if len(caCerts) == 0 {
		t.Fatal("p12 chain has no CA cert")
	}

	// Chain verifies against the bundled CA.
	roots := x509.NewCertPool()
	for _, c := range caCerts {
		roots.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("cert.Verify: %v", err)
	}
}

// TestMtlsIssue_RequiresCN documents the explicit-CN requirement:
// silently using a default like "client" would let an operator
// accidentally issue a cert with a placeholder name into a real
// deployment. Empty CN must hard-fail with a non-zero exit.
func TestMtlsIssue_RequiresCN(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	outFile := filepath.Join(t.TempDir(), "x.p12")
	if code := runMtlsIssue([]string{"-o", outFile}, stateDir, io.Discard, quietLogger()); code == 0 {
		t.Error("issue without --cn: expected non-zero exit")
	}
}

// TestMtlsIssue_RequiresOutput confirms the p12 path requirement:
// we never dump a binary p12 to whatever stdout happens to be. The
// passphrase is sensitive and stdout-only by design (no -o for it),
// but the p12 must be addressable to a file the operator chose.
func TestMtlsIssue_RequiresOutput(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	if code := runMtlsIssue([]string{"--cn", "alice"}, stateDir, io.Discard, quietLogger()); code == 0 {
		t.Error("issue without -o: expected non-zero exit")
	}
}

// TestMtlsSign_ReusesPubkey_SPKI is the agent flow: an Ed25519 SPKI
// PEM public key (the format `openssl pkey -in id.key -pubout`
// produces) is signed into a client cert; the resulting cert's
// public key matches the input. The agent's identity.key never
// leaves the agent host.
func TestMtlsSign_ReusesPubkey_SPKI(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := writeSPKI(t, pub)

	outFile := filepath.Join(t.TempDir(), "agent.crt")
	code := runMtlsSign([]string{"--pubkey", pubPath, "--cn", "agent-01", "-o", outFile}, stateDir, io.Discard, quietLogger())
	if code != 0 {
		t.Fatalf("sign: %d", code)
	}

	certBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certBytes)
	if blk == nil {
		t.Fatal("cert not PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("cert pubkey type = %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Error("cert pubkey != input pubkey")
	}
	if cert.Subject.CommonName != "agent-01" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "agent-01")
	}
}

// TestMtlsSign_ReusesPubkey_AllowlistFile is the live operator
// path that broke against the real production allowlist on
// 2026-05-23: a pubkey file written for the daemon's allowlist
// gate uses one base64-RawStd key per line with optional `#`
// comments and blank lines (`internal/allowlist` format). When
// mtls-sign rejects such a file, an operator who already runs
// the allowlist gate has to maintain a parallel pubkey file just
// for mTLS -- defeating the "one pubkey file works in both
// places" property docs/mtls.md promises.
func TestMtlsSign_AcceptsAllowlistFile(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "agent.pub")
	body := "# generated 2026-05-23\n\n" +
		base64.RawStdEncoding.EncodeToString(pub) + "  # agent comment\n"
	if err := os.WriteFile(pubPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "agent.crt")
	code := runMtlsSign([]string{"--pubkey", pubPath, "--cn", "agent-01", "-o", outFile}, stateDir, io.Discard, quietLogger())
	if code != 0 {
		t.Fatalf("sign with allowlist-style file: %d", code)
	}
	certBytes, _ := os.ReadFile(outFile)
	blk, _ := pem.Decode(certBytes)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if !bytes.Equal(cert.PublicKey.(ed25519.PublicKey), pub) {
		t.Error("cert pubkey != input pubkey (allowlist-style path)")
	}
}

// TestMtlsSign_ReusesPubkey_Base64 accepts the same one-line
// base64-RawStd format the allowlist files use. Lets an operator
// drop a single pubkey file into the allowlist dir AND sign it for
// mTLS without converting between formats.
func TestMtlsSign_ReusesPubkey_Base64(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "agent.pub")
	b64 := base64.RawStdEncoding.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(b64+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(t.TempDir(), "agent.crt")
	code := runMtlsSign([]string{"--pubkey", pubPath, "--cn", "agent-01", "-o", outFile}, stateDir, io.Discard, quietLogger())
	if code != 0 {
		t.Fatalf("sign: %d", code)
	}
	certBytes, _ := os.ReadFile(outFile)
	blk, _ := pem.Decode(certBytes)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	got := cert.PublicKey.(ed25519.PublicKey)
	if !bytes.Equal(got, pub) {
		t.Error("cert pubkey != input pubkey (base64 path)")
	}
}

// TestMtlsSign_RejectsBadPubkey confirms operator errors fail fast:
// a malformed pubkey file (neither valid PEM nor valid base64) must
// not silently produce a cert for some unintended key.
func TestMtlsSign_RejectsBadPubkey(t *testing.T) {
	stateDir := t.TempDir()
	if code := runMtlsInit(nil, stateDir, io.Discard, quietLogger()); code != 0 {
		t.Fatalf("init: %d", code)
	}
	pubPath := filepath.Join(t.TempDir(), "agent.pub")
	if err := os.WriteFile(pubPath, []byte("this is not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(t.TempDir(), "agent.crt")
	if code := runMtlsSign([]string{"--pubkey", pubPath, "--cn", "agent-01", "-o", outFile}, stateDir, io.Discard, quietLogger()); code == 0 {
		t.Error("sign with malformed pubkey: expected non-zero exit")
	}
}

// TestRunSubcommand_Dispatch confirms the multiplexer hands off to
// the right runMtls* function and returns handled=true. Tests the
// thin part of main()'s subcommand path without needing the daemon
// to boot.
func TestRunSubcommand_Dispatch(t *testing.T) {
	stateDir := t.TempDir()
	logger := quietLogger()

	// args[0] is the program name; args[1] is the subcommand.
	if code, handled := runSubcommand([]string{"swe-swe-tunneld", "mtls-init"}, stateDir, io.Discard, logger); !handled {
		t.Error("mtls-init: handled=false")
	} else if code != 0 {
		t.Errorf("mtls-init: exit = %d", code)
	}

	if code, handled := runSubcommand([]string{"swe-swe-tunneld", "not-a-subcommand"}, stateDir, io.Discard, logger); handled {
		t.Errorf("not-a-subcommand: handled=true (exit=%d), want false", code)
	}
	if _, handled := runSubcommand([]string{"swe-swe-tunneld"}, stateDir, io.Discard, logger); handled {
		t.Error("no subcommand: handled=true, want false")
	}
}

// writeSPKI marshals an Ed25519 public key into a PEM "PUBLIC KEY"
// block (the SPKI / PKIX format `openssl pkey -pubout` emits) and
// returns the file path. Used by sign-flow tests.
func writeSPKI(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "agent.pub")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// extractPrefix scans s line-by-line and returns the trimmed
// remainder of the first line beginning with prefix, or "" if not
// present.
func extractPrefix(s, prefix string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
