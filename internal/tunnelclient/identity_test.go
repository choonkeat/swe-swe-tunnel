package tunnelclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain clears any ambient SWE_TUNNEL_IDENTITY_KEY before running the
// suite. Dev containers export it, which would otherwise steer the
// file-path tests down the env branch (source=env) and break their
// assertions. Tests that need the env path set it explicitly via
// t.Setenv, which restores the (now-unset) value afterward.
func TestMain(m *testing.M) {
	os.Unsetenv(IdentityKeyEnv)
	os.Exit(m.Run())
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a slog.Logger that writes to the returned buffer
// in text format. Tests can grep the buffer's contents to assert on log
// output (e.g. the `identity loaded` fingerprint line).
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// writeFreshKey marshals a fresh Ed25519 key to a PKCS8 PEM file and
// returns (path, raw key bytes). Used by the identity-from-env tests
// to produce a known-good payload.
func writeFreshKey(t *testing.T, dir, name string) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, priv
}

// pemB64 returns base64(PKCS8 PEM(priv)) — the SWE_TUNNEL_IDENTITY_KEY format.
func pemB64(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemBytes)
}

func TestLoadOrCreateIdentity_Generate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")

	priv, err := LoadOrCreateIdentity(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file should exist: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}
}

func TestLoadOrCreateIdentity_Reuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")

	priv1, err := LoadOrCreateIdentity(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := LoadOrCreateIdentity(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1, priv2) {
		t.Error("second load returned a different key — should be persistent")
	}
}

func TestLoadOrCreateIdentity_NotPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	if err := os.WriteFile(path, []byte("garbage, not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateIdentity(path, discardLogger())
	if err == nil {
		t.Fatal("expected error for non-PEM file")
	}
}

func TestLoadOrCreateIdentity_WrongKeyType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrCreateIdentity(path, discardLogger())
	if err == nil {
		t.Fatal("expected error for RSA key (only Ed25519 accepted)")
	}
}

func TestLoadOrCreateIdentity_CreatesParentDir(t *testing.T) {
	// Path under a non-existent subdirectory.
	path := filepath.Join(t.TempDir(), "nested", "subdir", "id.key")
	if _, err := LoadOrCreateIdentity(path, discardLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist after Create: %v", err)
	}
}

// --------------------------------------------------------------------------
// LoadIdentity — env precedence
// --------------------------------------------------------------------------

// Env wins over file: file is not consulted at all when env is set.
func TestLoadIdentity_EnvBeatsFile(t *testing.T) {
	dir := t.TempDir()
	filePath, fileKey := writeFreshKey(t, dir, "file.key")

	_, envKey, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(IdentityKeyEnv, pemB64(t, envKey))

	got, err := LoadIdentity(filePath, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, envKey) {
		t.Error("LoadIdentity returned the file key; expected the env key")
	}
	if bytes.Equal(got, fileKey) {
		t.Error("LoadIdentity returned the file key when env was set — env precedence broken")
	}
}

// Env round-trip: write a file, base64 it, set env, load — must match
// the original file's key bytes.
func TestLoadIdentity_EnvRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, want := writeFreshKey(t, dir, "src.key")
	t.Setenv(IdentityKeyEnv, pemB64(t, want))

	got, err := LoadIdentity(filepath.Join(dir, "ignored.key"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("env round-trip changed the key bytes")
	}
}

// --------------------------------------------------------------------------
// LoadIdentity — env failure modes
// --------------------------------------------------------------------------

// Whitespace-only env is treated as unset, NOT as malformed: an operator
// who has the var declared but blank in their PaaS dashboard should
// silently fall through to the file path. (Empty string is the canonical
// "unset" signal in os.Getenv.)
func TestLoadIdentity_EnvEmptyFallsThroughToFile(t *testing.T) {
	dir := t.TempDir()
	_, fileKey := writeFreshKey(t, dir, "file.key")
	t.Setenv(IdentityKeyEnv, "")

	got, err := LoadIdentity(filepath.Join(dir, "file.key"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Error("expected fallback to file when env is empty")
	}
}

// Invalid base64 in env must produce a loud error WITHOUT falling through
// to the file path. The operator's intent (env) is honored even when their
// payload is wrong — silently ignoring it would let a typo masquerade as
// a fresh-identity startup and burn a `unique` on the tunneld.
func TestLoadIdentity_EnvInvalidBase64FailsLoud(t *testing.T) {
	dir := t.TempDir()
	filePath, _ := writeFreshKey(t, dir, "file.key")
	t.Setenv(IdentityKeyEnv, "this is !! not valid base64 ##")

	_, err := LoadIdentity(filePath, discardLogger())
	if err == nil {
		t.Fatal("expected error for invalid base64 in env, got nil")
	}
	if !strings.Contains(err.Error(), IdentityKeyEnv) {
		t.Errorf("error should name the env var; got: %v", err)
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error should mention base64 stage; got: %v", err)
	}
}

// Valid base64 but the decoded bytes aren't PEM. Same loud-failure rule.
func TestLoadIdentity_EnvValidBase64NotPEMFailsLoud(t *testing.T) {
	dir := t.TempDir()
	filePath, _ := writeFreshKey(t, dir, "file.key")
	t.Setenv(IdentityKeyEnv, base64.StdEncoding.EncodeToString([]byte("definitely not PEM")))

	_, err := LoadIdentity(filePath, discardLogger())
	if err == nil {
		t.Fatal("expected error for non-PEM payload in env, got nil")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("error should mention PEM; got: %v", err)
	}
}

// PEM but wrong key type (RSA in env, we only accept Ed25519). Same loud-
// failure rule. This protects against an operator who ran
// `base64 -w0 < server.key` against an unrelated TLS server key by mistake.
func TestLoadIdentity_EnvWrongKeyTypeFailsLoud(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	t.Setenv(IdentityKeyEnv, base64.StdEncoding.EncodeToString(pemBytes))

	_, err = LoadIdentity(filepath.Join(t.TempDir(), "ignored.key"), discardLogger())
	if err == nil {
		t.Fatal("expected error for RSA key in env (only Ed25519 accepted)")
	}
	if !strings.Contains(err.Error(), "ed25519") {
		t.Errorf("error should mention ed25519; got: %v", err)
	}
}

// --------------------------------------------------------------------------
// LoadIdentity — disk side-effects
// --------------------------------------------------------------------------

// The PaaS regression gate: when env supplies the key, the identity-key
// file path must NOT be created, mkdir'd, or written. If we ever touch
// disk on the env path, this test fails. (Important because the file
// path will land at a default like `~/.swe-swe-tunnel/identity.key`,
// and on a read-only PaaS root that mkdir attempt would 500 the boot.)
func TestLoadIdentity_EnvPathMakesNoDiskWrite(t *testing.T) {
	dir := t.TempDir()
	// Path under a non-existent subdir. If LoadIdentity touched disk
	// it would have to create both the subdir and the file.
	filePath := filepath.Join(dir, "nested", "subdir", "id.key")

	_, envKey, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(IdentityKeyEnv, pemB64(t, envKey))

	if _, err := LoadIdentity(filePath, discardLogger()); err != nil {
		t.Fatal(err)
	}
	// The subdirectory must not have been created.
	if _, err := os.Stat(filepath.Dir(filePath)); !os.IsNotExist(err) {
		t.Errorf("env-loaded path created the parent dir; stat err = %v (want IsNotExist)", err)
	}
	// And the file itself must not exist.
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("env-loaded path created the file; stat err = %v (want IsNotExist)", err)
	}
}

// --------------------------------------------------------------------------
// LoadIdentity — fingerprint log line
// --------------------------------------------------------------------------

// A single `identity loaded` line must be emitted on each call, with a
// 12-hex `fingerprint` field and the right `source` tag. This is what
// lets operators visually confirm the right key got into the right
// deploy without us having to log the key itself.
func TestLoadIdentity_LogsFingerprint_FileSource(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "id.key")
	logger, buf := captureLogger()

	if _, err := LoadIdentity(filePath, logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "identity loaded") {
		t.Errorf("expected 'identity loaded' line; got: %s", out)
	}
	if !strings.Contains(out, "source=file") {
		t.Errorf("expected source=file; got: %s", out)
	}
	if !strings.Contains(out, "fingerprint=") {
		t.Errorf("expected fingerprint= field; got: %s", out)
	}
	// Loose shape check: the fingerprint should be 12 hex chars (48 bits).
	// We don't pin the value (it depends on the auto-generated key bytes).
	checkFingerprintShape(t, out)
}

func TestLoadIdentity_LogsFingerprint_EnvSource(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(IdentityKeyEnv, pemB64(t, priv))
	logger, buf := captureLogger()

	if _, err := LoadIdentity(filepath.Join(t.TempDir(), "ignored.key"), logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "source=env") {
		t.Errorf("expected source=env; got: %s", out)
	}
	checkFingerprintShape(t, out)
}

// Two calls with the same key (one via file, one via env round-trip
// of that same file) must yield the SAME fingerprint. This is the
// property that makes the field useful for cross-deploy diffing.
func TestLoadIdentity_FingerprintIsStableAcrossSources(t *testing.T) {
	dir := t.TempDir()
	filePath, priv := writeFreshKey(t, dir, "id.key")

	logger1, buf1 := captureLogger()
	if _, err := LoadIdentity(filePath, logger1); err != nil {
		t.Fatal(err)
	}
	fpFile := extractFingerprint(t, buf1.String())

	t.Setenv(IdentityKeyEnv, pemB64(t, priv))
	logger2, buf2 := captureLogger()
	if _, err := LoadIdentity(filepath.Join(dir, "ignored.key"), logger2); err != nil {
		t.Fatal(err)
	}
	fpEnv := extractFingerprint(t, buf2.String())

	if fpFile != fpEnv {
		t.Errorf("fingerprint differs across sources for the same key: file=%q env=%q", fpFile, fpEnv)
	}
}

// --------------------------------------------------------------------------
// LoadIdentityStatus — generated flag (first-boot bootstrap gate)
// --------------------------------------------------------------------------

// A missing key file must report generated=true: this is the first-boot
// case main() intercepts to print the pubkey and exit before burning a
// registration attempt.
func TestLoadIdentityStatus_GeneratedOnFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")

	priv, generated, err := LoadIdentityStatus(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Error("generated = false on a missing key file; want true")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

// An existing key file must report generated=false: the second boot
// reuses the on-disk key and connects normally.
func TestLoadIdentityStatus_NotGeneratedOnReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")
	if _, err := LoadOrCreateIdentity(path, discardLogger()); err != nil {
		t.Fatal(err)
	}

	_, generated, err := LoadIdentityStatus(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if generated {
		t.Error("generated = true on an existing key file; want false")
	}
}

// The inline SWE_TUNNEL_IDENTITY_KEY path never touches disk, so it must
// always report generated=false — the bootstrap gate must NOT fire there.
func TestLoadIdentityStatus_EnvNeverGenerated(t *testing.T) {
	_, envKey, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(IdentityKeyEnv, pemB64(t, envKey))
	// A non-existent path: if generated were derived from the file's
	// absence we'd wrongly get true here.
	path := filepath.Join(t.TempDir(), "nope", "id.key")

	_, generated, err := LoadIdentityStatus(path, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if generated {
		t.Error("generated = true on the inline-env path; want false (env never touches disk)")
	}
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

func checkFingerprintShape(t *testing.T, log string) {
	t.Helper()
	fp := extractFingerprint(t, log)
	if len(fp) != 12 {
		t.Errorf("fingerprint length = %d, want 12 (hex chars); got %q", len(fp), fp)
	}
	for _, r := range fp {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Errorf("fingerprint contains non-hex char %q in %q", r, fp)
			return
		}
	}
}

// extractFingerprint pulls the value of `fingerprint=...` from a slog
// text-handler line. Returns "" if not found, which the callers treat
// as a failure.
func extractFingerprint(t *testing.T, log string) string {
	t.Helper()
	const key = "fingerprint="
	i := strings.Index(log, key)
	if i < 0 {
		t.Fatalf("no fingerprint= field in log: %s", log)
	}
	rest := log[i+len(key):]
	end := strings.IndexAny(rest, " \n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}
