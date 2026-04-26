package tunnelclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
