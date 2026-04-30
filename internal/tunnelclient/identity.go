package tunnelclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// IdentityKeyEnv is the env var that, when set, supplies the Ed25519
// identity key directly — bypassing the on-disk path entirely. The value
// is a base64-encoded PKCS8 PEM block (i.e. `base64 -w0 < identity.key`).
//
// Exists so the client can run on read-only / ephemeral filesystems
// (PaaS dynos, K8s pods) without burning a fresh `unique` on every
// container restart. See tasks/2026-05-01-identity-from-env.md.
const IdentityKeyEnv = "SWE_TUNNEL_IDENTITY_KEY"

// LoadIdentity returns the Ed25519 private key, resolving in this
// precedence order:
//
//  1. SWE_TUNNEL_IDENTITY_KEY env var — base64(PKCS8 PEM)
//  2. file at filePath (auto-generated and persisted on first run)
//
// When the env var is set but malformed, this returns an error WITHOUT
// falling through to the file path. The operator clearly intended the
// env path; silently auto-generating a different key would burn a fresh
// `unique` on the tunneld and leave them confused about why.
//
// When the env var is set and valid, the file at filePath is NOT read,
// created, or written. The env path is safe on a read-only filesystem.
//
// Either way, a single `identity loaded` log line is emitted with the
// 12-hex-prefix fingerprint of the public key, so an operator can confirm
// "yes I deployed the right key" from the boot log alone.
func LoadIdentity(filePath string, logger *slog.Logger) (ed25519.PrivateKey, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if envB64 := os.Getenv(IdentityKeyEnv); envB64 != "" {
		priv, err := parseB64Identity(envB64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", IdentityKeyEnv, err)
		}
		logIdentityFingerprint(logger, priv, "env", "")
		return priv, nil
	}
	priv, err := LoadOrCreateIdentity(filePath, logger)
	if err != nil {
		return nil, err
	}
	logIdentityFingerprint(logger, priv, "file", filePath)
	return priv, nil
}

// parseB64Identity decodes a base64-encoded PKCS8 PEM block into an
// Ed25519 private key. Surfaces a clear error chain at every stage so
// the operator can tell which step failed (base64 vs PEM vs PKCS8 vs
// key-type).
func parseB64Identity(s string) (ed25519.PrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not PEM after base64 decode")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity is %T, want ed25519.PrivateKey", key)
	}
	return priv, nil
}

// logIdentityFingerprint emits a single "identity loaded" line with a
// short, stable identifier of the public key. 12 hex chars (48 bits) is
// enough for human-eye comparison and useless to an attacker. We never
// log the private key or even the full pubkey hash.
func logIdentityFingerprint(logger *slog.Logger, priv ed25519.PrivateKey, source, path string) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		// Defensive — only callable with ed25519.PrivateKey, but if a
		// future change to LoadIdentity hands us something else we'd
		// rather log "unknown" than panic.
		logger.Info("identity loaded", "source", source, "fingerprint", "unknown")
		return
	}
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:6])
	if path != "" {
		logger.Info("identity loaded", "source", source, "path", path, "fingerprint", fp)
	} else {
		logger.Info("identity loaded", "source", source, "fingerprint", fp)
	}
}

// LoadOrCreateIdentity reads the Ed25519 private key at path, generating one
// on first run and persisting it as a PKCS8 PEM block (mode 0600).
//
// Prefer LoadIdentity in production code — it adds env-var support and the
// fingerprint log line. LoadOrCreateIdentity remains the file-only entry
// point for tests and for callers that explicitly want the on-disk path.
func LoadOrCreateIdentity(path string, logger *slog.Logger) (ed25519.PrivateKey, error) {
	if logger == nil {
		logger = slog.Default()
	}
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("identity key: not PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identity key is %T, want ed25519.PrivateKey", key)
		}
		return priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read identity key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir for identity key: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS8: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	logger.Info("generated new identity key", "path", path)
	return priv, nil
}
