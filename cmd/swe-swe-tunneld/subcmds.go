package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/mtls"
)

// runSubcommand routes one-shot CLI utility modes (mtls-init,
// mtls-issue, mtls-sign) that execute and exit before the
// long-running listener starts. Returns (exitCode, handled): when
// handled is false, main() should fall through to the daemon path.
// The shape mirrors the existing --ensure-cert one-shot flow.
func runSubcommand(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) (int, bool) {
	if len(args) < 2 {
		return 0, false
	}
	switch args[1] {
	case "mtls-init":
		return runMtlsInit(args[2:], stateDir, stdout, logger), true
	case "mtls-issue":
		return runMtlsIssue(args[2:], stateDir, stdout, logger), true
	case "mtls-sign":
		return runMtlsSign(args[2:], stateDir, stdout, logger), true
	}
	return 0, false
}

// defaultMtlsDir picks the CA directory when --dir is unset:
// {state-dir}/mtls. Matches the location the daemon would also
// SIGHUP-reload when --mtls-ca points inside it.
func defaultMtlsDir(stateDir string) string {
	return filepath.Join(stateDir, "mtls")
}

// newSubcmdFlagSet builds a flag set with stderr redirected to the
// bit bucket — subcommand argument errors surface via the logger
// (one structured message) rather than dumping flag's terse default
// usage onto a parent script's stderr.
func newSubcmdFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// runMtlsInit writes a fresh self-signed Ed25519 CA into --dir
// (default {state-dir}/mtls). Refuses to overwrite an existing CA
// unless --force is passed — silently rotating the CA would
// invalidate every client cert already deployed, so requiring
// --force makes that operator intent explicit.
func runMtlsInit(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) int {
	fs := newSubcmdFlagSet("mtls-init")
	dir := fs.String("dir", "", "directory to write ca.key + ca.pem (default {state-dir}/mtls)")
	force := fs.Bool("force", false, "overwrite existing ca.key / ca.pem")
	if err := fs.Parse(args); err != nil {
		logger.Error("mtls-init: parse args", "err", err)
		return 2
	}
	target := *dir
	if target == "" {
		target = defaultMtlsDir(stateDir)
	}
	if err := mtls.InitCA(target, *force); err != nil {
		logger.Error("mtls-init: init CA", "dir", target, "err", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s/ca.key and %s/ca.pem\n", target, target)
	return 0
}

// runMtlsIssue mints a fresh Ed25519 keypair, signs a client cert
// (CN=cn) for it, and packages it into a PKCS#12 bundle protected by
// a generated passphrase. The p12 always goes to a file (`-o`
// required, binary content is unsafe to dump on a terminal stdout);
// the passphrase is printed to stdout exactly once and never
// logged. Browser-user flow.
func runMtlsIssue(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) int {
	fs := newSubcmdFlagSet("mtls-issue")
	dir := fs.String("dir", "", "directory containing ca.key + ca.pem (default {state-dir}/mtls)")
	cn := fs.String("cn", "", "Common Name for the issued cert (required)")
	days := fs.Int("days", 365, "validity in days")
	out := fs.String("o", "", "p12 output path (required)")
	if err := fs.Parse(args); err != nil {
		logger.Error("mtls-issue: parse args", "err", err)
		return 2
	}
	if *cn == "" {
		logger.Error("mtls-issue: --cn is required")
		return 2
	}
	if *out == "" {
		logger.Error("mtls-issue: -o is required (path for p12)")
		return 2
	}
	target := *dir
	if target == "" {
		target = defaultMtlsDir(stateDir)
	}
	ca, err := mtls.LoadCA(target)
	if err != nil {
		logger.Error("mtls-issue: load CA", "dir", target, "err", err)
		return 1
	}
	bundle, err := ca.IssueClientCert(*cn, time.Duration(*days)*24*time.Hour)
	if err != nil {
		logger.Error("mtls-issue: mint cert", "err", err)
		return 1
	}
	if err := os.WriteFile(*out, bundle.P12, 0o600); err != nil {
		logger.Error("mtls-issue: write p12", "path", *out, "err", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (PKCS#12, %d bytes)\n", *out, len(bundle.P12))
	fmt.Fprintf(stdout, "passphrase: %s\n", bundle.Passphrase)
	return 0
}

// runMtlsSign signs an existing Ed25519 public key (no key minting)
// into a client cert. Used by agent hosts that already have an
// identity keypair on disk — the agent's identity.key doubles as
// the TLS private key, so we sign the matching pubkey and ship the
// resulting cert. The pubkey file accepts either an SPKI PEM (what
// `openssl pkey -pubout` emits) or a base64-RawStd single-line raw
// 32-byte pubkey (what the allowlist files already use).
func runMtlsSign(args []string, stateDir string, stdout io.Writer, logger *slog.Logger) int {
	fs := newSubcmdFlagSet("mtls-sign")
	dir := fs.String("dir", "", "directory containing ca.key + ca.pem (default {state-dir}/mtls)")
	cn := fs.String("cn", "", "Common Name for the issued cert (required)")
	days := fs.Int("days", 365, "validity in days")
	out := fs.String("o", "", "cert PEM output path (default: stdout)")
	pubkey := fs.String("pubkey", "", "path to the Ed25519 public key: SPKI PEM or base64-RawStd (required)")
	if err := fs.Parse(args); err != nil {
		logger.Error("mtls-sign: parse args", "err", err)
		return 2
	}
	if *cn == "" {
		logger.Error("mtls-sign: --cn is required")
		return 2
	}
	if *pubkey == "" {
		logger.Error("mtls-sign: --pubkey is required")
		return 2
	}
	target := *dir
	if target == "" {
		target = defaultMtlsDir(stateDir)
	}
	ca, err := mtls.LoadCA(target)
	if err != nil {
		logger.Error("mtls-sign: load CA", "dir", target, "err", err)
		return 1
	}
	pubBytes, err := os.ReadFile(*pubkey)
	if err != nil {
		logger.Error("mtls-sign: read pubkey", "path", *pubkey, "err", err)
		return 1
	}
	pub, err := parseEd25519Pubkey(pubBytes)
	if err != nil {
		logger.Error("mtls-sign: parse pubkey", "path", *pubkey, "err", err)
		return 1
	}
	certPEM, err := ca.SignClientPubkey(*cn, pub, time.Duration(*days)*24*time.Hour)
	if err != nil {
		logger.Error("mtls-sign: sign", "err", err)
		return 1
	}
	if *out != "" {
		if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
			logger.Error("mtls-sign: write cert", "path", *out, "err", err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s\n", *out)
		return 0
	}
	if _, err := stdout.Write(certPEM); err != nil {
		logger.Error("mtls-sign: write stdout", "err", err)
		return 1
	}
	return 0
}

// parseEd25519Pubkey decodes either an SPKI "PUBLIC KEY" PEM block
// or a single-line base64-RawStd encoding of the raw 32-byte
// Ed25519 public key. The dual-format support lets an operator
// drop a single file into the allowlist directory AND feed the
// same file to mtls-sign without converting.
func parseEd25519Pubkey(data []byte) (ed25519.PublicKey, error) {
	if blk, _ := pem.Decode(data); blk != nil {
		ifc, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX PEM: %w", err)
		}
		pub, ok := ifc.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM pubkey is %T, want ed25519.PublicKey", ifc)
		}
		return pub, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("pubkey is neither valid PEM nor base64-RawStd")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pubkey base64 decoded %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
