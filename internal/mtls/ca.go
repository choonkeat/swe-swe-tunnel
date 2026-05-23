// Package mtls provides the small CA + client-cert toolkit used by
// swe-swe-tunneld's mtls-init / mtls-issue / mtls-sign subcommands, plus
// the LoadCABundle helper the daemon calls at boot to populate
// tls.Config.ClientCAs.
//
// Everything is Ed25519: the CA root, freshly issued client keypairs
// (IssueClientCert), and signed-from-pubkey certs (SignClientPubkey). The
// last is what lets an agent reuse its existing identity.key as the TLS
// keypair — one private key, two uses, no new on-disk material on the
// agent host.
package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const (
	caKeyFile  = "ca.key"
	caCertFile = "ca.pem"
)

// LoadCABundle reads a PEM file of one or more X.509 certs and returns an
// x509.CertPool plus the number of certs parsed. Used by the daemon at
// boot to populate tls.Config.ClientCAs. Returns an error if the file is
// missing, the bytes aren't PEM, or zero CERTIFICATE blocks are found.
func LoadCABundle(path string) (*x509.CertPool, int, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	count := 0
	rest := bytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("parse cert in %s: %w", path, err)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("no CERTIFICATE blocks in %s", path)
	}
	return pool, count, nil
}

// InitCA writes a fresh self-signed Ed25519 CA into dir as ca.key (0600)
// and ca.pem (0644). With force=false it returns an error if either file
// already exists. With force=true it overwrites both.
func InitCA(dir string, force bool) error {
	keyPath := filepath.Join(dir, caKeyFile)
	certPath := filepath.Join(dir, caCertFile)

	if !force {
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("%s already exists; pass force=true to overwrite", keyPath)
		}
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("%s already exists; pass force=true to overwrite", certPath)
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "swe-swe-tunnel mTLS CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	// Force-mode reuse can inherit prior perms; chmod restores 0600.
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	return nil
}

// CA is a loaded CA from a directory written by InitCA.
type CA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

// LoadCA reads ca.key + ca.pem from dir. Used by the issue/sign
// subcommands to mint client certs.
func LoadCA(dir string) (*CA, error) {
	keyBytes, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	kblk, _ := pem.Decode(keyBytes)
	if kblk == nil {
		return nil, errors.New("CA key not PEM")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	edKey, ok := rawKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is %T, want ed25519.PrivateKey", rawKey)
	}

	certBytes, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	cblk, _ := pem.Decode(certBytes)
	if cblk == nil {
		return nil, errors.New("CA cert not PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return &CA{cert: cert, key: edKey}, nil
}

// ClientBundle is the result of IssueClientCert.
type ClientBundle struct {
	CertPEM    []byte
	KeyPEM     []byte
	P12        []byte
	Passphrase string
}

// IssueClientCert mints a fresh ECDSA P-256 keypair, signs a client
// cert (CN=cn) for it against the loaded CA, and returns the cert +
// key as PEM along with a PKCS#12 bundle protected by a generated
// passphrase. Used by `swe-swe-tunneld mtls-issue` for browser
// users.
//
// ECDSA P-256 (not Ed25519) is intentional: macOS and iOS Keychain
// refuse to decode an Ed25519 PKCS#12 with "Unable to decode the
// provided data" — a documented Apple-side limitation that
// surfaced live on 2026-05-23 trying to import a v1 (Ed25519)
// bundle. P-256 is universally supported across browsers and
// remains a sensible security floor (~128-bit equivalent). The CA
// itself stays Ed25519 (cross-algorithm chains are normal X.509);
// existing agent-side certs from SignClientPubkey are unaffected.
func (c *CA) IssueClientCert(cn string, validFor time.Duration) (*ClientBundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}
	certPEM, err := c.signPub(cn, &priv.PublicKey, validFor)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	passphrase, err := randomPassphrase()
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("re-parse issued cert: %w", err)
	}
	// LegacyDES (SHA-1 MAC + 3DES-CBC) is the algorithm combo Apple
	// Keychain and iOS profile installer accept; Modern2023's
	// HMAC-SHA-256 + AES-256-CBC combo is rejected with "Unable to
	// decode the provided data" on macOS (verified live 2026-05-23).
	//
	// `WithIterations(2048)` is load-bearing: the stock LegacyDES
	// encoder uses macIterations=1, which macOS Keychain rejects
	// with OSStatus -26276 ("PKCS#12 verify failure") because the
	// MAC iteration count is below its minimum threshold.
	// `openssl pkcs12 -export -legacy` produces files with
	// macIterations=2048 by default for exactly this reason.
	// WithIterations sets BOTH macIterations and
	// encryptionIterations to the value (encryption was already
	// 2048 in stock LegacyDES; this only changes MAC iter).
	//
	// The weaker outer-container algorithms are acceptable here
	// because the passphrase is high-entropy (18 chars over a
	// 56-char alphabet, ~104 bits) and the .p12 is an ephemeral
	// transport artifact — operators delete both .p12 and
	// passphrase as soon as the target device imports.
	p12, err := pkcs12.LegacyDES.WithIterations(2048).Encode(priv, cert, []*x509.Certificate{c.cert}, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encode pkcs12: %w", err)
	}
	return &ClientBundle{CertPEM: certPEM, KeyPEM: keyPEM, P12: p12, Passphrase: passphrase}, nil
}

// SignClientPubkey signs an existing Ed25519 public key into a client
// cert (CN=cn) against the loaded CA. Used by `swe-swe-tunneld mtls-sign`
// for agents reusing their identity.key as the TLS key — the private key
// never leaves the agent host.
func (c *CA) SignClientPubkey(cn string, pub ed25519.PublicKey, validFor time.Duration) ([]byte, error) {
	return c.signPub(cn, pub, validFor)
}

// signPub creates the cert DER for whichever leaf public key the
// caller passes — Ed25519 (agent flow via SignClientPubkey) or
// ECDSA P-256 (browser flow via IssueClientCert). x509.CreateCertificate
// accepts any supported public-key type via the empty interface,
// so the function stays algorithm-agnostic for the leaf while the
// CA's signing key (c.key) remains Ed25519.
func (c *CA) signPub(cn string, pub crypto.PublicKey, validFor time.Duration) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, pub, c.key)
	if err != nil {
		return nil, fmt.Errorf("create client cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 159)
	s, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	return s, nil
}

// randomPassphrase returns 18 chars from an unambiguous alphabet (no 0/O,
// 1/l/I) so passphrases are safe to write down or paste between systems
// without transcription errors.
func randomPassphrase() (string, error) {
	const n = 18
	var buf [n]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("random passphrase: %w", err)
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}
