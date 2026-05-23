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
	// Apple Keychain (macOS + iOS) requires an exact PKCS#12
	// algorithm combo, verified by matching what `openssl pkcs12
	// -export -legacy` (the canonical Apple-compatible tool)
	// produces:
	//
	//   MAC:       SHA-1, iterations 2048
	//   Cert bag:  pbeWithSHAAnd40BitRC2-CBC, iterations 2048
	//   Key bag:   pbeWithSHAAnd3-KeyTripleDES-CBC, iterations 2048
	//
	// LegacyRC2 has this exact algorithm split (RC2-40 for the
	// public cert bag, 3DES for the private key bag), but stock
	// uses macIterations=1, which Apple rejects with OSStatus
	// -26276 ("PKCS#12 verify failure"). WithIterations(2048)
	// raises both mac and encryption iter to 2048 across the
	// board.
	//
	// Modern2023 (HMAC-SHA-256 + AES-256) is rejected outright
	// by macOS ("Unable to decode the provided data");
	// LegacyDES (3DES for BOTH bags) decodes via openssl but
	// still fails Apple's verify with -26276 even at iter=2048.
	// Verified live 2026-05-23 through both Keychain Access and
	// `security import`.
	//
	// RC2-40 protects only the cert bag, which contains the
	// public cert (already public information). The private key
	// is protected by 3DES-CBC plus a high-entropy
	// passphrase (18 chars over a 56-char unambiguous alphabet,
	// ~104 bits) -- and the .p12 is an ephemeral transport
	// artifact deleted as soon as the target device imports.
	// Intentionally omit the CA cert from the p12 chain (nil third
	// arg). When the CA is Ed25519-signed, Apple Keychain's X.509
	// parser bails on the import with OSStatus -26276 ("PKCS#12
	// verify failure"), apparently because its strict-mode pre-flight
	// of the chain rejects the Ed25519 signature algorithm OID even
	// when the leaf itself is ECDSA. The leaf+key alone import
	// cleanly. The browser doesn't need the CA cert at import time
	// to present the leaf during a TLS handshake -- the CA only
	// matters for chain verification on the SERVER side, which the
	// daemon has covered via --mtls-ca.
	p12, err := pkcs12.LegacyRC2.WithIterations(2048).Encode(priv, cert, nil, passphrase)
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
