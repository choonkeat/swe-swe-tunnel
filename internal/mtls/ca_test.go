package mtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// TestLoadCABundle_HappyPath: after InitCA writes a fresh CA, LoadCABundle
// reads the resulting ca.pem and returns a populated pool plus a cert count
// of 1.
func TestLoadCABundle_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	pool, n, err := LoadCABundle(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if pool == nil {
		t.Fatal("LoadCABundle returned nil pool")
	}
	if n != 1 {
		t.Fatalf("LoadCABundle cert count = %d, want 1", n)
	}
}

// TestLoadCABundle_MissingFile: pointing at a nonexistent path must return
// an error so the daemon boot fails loudly rather than silently disabling
// mTLS.
func TestLoadCABundle_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadCABundle(filepath.Join(dir, "nope.pem"))
	if err == nil {
		t.Fatal("LoadCABundle on missing file returned nil error")
	}
}

// TestLoadCABundle_MalformedPEM: a file that isn't PEM at all must error,
// not silently produce an empty pool.
func TestLoadCABundle_MalformedPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("this is not a pem file"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := LoadCABundle(path)
	if err == nil {
		t.Fatal("LoadCABundle on garbage file returned nil error")
	}
}

// TestLoadCABundle_ZeroCerts: a PEM file containing only non-cert blocks
// must error. A boot-time "loaded CA bundle with 0 certs" would make every
// handshake fail mysteriously; we'd rather fail at flag-parse time.
func TestLoadCABundle_ZeroCerts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	bogus := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("xx")})
	if err := os.WriteFile(path, bogus, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := LoadCABundle(path)
	if err == nil {
		t.Fatal("LoadCABundle on cert-less bundle returned nil error")
	}
}

// TestInitCA_CreatesECDSACA: a fresh InitCA writes ca.key (0600) and
// ca.pem (0644). The key is ECDSA P-256 and the cert is self-signed with
// the IsCA flag set. ECDSA (not Ed25519) is required: Apple (macOS/iOS)
// clients cannot evaluate an Ed25519 CA signature, so a leaf signed by an
// Ed25519 CA imports but is never presented during a TLS handshake.
func TestInitCA_CreatesECDSACA(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0600 {
		t.Fatalf("ca.key perms = %o, want 0600", mode)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read ca.key: %v", err)
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		t.Fatal("ca.key did not decode as PEM")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse ca.key as PKCS8: %v", err)
	}
	ecKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("ca.key is %T, want *ecdsa.PrivateKey", rawKey)
	}
	if ecKey.Curve != elliptic.P256() {
		t.Fatalf("ca.key curve = %v, want P-256", ecKey.Curve)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	cblk, _ := pem.Decode(certPEM)
	if cblk == nil {
		t.Fatal("ca.pem did not decode as PEM")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		t.Fatalf("parse ca.pem: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("ca.pem missing IsCA")
	}
	if cert.Issuer.String() != cert.Subject.String() {
		t.Fatalf("ca.pem not self-signed: issuer=%s subject=%s", cert.Issuer, cert.Subject)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("ca.pem signature alg = %v, want ECDSAWithSHA256", cert.SignatureAlgorithm)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("ca.pem self-signature: %v", err)
	}
}

// TestInitCA_RefusesOverwrite: running InitCA a second time on the same dir
// without force=true must error, naming the existing file. Otherwise an
// operator who runs the subcommand twice silently rotates their CA and
// invalidates every issued client cert.
func TestInitCA_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("first InitCA: %v", err)
	}
	err := InitCA(dir, false)
	if err == nil {
		t.Fatal("second InitCA without force returned nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "exist") {
		t.Fatalf("error message does not mention existing CA: %v", err)
	}
}

// TestInitCA_ForceOverwrites: with force=true a second InitCA replaces the
// existing CA. The new key bytes must differ from the previous (cryptographic
// rotation, not a no-op).
func TestInitCA_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("first InitCA: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read first ca.key: %v", err)
	}
	if err := InitCA(dir, true); err != nil {
		t.Fatalf("force InitCA: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read second ca.key: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("force InitCA produced identical ca.key bytes")
	}
}

// TestLoadCA_MissingFiles: an empty dir must error. The subcommands rely on
// LoadCA failing loudly if InitCA hasn't been run first.
func TestLoadCA_MissingFiles(t *testing.T) {
	_, err := LoadCA(t.TempDir())
	if err == nil {
		t.Fatal("LoadCA on empty dir returned nil error")
	}
}

// TestIssueClientCert_RoundTrip exercises the full server-side mint flow
// used by `swe-swe-tunneld mtls-issue`. The returned bundle must:
//   - contain non-empty CertPEM, KeyPEM, P12, Passphrase.
//   - decode the p12 with the passphrase to recover the same ECDSA P-256
//     private key that's in KeyPEM.
//   - produce a cert with the requested CN, signed by the CA in dir.
//
// ECDSA P-256 (not Ed25519) is intentional here: macOS / iOS Keychain
// refuse to decode an Ed25519 PKCS#12 with "Unable to decode the
// provided data" -- documented in the mTLS plan's Gotchas section.
// The agent-side flow (SignClientPubkey) is separate and keeps
// Ed25519 -- agents reuse their identity.key, which is Ed25519 by
// design.
func TestIssueClientCert_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	ca, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	bundle, err := ca.IssueClientCert("alice", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	if bundle.CertPEM == nil {
		t.Fatal("bundle.CertPEM is nil")
	}
	if bundle.KeyPEM == nil {
		t.Fatal("bundle.KeyPEM is nil")
	}
	if bundle.P12 == nil {
		t.Fatal("bundle.P12 is nil")
	}
	if bundle.Passphrase == "" {
		t.Fatal("bundle.Passphrase is empty")
	}

	cblk, _ := pem.Decode(bundle.CertPEM)
	if cblk == nil {
		t.Fatal("CertPEM did not decode")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Fatalf("CN = %q, want alice", cert.Subject.CommonName)
	}
	// The whole point of an ECDSA CA: the leaf carries an ECDSA CA
	// signature, which Apple clients can actually evaluate. An Ed25519
	// CA signature (the old behavior) imports but is never presented.
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("leaf signature alg = %v, want ECDSAWithSHA256 (CA must sign with ECDSA)", cert.SignatureAlgorithm)
	}

	pool, _, err := LoadCABundle(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}

	p12key, p12cert, _, err := pkcs12.DecodeChain(bundle.P12, bundle.Passphrase)
	if err != nil {
		t.Fatalf("p12 decode with passphrase: %v", err)
	}
	if p12cert.Subject.CommonName != "alice" {
		t.Fatalf("p12 cert CN = %q, want alice", p12cert.Subject.CommonName)
	}

	pblk, _ := pem.Decode(bundle.KeyPEM)
	if pblk == nil {
		t.Fatal("KeyPEM did not decode")
	}
	rawPEMKey, err := x509.ParsePKCS8PrivateKey(pblk.Bytes)
	if err != nil {
		t.Fatalf("parse KeyPEM: %v", err)
	}
	pemECDSA, ok := rawPEMKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("KeyPEM = %T, want *ecdsa.PrivateKey", rawPEMKey)
	}
	if pemECDSA.Curve != elliptic.P256() {
		t.Fatalf("KeyPEM curve = %v, want P-256", pemECDSA.Curve)
	}
	p12ECDSA, ok := p12key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("p12 key = %T, want *ecdsa.PrivateKey", p12key)
	}
	if !pemECDSA.Equal(p12ECDSA) {
		t.Fatal("KeyPEM and p12 key do not match")
	}
}

// writeLegacyEd25519CA writes a self-signed Ed25519 CA (ca.key + ca.pem)
// into dir, replicating exactly what InitCA produced before the ECDSA
// switch. Used to prove LoadCA stays backward-compatible with the CA
// already deployed in production.
func writeLegacyEd25519CA(t *testing.T, dir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519 CA key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "swe-swe-tunnel mTLS CA (legacy ed25519)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("create legacy CA cert: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal legacy CA key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
		t.Fatalf("write legacy ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatalf("write legacy ca.pem: %v", err)
	}
}

// TestLoadCA_AcceptsLegacyEd25519Root: the production CA predates the ECDSA
// switch and is Ed25519. LoadCA must keep loading it (via crypto.Signer)
// and IssueClientCert must keep minting leaves that chain to it -- so the
// existing iPad/iOS certs keep working while a new ECDSA CA is added
// alongside. The leaf inherits the CA's Ed25519 signature here.
func TestLoadCA_AcceptsLegacyEd25519Root(t *testing.T) {
	dir := t.TempDir()
	writeLegacyEd25519CA(t, dir)

	ca, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA on legacy Ed25519 CA: %v", err)
	}
	if _, ok := ca.key.(ed25519.PrivateKey); !ok {
		t.Fatalf("legacy CA key = %T, want ed25519.PrivateKey", ca.key)
	}

	bundle, err := ca.IssueClientCert("legacy-user", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueClientCert from legacy CA: %v", err)
	}
	cblk, _ := pem.Decode(bundle.CertPEM)
	if cblk == nil {
		t.Fatal("CertPEM did not decode")
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.SignatureAlgorithm != x509.PureEd25519 {
		t.Fatalf("leaf signature alg = %v, want PureEd25519 (legacy CA signs Ed25519)", cert.SignatureAlgorithm)
	}
	pool, _, err := LoadCABundle(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("legacy-CA leaf does not chain to CA: %v", err)
	}
}

// TestSignClientPubkey_HappyPath exercises the mtls-sign flow used by
// agents. We bring our own Ed25519 keypair, hand the public half to the CA,
// and assert the resulting cert wraps exactly that pubkey and chains to the
// CA. The private key never leaves the test (mirroring an agent host
// keeping identity.key on disk).
func TestSignClientPubkey_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := InitCA(dir, false); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	ca, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen pubkey: %v", err)
	}

	certPEM, err := ca.SignClientPubkey("agent-prod-01", pub, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("SignClientPubkey: %v", err)
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("certPEM did not decode")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "agent-prod-01" {
		t.Fatalf("CN = %q, want agent-prod-01", cert.Subject.CommonName)
	}
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("cert pubkey = %T, want ed25519.PublicKey", cert.PublicKey)
	}
	if !certPub.Equal(pub) {
		t.Fatal("cert pubkey does not match input pubkey")
	}

	pool, _, err := LoadCABundle(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatalf("LoadCABundle: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("signed cert does not chain to CA: %v", err)
	}
}
