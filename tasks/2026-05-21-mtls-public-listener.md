# Tunneld: mTLS for browser + agent connections (opt-in, single listener)

## Status

Phase 1 landed. Surface in the codebase:

- `internal/mtls/` — Ed25519 CA + client-cert toolkit
  (`InitCA` / `LoadCA` / `IssueClientCert` /
  `SignClientPubkey` / `LoadCABundle`) plus unit tests.
- `cmd/swe-swe-tunneld/` — `--mtls-ca` flag, SIGHUP-reloadable
  CA pool via `tls.Config.GetConfigForClient`,
  `injectClientIdentityHeaders` in `route()`,
  peer-cert-pubkey-vs-Register-pubkey defence-in-depth check in
  `handleRegister`, three subcommands (`mtls-init`,
  `mtls-issue`, `mtls-sign`).
- `cmd/swe-swe-tunnel/` — `--client-cert` flag (paired against
  the in-memory `identity.key`).
- `internal/tunnelclient/` — `isPermanentTLSError` classifier
  wired into the supervisor's retry policy.
- `docs/mtls.md` — operator workflow, known limitations
  (TLS-intercepting middleboxes, Apple Keychain quirks),
  pubkey file formats, revocation roadmap.
- `.claude/commands/generate-mtls-{p12-for-device,crt-for-client}.md`
  — operator-facing slash commands that stage artifacts under
  `./generated/`.

The `IssueClientCert` algorithm choices (ECDSA P-256 leaf,
LegacyRC2 PKCS#12 encoder with `WithIterations(2048)`, no CA
bundled in the chain) are dictated by Apple Keychain's PKCS#12
parser — see `docs/mtls.md` "Known limitations".

Phase 2 (fingerprint denylist for revocation) is unstarted —
see "Out of scope" below.

Companion design discussion at `docs/research/mtls-design.html`
(open with `npx @choonkeat/md-serve` and visit
`/docs/research/mtls-design.html` for the rendered mermaid
sequence diagrams).

## Why

Today the public listener of `swe-swe-tunneld` is open: anything that
resolves to a registered tunnel hostname can hit the proxy. The agent
control plane (`/v1/connect`) is gated by an Ed25519 pubkey allowlist,
but the proxied apps behind the tunnel have no edge-level
authentication — they get whatever auth their own code implements,
which for the typical "expose my dev server to a teammate" use case is
nothing.

Operators have asked for an mTLS option on the public listener so the
daemon refuses connections that don't present a client certificate
signed by a CA the operator trusts. Three real-world use cases:

1. **Personal / hobby deployments.** Operator wants their tunnel
   reachable only from their own laptop + phone. mTLS with a tiny
   self-signed CA is much simpler than maintaining a reverse-proxy +
   auth stack in front.
2. **Team / internal deployments.** A handful of named humans need
   browser access; admin issues each a `.p12`. Lifecycle is "issue
   when someone joins, let it expire when they leave."
3. **Enterprise pickier-than-thou.** Existing internal CA is
   authoritative; tunneld must trust certs signed by that CA without
   tunneld doing the issuance.

All three want the same daemon surface: a `--mtls-ca` flag pointing
at a CA bundle. Cases (1) and (2) additionally want a built-in
"mint your own CA" subcommand so they don't have to learn `openssl`
or `cfssl`. Case (3) brings its own CA file.

The feature is **fully opt-in** — until `--mtls-ca` is set on a
given daemon, behaviour is byte-identical to today. The production
tunnel at `tunnel.example.com` is unaffected unless the operator
explicitly turns mTLS on.

## Scope

In-scope (Phase 1):

- New flag `--mtls-ca <path>` (boolean-coerced: presence enables
  mTLS; absence keeps today's behaviour). Env fallback
  `SWE_TUNNEL_MTLS_CA`.
- New flag `--mtls-ca-dir <path>` (default `{state-dir}/mtls/`)
  pointing at where the self-mint mode reads/writes the CA key+cert.
- When `--mtls-ca` is set, the single public listener gets
  `ClientAuth = RequireAndVerifyClientCert` and a `ClientCAs` pool
  populated from the PEM bundle at that path. The handshake fails
  at the TLS layer for any browser or agent that doesn't present a
  verified client cert.
- Both `/v1/connect` (agent registration) and `/` (browser proxy
  traffic) require mTLS. The Ed25519 pubkey allowlist on
  `/v1/connect` is **unchanged** — both gates apply in series
  (defence in depth). One TLS listener, two layered auth checks.
- Two new subcommands on the daemon binary for ease-of-use mode:
  - `swe-swe-tunneld mtls-init` — generate a self-signed CA into
    `--mtls-ca-dir` (`ca.key` + `ca.pem`). Idempotent: refuses to
    overwrite an existing CA unless `--force` is passed.
  - `swe-swe-tunneld mtls-issue --cn <name> [--days N]` —
    server-side mint of a client keypair + signed cert,
    bundled into `<name>.p12` (passphrase-protected, passphrase
    printed to stdout once). For browser users who can't easily BYO
    keys.
  - `swe-swe-tunneld mtls-sign --pubkey <path> --cn <name> [--days N]`
    — sign an existing public key into a client cert (no key
    minting; agent keeps its existing Ed25519 keypair). Output:
    `<name>.crt` on stdout or to `-o`. For agent hosts that reuse
    `identity.key` as their TLS key. RFC 8410 — Ed25519 X.509 certs
    are well supported by Go's `crypto/x509`.
- Identity propagation to upstream apps: on every accepted proxied
  request, the route handler strips any inbound `X-Client-*` headers
  and re-injects:
  - `X-Client-CN` — Subject CN from the verified peer cert
  - `X-Client-Cert-Fingerprint` — `sha256:<hex>` of the DER cert
- New flag on `swe-swe-tunnel` (the agent CLI):
  - `--client-cert <pem-path>` (env `SWE_TUNNEL_CLIENT_CERT`)
  - When set, the agent loads the cert with
    `tls.X509KeyPair(certPEM, identityKeyPEM)` — i.e. **the agent's
    existing `identity.key` is the TLS private key**. One key,
    two uses (TLS CertificateVerify + Register-frame Ed25519 sig).
    No new private key on the agent host.
- Documentation:
  - `docs/mtls.md` — operator workflow (init, issue/sign, deploy,
    install in browser, agent flag).
  - `docs/configuration.md` — new rows for `--mtls-ca` and
    `--mtls-ca-dir`.
  - `docs/research/mtls-design.html` — already written (this PR
    just promotes its decisions; no further changes).
  - `README.md` — one-line link from the Server quickstart to
    `docs/mtls.md`.

In-scope (Phase 2, separate PR after Phase 1 lands):

- Fingerprint denylist for revocation. New file
  `{--mtls-ca-dir}/revoked.txt` (one `sha256:hex` per line).
  Daemon loads on boot, reloads on SIGHUP. `route()` rejects
  requests where the peer cert's fingerprint is in the denylist
  with a 401. `swe-swe-tunneld mtls-revoke <fingerprint-or-cert-path>`
  appends to the file and sends SIGHUP.

Out of scope:

- Per-host or SNI-conditional mTLS policy. The whole daemon is
  mTLS-on or mTLS-off. Mixed deployments run two daemons.
- Friendly 403 fallback for missing client cert. We use
  `RequireAndVerifyClientCert` (strict TLS layer rejection); the
  browser shows its native cert-error page. Less pretty but
  unambiguously secure — no pre-auth attack surface in our Go HTTP
  stack.
- CSR-based browser enrollment (private key generated client-side,
  CSR submitted to CA, signed cert returned). Useful for true
  enterprise PKI but needs an enrollment portal. Deferred until an
  enterprise asks.
- OCSP / CRL / online revocation. Phase 2 file-based denylist
  covers the practical use case; full PKI revocation infrastructure
  is large and not justified yet.
- Automatic cert distribution to agent hosts. Operators ship
  `.crt` files via the same out-of-band mechanism they already use
  for pubkey allowlist entries.
- Migrating production. This task lands the feature behind a flag;
  enabling mTLS on the live tunnel at `tunnel.example.com` is a
  follow-up operator decision and not part of the code change.

## Decisions captured in chat

| Question | Decision | Rationale |
|----------|----------|-----------|
| Granularity | Per *daemon instance*. | Avoids SNI-conditional logic. Mixed deployments run two daemons. |
| Trust anchor | Support both BYO CA and self-mint CA. | Hobbyist ergonomics + enterprise compatibility from one binary. |
| Failure mode | Strict TLS rejection (`RequireAndVerifyClientCert`). | Smallest pre-auth surface; no chance of a future endpoint forgetting the cert check. |
| Identity forwarding | Forward `X-Client-CN` + `X-Client-Cert-Fingerprint` headers. | Free to compute; valuable to backends; strip inbound copies to prevent spoofing. |
| Scope on ports | Single listener; both `/` and `/v1/connect` require mTLS. | One TLS config to reason about; defence in depth (Ed25519 still applies on /v1/connect). |
| Agent key reuse | Agent's `identity.key` IS the TLS key (Ed25519 X.509). | One private key per agent. No new on-disk material. |
| Revocation | Fingerprint denylist file in Phase 2. | Covers practical "user left, kill their access" without CRL/OCSP weight. |

## Sequence diagrams

See `docs/research/mtls-design.html` for the rendered version. ASCII
summaries:

**Enrollment — browser user (Alice):**
```
operator → swe-swe-tunneld mtls-init           ⇒ ./mtls/ca.key + ca.pem
operator → swe-swe-tunneld mtls-issue --cn alice ⇒ alice.p12 + passphrase
operator → alice (out-of-band)                 ⇒ p12 + passphrase
alice    → browser/keychain                    ⇒ import p12
operator → daemon restart with --mtls-ca ./mtls/ca.pem
```

**Enrollment — agent host:**
```
operator → swe-swe-tunneld mtls-sign --pubkey agent.pub --cn agent-01 ⇒ agent-01.crt
operator → agent host                                                  ⇒ scp agent-01.crt
operator → agent restart with --client-cert /etc/swe-swe-tunnel/agent-01.crt
                                              (--identity-key stays the same)
```

**Browser connect:**
```
browser → daemon: TLS ClientHello (SNI=app.example.com)
daemon  → browser: ServerHello + LE cert + CertificateRequest(CAs=[ca.pem])
browser → user: cert picker
user    → browser: select alice
browser → daemon: Certificate(alice.crt) + CertificateVerify(alice.key)
daemon: verify alice.crt against ClientCAs pool
        check fingerprint against denylist (Phase 2)
   if OK:
        handshake complete → HTTP GET / → route() strips X-Client-* →
        route() sets X-Client-CN=alice + X-Client-Cert-Fingerprint=sha256:… →
        proxy upstream
   else:
        TLS alert (bad_certificate) → connection closed → native browser error
```

**Agent connect:**
```
agent → daemon: TLS ClientHello (SNI=tunnel.example.com)
daemon → agent: ServerHello + LE cert + CertificateRequest(CAs=[ca.pem])
agent → daemon: Certificate(agent-01.crt) + CertificateVerify(identity.key)
daemon: verify agent-01.crt against ClientCAs pool
        if OK: handshake complete
agent → daemon: HTTP POST /v1/connect (Upgrade)
daemon → agent: 101 Switching Protocols + yamux stream-1
agent → daemon: Register{unique, ed25519 sig over payload with identity.key}
daemon: Ed25519 sig verifies (same key as cert)
        pubkey ∈ allowlist (existing check)
        ⇒ session established
```

## Implementation sketch

### 1. Refactor: extract a CA helper.

New package `internal/mtls/`, one file `ca.go`:

```go
// LoadCABundle reads a PEM file and returns an x509.CertPool suitable
// for use as tls.Config.ClientCAs. Fails loudly if the file is missing
// or contains zero parsable certs.
func LoadCABundle(path string) (*x509.CertPool, error)

// InitCA writes a fresh self-signed Ed25519 CA into dir/ca.key + ca.pem.
// Returns an error if either file already exists (unless force=true).
func InitCA(dir string, force bool) error

// IssueClientCert mints a fresh Ed25519 keypair, signs a cert for it
// against the CA in dir, returns the cert + key as PEM and a p12
// bundle protected by a random passphrase. Output: certPEM, keyPEM,
// p12Bytes, passphrase, error.
func IssueClientCert(dir, cn string, validFor time.Duration) (cert, key, p12 []byte, passphrase string, err error)

// SignClientPubkey signs an existing Ed25519 public key into a client
// cert against the CA in dir. Used by agents that want to reuse their
// existing identity.key as the TLS key.
func SignClientPubkey(dir, cn string, pub ed25519.PublicKey, validFor time.Duration) (certPEM []byte, err error)
```

p12 packaging uses `software.sslmate.com/src/go-pkcs12` (already a
small, well-maintained dep; check `go.mod` to confirm if it's already
present).

Unit tests in `internal/mtls/ca_test.go`:
- `LoadCABundle` happy path, missing file, malformed PEM, zero-cert
  bundle.
- `InitCA` happy path, refuses-to-overwrite, `force=true` override,
  generated cert is parseable + self-signed + Ed25519.
- `IssueClientCert` happy path: parseable cert, chains to the CA,
  p12 round-trips via `pkcs12.Decode`, CN matches.
- `SignClientPubkey` happy path: cert's public key matches the input
  pubkey, chains to the CA, cert is Ed25519 not RSA.

### 2. Daemon flag + TLS-config wiring.

`cmd/swe-swe-tunneld/main.go`:

```go
var (
    mtlsCA    = flag.String("mtls-ca", "", "PEM bundle of CAs to trust for client certs; empty disables mTLS")
    mtlsCADir = flag.String("mtls-ca-dir", "", "directory holding self-mint CA + revocation list (default {state-dir}/mtls)")
)
```

After flag parsing (around the existing env-fallback block), default
`mtlsCADir` to `filepath.Join(*stateDir, "mtls")` if unset.

In the TLS-config construction at `main.go:329-335`:

```go
tlsCfg := &tls.Config{
    GetCertificate: certMgr.GetCertificate,
    MinVersion:     tls.VersionTLS12,
}
if *mtlsCA != "" {
    pool, err := mtls.LoadCABundle(*mtlsCA)
    if err != nil {
        logger.Error("load mTLS CA bundle", "path", *mtlsCA, "err", err)
        os.Exit(1)
    }
    tlsCfg.ClientCAs = pool
    tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
    logger.Info("mTLS enabled", "ca", *mtlsCA, "pool_size", certPoolSize(pool))
} else {
    logger.Info("mTLS disabled (no --mtls-ca)")
}
srv := &http.Server{ Addr: *listen, Handler: mux, TLSConfig: tlsCfg, ... }
```

`certPoolSize` is a one-liner that introspects via reflection or a
parallel counter we maintain in `LoadCABundle`. The latter is
cleaner; have `LoadCABundle` return `(*x509.CertPool, int, error)`.

### 3. Header injection in `route()`.

`cmd/swe-swe-tunneld/tunnel.go:793-826`. Today the route handler
ends with `ts.proxy.ServeHTTP(w, r)`. Insert before that call:

```go
if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
    peer := r.TLS.PeerCertificates[0]
    r.Header.Del("X-Client-CN")
    r.Header.Del("X-Client-Cert-Fingerprint")
    r.Header.Set("X-Client-CN", peer.Subject.CommonName)
    fp := sha256.Sum256(peer.Raw)
    r.Header.Set("X-Client-Cert-Fingerprint", "sha256:"+hex.EncodeToString(fp[:]))
}
```

We *also* strip the headers when mTLS is disabled, just in case an
operator runs an unauth daemon behind a fronting LB that already
sets these headers — strip-then-set is consistent regardless of
mode.

Pull the strip-then-inject into a helper:

```go
func injectClientIdentityHeaders(r *http.Request) {
    r.Header.Del("X-Client-CN")
    r.Header.Del("X-Client-Cert-Fingerprint")
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
        return
    }
    peer := r.TLS.PeerCertificates[0]
    r.Header.Set("X-Client-CN", peer.Subject.CommonName)
    fp := sha256.Sum256(peer.Raw)
    r.Header.Set("X-Client-Cert-Fingerprint", "sha256:"+hex.EncodeToString(fp[:]))
}
```

### 4. Subcommands `mtls-init` / `mtls-issue` / `mtls-sign`.

Today `cmd/swe-swe-tunneld/main.go` is a single `func main()` with
flags. Subcommand dispatch is grafted in by checking `os.Args[1]`
before flag parsing — same shape as `--ensure-cert` today (a one-shot
mode that exits before the long-running listener loop).

Layout: a small `subcmds.go` in the same package:

```go
// runSubcommand returns (exitCode, handled).
// handled=true means main() should exit; false means fall through to
// the normal daemon path.
func runSubcommand(args []string, stateDir string, logger *slog.Logger) (int, bool) {
    if len(args) < 2 { return 0, false }
    switch args[1] {
    case "mtls-init":
        return runMtlsInit(args[2:], stateDir, logger), true
    case "mtls-issue":
        return runMtlsIssue(args[2:], stateDir, logger), true
    case "mtls-sign":
        return runMtlsSign(args[2:], stateDir, logger), true
    }
    return 0, false
}
```

Each subcommand uses `flag.NewFlagSet` to parse its own args, calls
into `internal/mtls/`, writes output to stdout / `-o`. No daemon
state involved.

### 5. Agent CLI: `--client-cert` flag.

`cmd/swe-swe-tunnel/main.go`, around the existing `--insecure`
handling at line 88-91:

```go
var (
    clientCert = flag.String("client-cert", "", "path to client cert PEM for mTLS (key comes from --identity-key)")
)

// after flag.Parse + env fallbacks:
var tlsCfg *tls.Config
if *clientCert != "" {
    certPEM, err := os.ReadFile(*clientCert)
    if err != nil { log.Fatalf("read client cert: %v", err) }
    keyPEM, err := os.ReadFile(*identityKey)
    if err != nil { log.Fatalf("read identity key: %v", err) }
    cert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil { log.Fatalf("build client cert: %v", err) }
    tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
}
if *insecure {
    if tlsCfg == nil { tlsCfg = &tls.Config{} }
    tlsCfg.InsecureSkipVerify = true //nolint:gosec // user opted in
}
```

The existing `identity.key` is now load-bearing in two places: it
signs Register frames *and* backs the TLS keypair. That's the whole
point of using Ed25519 X.509 — one keypair, two uses, zero extra
private-key files on disk.

Env fallback: `SWE_TUNNEL_CLIENT_CERT`. No `--client-key` flag — the
key always comes from `--identity-key`.

### 6. Error classification for permanent-deny.

`internal/tunnelclient/client.go`'s `Connect` wraps TLS handshake
errors as `tls handshake: %w`. The supervisor's retry classifier
should treat `bad_certificate`, `certificate_required`, and
`unknown_ca` TLS alerts as permanent — there's nothing the
supervisor can do without a human swapping out the cert file.

Concrete check (in `internal/tunnelclient/client.go` or run.go,
whichever owns retry policy):

```go
func isPermanentTLSError(err error) bool {
    var alert tls.RecordHeaderError
    if errors.As(err, &alert) { /* …examine */ }
    msg := err.Error()
    return strings.Contains(msg, "bad certificate") ||
           strings.Contains(msg, "certificate required") ||
           strings.Contains(msg, "unknown certificate authority") ||
           strings.Contains(msg, "tls: certificate required")
}
```

Hook it into the existing `DenyError.IsPermanent` neighbour — the
supervisor in `run.go` already has a "permanent vs transient"
branch; add a TLS arm.

## Tests

### `internal/mtls/ca_test.go` (Phase 1)

Already enumerated in §1.

### `cmd/swe-swe-tunneld/mtls_test.go` (Phase 1)

- `TestMTLS_BrowserGetWithoutCertRejected` — start daemon with
  `--mtls-ca`, dial public listener over TLS with **no** client cert,
  assert handshake fails (Go returns `remote error: tls: bad
  certificate` or similar).
- `TestMTLS_BrowserGetWithValidCertProxies` — same setup, dial with
  a cert signed by the configured CA, expect 200 + body from a stub
  upstream, expect `X-Client-CN` to be set on the upstream-observed
  request.
- `TestMTLS_BrowserGetWithWrongCAFails` — dial with a cert signed
  by a *different* CA, assert handshake fails.
- `TestMTLS_HeadersStripped` — client sends inbound `X-Client-CN:
  attacker`, daemon should strip and re-inject the verified value.
  Stub upstream asserts the received CN matches the actual peer
  cert.
- `TestMTLS_AgentConnectWithoutCertRejected` — call
  `/v1/connect` over TLS with no client cert, assert handshake
  fails (same as browser case).
- `TestMTLS_AgentConnectWithValidCertSucceeds` — agent presents
  cert backed by the *same* Ed25519 key as `identity.key`, expect
  TLS to succeed, Ed25519 register-sig to succeed, session to
  establish, end-to-end stream-1 control roundtrip.
- `TestMTLS_AgentConnectWithDifferentCertAndKeyFails` — pathological
  case: agent presents cert backed by key A, signs Register with
  key B. TLS succeeds, but the daemon's Register Ed25519 check
  fails — verify the daemon denies with the existing
  `register denied: not_authorized` shape.

### `cmd/swe-swe-tunneld/mtls_subcmd_test.go` (Phase 1)

- `TestMtlsInit_CreatesCA` — temp dir, run `mtls-init`, assert
  `ca.key` (0600) + `ca.pem` exist + parse as Ed25519 + self-signed.
- `TestMtlsInit_RefusesOverwrite` — running twice fails on second
  call. With `--force` succeeds.
- `TestMtlsIssue_RoundTrip` — `mtls-init` then `mtls-issue --cn
  alice`; decode the printed p12 with the printed passphrase;
  verify cert chains to ca.pem; verify cert subject CN = alice.
- `TestMtlsSign_ReusesPubkey` — `mtls-init` then create an
  Ed25519 keypair on disk; `mtls-sign --pubkey alice.pub --cn alice`
  produces a cert whose public key matches alice.pub.

### Existing test impact

Every existing daemon e2e test (`e2e_test.go`, `register_test.go`,
`preregister_test.go`, `connect_cancel_test.go`,
`deregister_test.go`, `issuance_grace_test.go`, `no_acme_test.go`,
`run_e2e_test.go`, `handler_test.go`) currently constructs the
daemon **without** `--mtls-ca`. That's the unaffected path. They
all keep working byte-identically.

We do **not** rewrite the existing tests to run a second
mTLS-on variant of every assertion — that's massive churn for low
return. The new `mtls_test.go` file is the dedicated mTLS surface.

### Phase 2 test additions

`cmd/swe-swe-tunneld/mtls_revoke_test.go`:
- `TestMtlsRevoke_FingerprintInDenylistRejected` — issue cert,
  add fingerprint to `revoked.txt`, SIGHUP, dial → 401.
- `TestMtlsRevoke_SighupReload` — start with denylist empty,
  dial OK, append fingerprint, SIGHUP, next dial 401.
- `TestMtlsRevoke_BootLoad` — boot with non-empty denylist, dial
  with a revoked cert, 401.

## Compatibility

Fully additive. Default behaviour unchanged. The production tunnel
at `tunnel.example.com` is unaffected until `--mtls-ca` is set on
its daemon.

For existing deployments adopting mTLS:

1. Generate or supply a CA. Either run `swe-swe-tunneld mtls-init`
   (writes to `{state-dir}/mtls/`), or copy in an existing
   `ca.pem`.
2. For every browser user, run `mtls-issue --cn <name>`, distribute
   the resulting `.p12` + passphrase out-of-band, user imports into
   keychain.
3. For every agent host, run `mtls-sign --pubkey <agent.pub> --cn
   <agent-name>`, scp the resulting `.crt` to the agent host,
   update the agent's launch command to add `--client-cert
   /path/to/agent.crt`. The agent's existing `identity.key`
   stays untouched — it now does double duty.
4. Restart the daemon with `--mtls-ca /path/to/ca.pem`. From this
   moment, every browser and agent must present a valid cert.

Order matters: do (1), (2), (3) **before** (4). Otherwise the
daemon flip cuts off all existing agents until they're re-deployed
with the cert flag.

## Sequencing

Four commits, each independently reviewable / revertable. Numbered
1.x = Phase 1, 2.x = Phase 2 (separate PR).

**Discipline within each commit (TDD):**
1. Baseline: `go test -race ./...` is green on the branch tip before
   any change. Confirms test infrastructure works.
2. Write the new tests (red) for that commit's scope. They must fail
   for the right reason — "undefined: mtls.LoadCABundle" not "import
   error" or "panic in setup."
3. Implement the production code to turn the tests green.
4. **No edits to test code after red→green.** If a test needs to
   change shape, the production code is wrong and the implementation
   step continues. If the test was wrong, revert and rewrite the test
   *as its own change*, not bundled with implementation.
5. `go test -race ./...` green again. Commit.

1. **`internal/mtls/` package + tests.** No wiring yet. Just the
   CA helpers (LoadCABundle, InitCA, IssueClientCert,
   SignClientPubkey) and their unit tests. Verifies the `go-pkcs12`
   dep round-trips and Ed25519 X.509 certs work end-to-end before
   anything else lands.

2. **Daemon flag + TLS-config wiring + header injection.** Adds
   `--mtls-ca` / `--mtls-ca-dir`, the `tls.Config.ClientCAs` /
   `ClientAuth` plumbing, the `injectClientIdentityHeaders` helper,
   the `mtls_test.go` tests. Subcommands not yet present —
   operator uses BYO CA only at this point. Smallest meaningful
   shippable surface.

3. **Subcommands `mtls-init` / `mtls-issue` / `mtls-sign`.** Adds
   `subcmds.go` dispatch, the three subcommands, the
   `mtls_subcmd_test.go` tests. After this commit, the
   ease-of-use mode is complete.

4. **Agent CLI flag + permanent-deny classification + docs.** Adds
   `--client-cert` to `swe-swe-tunnel`, the
   `isPermanentTLSError` arm in the supervisor, `docs/mtls.md`,
   `docs/configuration.md` rows, README link. End-to-end agent
   path is exercised by the existing `TestMTLS_AgentConnectWith*`
   tests from commit 2.

Phase 2 (later PR):

5. **Fingerprint denylist.** Adds `mtls-revoke` subcommand,
   `revoked.txt` load on boot + SIGHUP reload, the denylist check
   in `route()` (and the equivalent check at the start of
   `handleRegister` for the agent path). Tests in
   `mtls_revoke_test.go`.

Commits 1-4 can land back-to-back over a single day; (5) waits
until someone actually asks for revocation (or hits the use case).

## Coding rules to honor

- ASCII only in source.
- Direct commits on `main` per project convention; each commit
  green on `go test -race ./...`.
- Loud-failure on operator errors: `LoadCABundle` fails the boot
  with a clear error message; a malformed `--mtls-ca` value
  shouldn't silently produce a permissive daemon.
- Strip-then-set for `X-Client-*` headers — never trust inbound
  copies even in mTLS-disabled mode.
- No fsnotify-based auto-reload of the CA bundle. SIGHUP is the
  reload primitive across this codebase (allowlist, port policy,
  certs); add a CA-bundle arm to the existing SIGHUP goroutine in
  the same commit that wires `--mtls-ca`. Failure to reload (file
  vanished, parse error) logs a warning and keeps the old pool
  in place — same shape as `reloadAllowlistAndRevoke`.
- No knob we don't yet need: no `--mtls-required` toggle (presence
  of `--mtls-ca` IS the toggle), no `--mtls-cipher-suites`, no
  per-host policy, no CRL/OCSP.
- Subcommands write secrets (passphrase, key material) to stdout
  exactly once and never to logs. No env-var leakage of
  passphrases.
- `go-pkcs12` is a hard new dep. Vet it (single-purpose, low LOC,
  active maintenance) before adding to `go.mod`. If we're
  uncomfortable adding it, fall back to writing the p12 with
  `software.sslmate.com/src/go-pkcs12/internal` shapes or
  emitting separate `.crt` + `.key` files and letting the user
  package them with `openssl pkcs12 -export`. p12 is nicer UX but
  not load-bearing.
