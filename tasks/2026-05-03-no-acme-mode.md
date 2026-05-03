# Tunneld: --no-acme mode + manual-cert workflow

## Status

**Proposed (2026-05-03).** No code changes yet; this file captures
the scope and rationale.

Companion design discussion: 2026-05-03 chat thread on running
swe-swe-tunneld in environments where the operator doesn't want to
hand a DNS-API token to tunneld but is willing to provision certs
out-of-band.

## Why

Today, swe-swe-tunneld is hardwired to the ACME-via-DNS-01 happy
path. On boot it requires `--acme-email` and a DNS provider
(currently `dnsimple` only); on first Register for a fresh unique it
synchronously calls `lego` to issue `*.{unique}-tunnel.{apex}`.

Three real operator profiles don't fit:

1. **No DNS API access at all.** The apex is at a registrar/DNS host
   whose API isn't supported by lego (or whose API the operator
   doesn't want to grant a token for — for compliance, separation of
   duties, etc.). The wildcard A record is set up manually; certs
   are obtained externally.
2. **Multi-environment handoff.** Cert issuance happens in a
   separate orchestrator (cert-manager / certbot cron / GitHub
   Action) running on a different host with the DNS API token,
   pushing certs into a shared volume that tunneld reads.
3. **Air-gapped / lab.** No public ACME endpoint reachable; operator
   wants tunneld to serve whatever certs are on disk and never
   attempt issuance.

All three want the same thing: tunneld serves pre-provisioned certs
from `{state-dir}/lego/certificates/` and *never* talks to ACME.

This task adds a single `--no-acme` flag that flips that switch.

## Scope

In-scope:

- New flag `--no-acme` (boolean, default `false`). Env:
  `SWE_TUNNEL_NO_ACME=1` for parity with the other env-fallback flags.
- When `--no-acme` is set:
  - `cert.Manager` is not constructed. No DNS-01 provider factory
    call. No `mgr.Ensure` apex-cert ensure-on-boot. No `mgr.Run`
    renewal goroutine. The `--acme-email`, `--dns-provider`,
    `--dns-propagation-timeout`, `--dns-polling-interval`,
    `--acme-staging` flags become inert (ignored if set; not
    required).
  - A new `cert.StaticLoader` (parallel to `cert.Manager`) is built
    instead. It owns the same on-disk layout and exposes the
    `EnsureName` / `GetCertificate` / `LoadAllFromDisk` surface that
    `connectHandler` and the TLS listener call today.
  - `EnsureName(ctx, label)` returns
    `errors.New("cert not provisioned for " + label)` if no cert
    file matching the label exists on disk; nil otherwise.
  - On Register for a missing cert, server sends
    `Deny{reason="cert not provisioned"}`; the client treats this
    as permanent (added to `DenyError.IsPermanent`).
  - SIGHUP, in addition to its existing reload duties (allowlist
    + port policy), re-runs `LoadAllFromDisk` so an operator who
    just dropped a fresh cert can ask tunneld to pick it up
    without restarting.
- When `--no-acme` is unset: behavior is byte-identical to today.
- `--ensure-cert` (admin one-shot) becomes a no-op in `--no-acme`
  mode, exiting with a one-line hint: "issuance is external in
  --no-acme mode; use lego/certbot directly."
- `cmd/swe-swe-tunneld/main.go` switches `certMgr` to a small
  interface (`certEnsurer`-shape, already partially in use in tests)
  so both `*cert.Manager` and `*cert.StaticLoader` are
  drop-in-compatible.
- New `docs/manual-certs.md` documents the operator workflow:
  external lego/certbot invocation, where to drop the resulting
  files, the SIGHUP step, and a renewal recipe.
- `docs/configuration.md` gains a row for `--no-acme`.
- `README.md` gains a one-line link from the Server quickstart to
  `docs/manual-certs.md` for operators who don't want to hand
  tunneld a DNS API token.

Out of scope:

- A built-in CA / self-signed mode where tunneld mints its own
  certs from a local CA. That's a separate task (Option B from the
  discussion); useful for air-gapped lab use but introduces a
  trust-distribution problem this task doesn't want to take on.
- An `fsnotify`-based auto-rescan of the cert directory. SIGHUP is
  enough for now and matches how the allowlist works.
- A "cert not provisioned" pre-flight that proactively walks the
  identity store at boot and warns about missing certs. Useful
  ergonomic but additive — can land later.
- Per-cert validation at SIGHUP time (rejecting malformed PEM
  loudly). `LoadAllFromDisk` already logs and skips bad files; no
  reason to harden further here.
- Integration with `cert-manager` / k8s CRDs. The cert-on-disk
  contract is the integration point; whatever drops files there
  works.

## Implementation sketch

### 1. Refactor: extract a shared cert-store struct.

`internal/cert/store.go` (new): pull the cert-entry / SNI-index /
addEntry / GetCertificate dispatch out of `Manager` into a small
`certStore` struct. Both `Manager` and the new `StaticLoader`
embed/own one. Tests stay green; no behaviour change.

### 2. Add `cert.StaticLoader`.

`internal/cert/static.go` (new, ~80 lines):

```go
type StaticLoader struct {
    store     *certStore       // shared with Manager
    stateDir  string
    apex      string
    logger    *slog.Logger
}

func NewStaticLoader(stateDir, apex string, logger *slog.Logger) *StaticLoader { ... }

func (s *StaticLoader) EnsureName(ctx context.Context, label string) error {
    fqdn := label + "." + s.apex
    if s.store.has(fqdn) {
        return nil
    }
    // Try to load from disk one more time in case the operator
    // dropped a file but hasn't SIGHUPped yet.
    if _, ok, err := s.loadCertFile("_." + fqdn); err == nil && ok {
        return nil
    }
    return fmt.Errorf("cert not provisioned for %s", label)
}

func (s *StaticLoader) GetCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
    return s.store.lookup(ch)  // shared with Manager
}

func (s *StaticLoader) LoadAllFromDisk() (int, error) {
    return s.store.loadAll(s.certDir())  // shared with Manager
}
```

### 3. Wire the flag in `cmd/swe-swe-tunneld/main.go`.

```go
type certEnsurer interface {
    EnsureName(ctx context.Context, label string) error
    GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
    LoadAllFromDisk() (int, error)
}

var noAcme = flag.Bool("no-acme", false, "skip ACME entirely; serve only pre-provisioned certs from {state-dir}/lego/certificates/")

if *noAcme {
    if envNA := os.Getenv("SWE_TUNNEL_NO_ACME"); !flagSet("no-acme") && envNA == "1" {
        *noAcme = true
    }
    var certMgr certEnsurer = cert.NewStaticLoader(*stateDir, *apex, logger)
    logger.Info("ACME disabled (--no-acme); serving pre-provisioned certs only")
    // mgr.Ensure / mgr.Run skipped entirely.
} else {
    // existing path: mgr := cert.New(...); mgr.Ensure; go mgr.Run
}

if n, err := certMgr.LoadAllFromDisk(); ... { ... }
```

The `--acme-email` required-check moves *inside* the non-no-acme
branch, so a `--no-acme` boot doesn't require it.

### 4. Surface "cert not provisioned" as a permanent client deny.

`internal/tunnelclient/client.go` `DenyError.IsPermanent`:

```go
case "bad pubkey", "bad sig", "key_mismatch", "unique mismatch",
    "bad register payload", "bad deregister payload",
    "bad proof payload", "bad proof sig", "signature invalid",
    "cert not provisioned":   // NEW
    return true
```

This makes the supervisor exit fatally on missing-cert rather than
loop-retrying — the cert isn't going to spontaneously appear.

### 5. SIGHUP cert reload.

`cmd/swe-swe-tunneld/main.go`'s existing SIGHUP goroutine adds one
more arm:

```go
case <-hupCh:
    if allow != nil { reloadAllowlistAndRevoke(...) }
    reloadPortPolicy(...)
    if n, err := certMgr.LoadAllFromDisk(); err != nil {
        logger.Warn("cert reload failed", "err", err)
    } else {
        logger.Info("cert reload OK", "count", n)
    }
```

`LoadAllFromDisk` is idempotent — re-loading files already in the
index just refreshes them. Safe to call on every SIGHUP regardless
of mode (so the same behavior applies to ACME-mode operators who
want to manually drop in a cert during an ACME outage).

## Tests

`cmd/swe-swe-tunneld/no_acme_test.go` (new):

- **`TestNoAcme_PreProvisionedCertServed`** — drop a self-signed
  cert into the cert dir, start in `--no-acme` mode, Connect with
  the matching unique, assert Connect succeeds and the SNI returns
  the dropped cert.
- **`TestNoAcme_MissingCertReturnsPermanentDeny`** — start with
  empty cert dir, Connect with a fresh unique, assert
  `Deny{reason="cert not provisioned"}` and that the client sees
  this as a permanent / fatal error (no retry loop).
- **`TestNoAcme_SighupReloadPicksUpNewCert`** — start empty, Connect
  fails permanent-deny, drop cert mid-test, SIGHUP, Connect again,
  assert success.
- **`TestNoAcme_NoEmailRequired`** — boot tunneld with `--no-acme`
  and no `--acme-email`; must succeed (the required-flag check is
  skipped in no-acme mode).

Plus `internal/cert/static_test.go` for the new `StaticLoader`
directly: load-from-disk, missing-cert error shape, SNI dispatch.

## Compatibility

Fully additive. Default behavior unchanged. Existing deployments
that don't pass `--no-acme` keep auto-issuing via DNS-01 exactly as
before.

For operators switching to `--no-acme` mid-flight: they need to drop
the apex `_.{apex}.crt`/`.key` (covering both `{apex}` and
`*.{apex}` for the registration endpoint at `tunnel.{apex}`) PLUS
one `_.{label}-tunnel.{apex}.{crt,key}` per active unique. The
existing on-disk layout produced by `cert.Manager` is the same one
`StaticLoader` reads, so an operator can `--no-acme` a tunneld whose
ACME-mode predecessor already populated the cert dir, and everything
keeps working until the existing certs expire.

## Sequencing

1. **Refactor commit** — extract the shared `certStore` struct from
   `Manager`. No behaviour change. Tests stay green.
2. **Feature commit** — add `cert.StaticLoader`, the `--no-acme`
   flag, the `certEnsurer` interface in main.go, the
   `IsPermanent` arm, the SIGHUP cert-reload arm. Add the four
   `no_acme_test.go` tests plus `static_test.go`.
3. **Docs commit** — `docs/manual-certs.md`, the
   `docs/configuration.md` row, the README link.

Splitting (1) out keeps the diff readable. (2) and (3) can land
together if preferred.

## Coding rules to honor

- ASCII only.
- Direct commits on `main`.
- Loud-failure where applicable: a malformed cert file should still
  log+skip (existing behavior), but a missing cert in `--no-acme`
  mode should produce a clear deny with the exact label so the
  operator knows what to issue.
- All changes ship with extensive unit + e2e tests — `go test -race
  ./...` must remain clean.
- No flag knob we don't need yet: no `--cert-dir` override (the
  existing `{state-dir}/lego/certificates/` location is fine), no
  `--cert-format` toggle, no fsnotify auto-rescan.
