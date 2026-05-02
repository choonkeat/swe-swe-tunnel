# Server-side LE issuance grace window

## Status

**Proposed (2026-05-02).** Companion to
`tasks/2026-05-02-connect-ctx-cancel.md` (the client-side Ctrl-C fix).

## Why

Empirical motivator from a 2026-05-02 dev session: an operator
deployed with `SWE_TUNNEL_UNIQUE=alice-2m94n` — a typo of
`alice-fixed`. The server treated the typo as a fresh unique:

1. Allowed it past the per-pubkey rate limit (consuming a slot).
2. Kicked off Let's Encrypt DNS-01 issuance for
   `*.alice-2m94n-tunnel.example.com` immediately.
3. ~2m 37s later, returned RegisterOK on a hostname the operator
   never wanted.

By the time the operator realized the typo, the LE slot was burned
and the per-pubkey rate-limit budget had a chunk taken out of it for
the wrong name. Each subsequent typo would compound the cost — and
LE has hard weekly per-account / per-domain caps (50 issuances /
week per account, 5 duplicate-cert / week per FQDN set).

The client-side Ctrl-C fix (companion task) makes the *client* exit
cleanly, but the *server* still sees the connection drop mid-issuance
and the in-flight LE call still completes (or fails noisily). Either
way the slot is gone.

A short server-side grace window between accepting the Register and
starting LE issuance gives the operator a moment to spot the typo in
the client log line ("awaiting RegisterOK from server") and Ctrl-C —
at which point the server detects the disconnect during the grace,
refunds the consumed rate-limit tokens, and never touches ACME.

## Scope

In-scope:

- A `var issuanceGrace = 5 * time.Second` constant in
  `cmd/swe-swe-tunneld/tunnel.go`. `var` so tests can shorten or
  zero it via TestMain.
- A bridge in `connectHandler` that ties yamux session close
  (`sess.CloseChan()`) to the request ctx. Hijacked connections do
  not propagate TCP-close into `r.Context()` — the http server
  detaches its tracking after Hijack — so without this bridge the
  server cannot tell that the client just hung up. The bridge is a
  one-line helper goroutine that calls cancel on session close.
- A `select { <-graceTimer.C; <-ctx.Done(): … }` insertion in
  `handleRegister` between the per-pubkey rate-limit check and
  `EnsureName`. On `ctx.Done()` during grace: refund both rate-limit
  buckets, log "register aborted by client during issuance grace",
  return without calling EnsureName.
- A `TestMain` in `cmd/swe-swe-tunneld` that sets
  `issuanceGrace = 0` for the whole package by default; new
  grace-specific tests opt back in to a real grace.
- Tests for both arms (proceed vs bail) and a rate-limit refund check.

Out of scope (worth follow-ups, not this commit):

- A flag/env to tune the grace window per operator. Default of 5s is
  almost always right — operators who want zero grace can wait
  for a future flag, and operators who want longer should probably
  be using a separate "preview / staging" provisioning path.
- A "grace started" frame to inform the client. Would require a new
  control frame type. The client's "awaiting RegisterOK" log line is
  already the user-visible signal that something is happening; that's
  enough for now.
- Per-IP grace (longer for repeat offenders, etc.). The ratelimit
  budget already captures that signal at a different layer.

## Implementation sketch

`cmd/swe-swe-tunneld/tunnel.go`:

```go
var issuanceGrace = 5 * time.Second

// In connectHandler, after sess is built and stream is accepted:
ctx, cancelOnSessClose := context.WithCancel(r.Context())
defer cancelOnSessClose()
go func() {
    select {
    case <-sess.CloseChan():
        cancelOnSessClose()
    case <-ctx.Done():
    }
}()

// Pass that ctx into handleRegister (existing call).
```

In `handleRegister`'s `errors.Is(err, identity.ErrNotFound)` arm,
between the per-pubkey rate-limit check and `EnsureName`:

```go
if issuanceGrace > 0 {
    graceTimer := time.NewTimer(issuanceGrace)
    select {
    case <-graceTimer.C:
        // proceed
    case <-ctx.Done():
        graceTimer.Stop()
        if ipLimiter != nil { ipLimiter.CancelLatest(ipKey) }
        if pubkeyLimiter != nil { pubkeyLimiter.CancelLatest(string(pub)) }
        logger.Info("register aborted by client during issuance grace",
            "unique", reg.Unique, "remote", remoteAddr,
            "pubkey_fp", fingerprint(pub), "reason", ctx.Err())
        return registerResult{}, false
    }
}
```

The `if issuanceGrace > 0` gate makes the test-default of zero a
clean no-op — the grace window simply doesn't exist when set to zero,
so all the existing pre-fix tests pass without modification.

## Tests

`cmd/swe-swe-tunneld/issuance_grace_test.go` (new file):

- **`TestIssuanceGrace_ClientBailsDuringGrace`** — start the server
  with `issuanceGrace = 200ms` and a `slowEnsurer` that would take
  forever (or assert it's never called via a counter). Connect with
  a fresh unique, then close the client conn ~50ms in. Assert:
  - server returns from handleRegister without invoking
    `slowEnsurer.EnsureName`
  - per-pubkey rate-limit budget is back to its pre-attempt level
    (CancelLatest fired)
  - per-IP rate-limit budget is back too

- **`TestIssuanceGrace_HappyPathProceedsAfterGrace`** — same setup,
  but client stays connected through the grace. Assert:
  - server calls `EnsureName` (counter goes up)
  - client receives `RegisterOK`
  - rate-limit budgets remain consumed (no spurious refund)

- **`TestIssuanceGrace_ZeroDisablesEntirely`** — `issuanceGrace = 0`,
  inject a "ctx already canceled" path. Server must NOT bail; the
  grace window doesn't exist when zero. (Regression gate against an
  accidental future "0 means infinite" mistake.)

The first two tests need the `issuanceGrace` override at non-zero
because the package's `TestMain` defaults it to zero.

## Compatibility

Fully additive on the wire — no protocol change, no new control
frame, no client-visible behavior unless the operator Ctrl-Cs during
the first 5 seconds of a fresh-unique Connect.

For an operator on the canonical happy path (correct unique, stays
connected), the only observable effect is that fresh-unique Connects
take an extra ~5s before LE starts. LE itself still takes 1-3 minutes
during DNS-01 propagation, so the relative cost is negligible
(~3-5%). Existing-unique reconnects are unaffected — they don't
take the new-unique branch.

For tests, `TestMain` sets `issuanceGrace = 0` package-wide so no
existing test sees the grace; new grace-specific tests opt in.

## Coding rules to honor

- ASCII only.
- Direct commits on `main`.
- Loud-failure: not applicable (no parsing added).
- Tests must remain `go test -race ./...` clean.
- Don't add config knobs we don't need yet — the 5s default is fine.
