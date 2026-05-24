# Tunneld: `--register-listen-without-mtls` (additive cert-less registration port)

## Status

Implemented. Surface in the codebase:

- `cmd/swe-swe-tunneld/main.go` — `--register-listen-without-mtls`
  flag + env fallback, `validateRegisterListen` boot guard, the
  second `http.Server`, and `registerTLSConfig` (SIGHUP-live CA via
  `GetConfigForClient`, `VerifyClientCertIfGiven`).
- `cmd/swe-swe-tunneld/register_listen_no_mtls_test.go` — e2e +
  unit coverage (see Tests below).
- `docs/mtls.md` — "Cert-less agent registration" section.
- `docs/configuration.md` — flag/env row.

Decision taken in chat: the register port's CA pool is
**SIGHUP-live** (not a boot snapshot) — `registerTLSConfig` reads
`bundle.Pool()` per handshake through `GetConfigForClient`, the same
mechanism the main listener uses.

Builds on the Phase-1 mTLS work in
`tasks/2026-05-21-mtls-public-listener.md`.

This **adds** a second listener; it does **not** change `:443`.
Registration over mTLS on `:443` stays exactly as it is — agents
that hold a `--client-cert` keep using `:443`. The new port is a
parallel entry point for agents that don't (or can't) present a
client cert.

## Why

Enabling `--mtls-ca` today locks every live agent out at the TLS
layer until each one is re-deployed with `--client-cert` — which
means minting, distributing, and installing a cert per agent
host. That cert-distribution step is the painful part of turning
mTLS on.

The agent register path is already strongly authenticated without
mTLS (`handleRegister`): Ed25519-signed Register frame, ±5min
replay window, per-IP + per-pubkey rate limits, slow-loris
timeout, and the optional `--allowlist-dir` gate. mTLS on the
agent path is pure defence-in-depth.

So: expose a second listener that accepts `/v1/connect` **without
requiring a client cert**, while browser access on `:443` stays
mTLS-gated. Cert-less agents point `--server` at the new port; the
tunnels they register are immediately reachable through the
mTLS-protected proxy on `:443` (shared registry). This swaps
"cert per agent" for "one URL edit per agent."

This knowingly reverses the Phase-1 non-goal *"Per-host or
SNI-conditional mTLS policy"* — but via **separate sockets**, not
SNI. That matters: `:443` keeps `RequireAndVerifyClientCert`
untouched, so the browser path gains **no** pre-auth HTTP surface,
and there is no SNI-vs-Host cross-check to get right (the proxy
`route()` is simply never mounted on the register port).

## Scope

In scope (single PR):

- New flag `--register-listen-without-mtls <addr>` (env
  `SWE_TUNNEL_REGISTER_LISTEN_WITHOUT_MTLS`), e.g. `:8443`.
  Empty (default) = disabled, behaviour byte-identical to today.
- A second `http.Server` when set, whose mux mounts **only**
  `/v1/connect` (reusing the same `connectHandler` value) plus
  `/healthz`. No hello page, no proxy `route()`.
- TLS on that listener: server-auth via the same
  `certMgr.GetCertificate`; `ClientAuth = VerifyClientCertIfGiven`
  with `ClientCAs = mtlsB.Pool()`. Cert-less agents pass; a
  cert-*bearing* agent must present a CA-trusted cert, which then
  still flows through the `cert_key_mismatch` binding in
  `handleRegister` (opportunistic defence-in-depth).
- Shared singletons with `:443`: `reg`, `idStore`, the three
  rate limiters, `allow`, `certMgr`. Already concurrency-safe.
- Boot guards (loud-fail, exit 2):
  - require `--mtls-ca` to be set — without mTLS on `:443` the
    main port already accepts cert-less registration, so this
    flag would be a no-op / misconfiguration;
  - require `--allowlist-dir` to be set — the register port is a
    non-mTLS surface; without an allowlist it is
    open-registration-to-the-internet (rate-limited only).
- Graceful shutdown of both servers on `ctx.Done()`.

Out of scope:

- Any change to `:443` behaviour, including its mTLS-gated
  `/v1/connect`.
- The proxy `route()` on the register port (never mounted).
- Agent-side auto-fallback from `:443` → register port on TLS
  failure. The agent just configures the new URL.
- SNI-conditional policy on a single listener (the rejected
  alternative).

## Decisions captured in chat

- **Separate port, not SNI relaxation.** Avoids treating SNI as a
  security boundary and avoids any pre-auth HTTP surface on the
  browser path.
- **Additive.** mTLS registration on `:443` is retained, not
  replaced. Agents with certs keep `:443`; cert-less agents use
  the new port. Both can run simultaneously.
- **Flag name `--register-listen-without-mtls`** — the name states
  the security property out loud.
- **`VerifyClientCertIfGiven`** on the register port (not
  `NoClientCert`, not `RequestClientCert`): only a verified cert
  populates `r.TLS.PeerCertificates`, so the existing
  `peerCertPub` binding in `handleRegister` stays meaningful and
  unforgeable; cert-less agents still pass.
- **Require `--mtls-ca` and `--allowlist-dir`** to enable the
  flag (hard-fail). Open to softening the allowlist requirement to
  a loud warning if an operator argues for it.

## Implementation sketch

### 1. Flag + env wiring (`main.go`)

Mirror the `--mtls-ca` block: declare `registerListenNoMTLS`,
fall back to `SWE_TUNNEL_REGISTER_LISTEN_WITHOUT_MTLS`. After the
existing flag validation:

```go
if *registerListenNoMTLS != "" {
    if *mtlsCA == "" {
        logger.Error("--register-listen-without-mtls requires --mtls-ca " +
            "(the main listener already accepts cert-less registration when mTLS is off)")
        os.Exit(2)
    }
    if *allowlistDir == "" {
        logger.Error("--register-listen-without-mtls requires --allowlist-dir " +
            "(a cert-less registration port without an allowlist is open registration)")
        os.Exit(2)
    }
}
```

### 2. Second server (`main.go`, after the `:443` server starts)

```go
if *registerListenNoMTLS != "" {
    regMux := http.NewServeMux()
    regMux.Handle("/v1/connect", connectHandler(reg, idStore, certMgr, *apex, ipLim, keyLim, skewLim, allow, logger))
    regMux.HandleFunc("/healthz", okHandler)

    regTLS := &tls.Config{
        GetCertificate: certMgr.GetCertificate,
        MinVersion:     tls.VersionTLS12,
        ClientAuth:     tls.VerifyClientCertIfGiven,
        ClientCAs:      mtlsB.Pool(), // opportunistic binding only
    }
    regSrv := &http.Server{
        Addr: *registerListenNoMTLS, Handler: regMux, TLSConfig: regTLS,
        ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
    }
    logger.Info("register-without-mtls listener", "addr", *registerListenNoMTLS)
    go func() {
        if err := regSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
            logger.Error("register listener exited", "err", err)
            stop()
        }
    }()
    // add regSrv.Shutdown(shutdownCtx) to the shutdown block.
}
```

Note: `ClientCAs` here is a boot snapshot, acceptable for the
opportunistic-binding case. If we want SIGHUP-live CA on this port
too, thread `GetConfigForClient` the same way `:443` does. Decide
during implementation; the binding is defence-in-depth, so a boot
snapshot is defensible for v1.

### 3. Shutdown

Extend the existing shutdown block to `regSrv.Shutdown` alongside
`srv.Shutdown`.

## Tests

`cmd/swe-swe-tunneld/register_listen_no_mtls_test.go` (new):

- **Happy path**: bring up both listeners; agent connects to the
  register port with **no** client cert, registers, then a request
  to the proxy on the mTLS `:443` for that label is served through
  the tunnel. Proves shared `reg`.
- **Proxy not mounted on register port**: a tunnel-proxy `Host`
  sent to the register port is **not** reverse-proxied (404 / hello
  absent) — the proxy path is unreachable there.
- **Untrusted cert rejected**: an agent presenting a cert signed by
  a CA *not* in `--mtls-ca` fails the handshake on the register
  port (`VerifyClientCertIfGiven` still verifies when a cert is
  given).
- **Opportunistic binding**: a cert-bearing agent whose Register
  pubkey ≠ cert pubkey gets `not_authorized` /
  `reason_detail=cert_key_mismatch`, same as on `:443`.
- **Boot guards**: `--register-listen-without-mtls` without
  `--mtls-ca` → exit 2; without `--allowlist-dir` → exit 2.
- **Allowlist still gates**: a non-allowlisted pubkey registering
  via the register port gets `not_authorized`.
- **SIGHUP revoke**: removing a pubkey from the allowlist drops the
  session it registered via the register port (shared `reg`).

Regression: existing `:443` mTLS register tests
(`mtls_test.go`, `e2e_test.go`) must stay green unchanged.

## Compatibility

Default off → byte-identical to today. Purely additive; no
migration, no required upgrade order. Turning it on touches only
the daemon command line plus the `--server` URL of any agent the
operator wants to move off cert-based auth.

## Docs

Add a section to `docs/mtls.md`: when to use the register port,
the `--mtls-ca` + `--allowlist-dir` requirement, the agent
`--server https://host:8443` change, and the note that `:443`
mTLS registration is unaffected. Update `docs/configuration.md`
with the flag + env var.

## Coding rules to honor

- Loud-fail on boot for the guards (match the `--mtls-ca` /
  allowlist precedent).
- Reuse `connectHandler` verbatim — no fork of the register code
  path.
- slog structured logging, same key names as the `:443` boot logs.
