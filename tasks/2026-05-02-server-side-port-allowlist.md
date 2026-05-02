# Tunneld: server-side port allowlist (and remove client-side gate)

## Status

**Proposed (2026-05-02).** No code changes yet; this file captures
the scope and rationale for moving port gating from the tunnel
client to the tunneld server.

Companion tasks not in scope here:

- `2026-05-02-pubkey-allowlist.md` — pubkey gate on `Register`. The
  port allowlist is independent: pubkey gates *who* may register,
  port allowlist gates *what destination ports* the server is willing
  to proxy.

## Why

Today, port gating lives on the client. `cmd/swe-swe-tunnel/main.go`
defaults `--ports` to `tunnelclient.DefaultPortSpec` (`1977,3000-3099,
4000-4099,5000-5099,5173,8000-8099,8080,8081`), and
`internal/tunnelclient/client.go:382-400` rejects any inbound proxy
request whose `{port}` host-label is not in that policy with
`HTTP 404 "port not allowed"`.

This is operationally awkward for two reasons.

**1. The trust model already centers the server.** Every browser hit
lands on tunneld first, gets routed by `route()` in `tunnel.go:687`
through the per-tenant yamux session, then hits the client's
`PortDispatchHandler`. The tunneld operator is the one who chose
which apex to expose to the public internet; they are the natural
party to decide which destination ports their tunnel will proxy.
Asking each client to also configure a port policy is duplicate
config that drifts.

**2. The hardcoded default doesn't include the consumer's main
service port.** swe-swe binds its primary UI on `127.0.0.1:9898` in
tunnel mode (the consumer's `Dockerfile` CMD sets `-bind
127.0.0.1:9898`), and the consumer's supervisor prints `OPEN AT
https://9898.{hostname}/` as the operator-friendly entry URL.
Visiting that URL today returns `HTTP 404 "port not allowed"` from
the client because `9898` is not in `DefaultPortSpec`. The consumer
could pass `--ports` to the child to inject `9898`, but that just
papers over the broader awkwardness — every consumer of swe-swe-tunnel
that picks a non-`80xx`/`30xx`/etc. port has to know to do this, and
the policy-config surface lives on the wrong side of the wire.

The fix: tunneld owns the port allowlist. Client unconditionally
forwards whatever the server hands it.

## Scope

In-scope:

- New tunneld config: `--allowed-ports=<spec>` flag with env override
  `SWE_TUNNEL_ALLOWED_PORTS`. Spec format is the same comma/range
  syntax the client's `ParsePortPolicy` already parses (e.g.
  `1977,3000-3099,9898`). Reuse `internal/tunnelclient/portpolicy.go`
  by moving it to a neutral location (proposed:
  `internal/portpolicy/`) and importing from both server and client.
- Default value: a conservative-but-useful baseline that includes the
  swe-swe primary port. Recommendation:
  `1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898`
  (i.e. the existing `DefaultPortSpec` plus `9898`). The operator can
  override to anything, including `>=1024` shorthand if the parser
  grows that. Document that `0` and the privileged range are
  intentionally excluded by default — privileged ports are unlikely
  destinations for a tunnel client and accidentally routing port 22
  is a foot-gun.
- Enforcement point: in `route()` (`tunnel.go:687`), after the
  `{port}.{label}` split succeeds and before `ts.proxy.ServeHTTP`.
  Parse the `{port}` component (already a string from the split),
  reject `404 "port not allowed"` (preserve the wire-visible error
  text so any existing operator runbook keyed on it keeps working).
  Log the rejection at warn with `port`, `host`, and `remote_addr`.
- **Live reload** is *not* required for v1. Editing the allowlist on
  a running tunneld requires a restart. Operators who need hot-reload
  can layer SIGHUP later (cheap follow-up; the same `atomic.Pointer`
  pattern from the pubkey allowlist applies).
- Tests: parser round-trip (already exists for the client copy),
  `route()` table test for in-policy / out-of-policy / malformed-port
  / missing-port-label, and an e2e test that a request to a denied
  port gets `404 "port not allowed"` *without* the request ever
  reaching the client (assert via the backend mux not seeing it).
- Consumer-visible behavior: when the consumer's `OPEN AT
  https://9898.{hostname}/` URL is visited, the request now passes
  the server gate (since `9898` is in the default) and reaches the
  client unconditionally.

Out-of-scope (deliberately):

- Per-pubkey port allowlists. One global set is fine for the current
  operator profile (single-operator, friends-and-family clients).
  Mixing port-allowlist with pubkey-allowlist multiplies config
  complexity for small benefit; revisit if a tenant actually needs
  port isolation from another tenant.
- A "deny" list. The allowlist *is* the policy; subtraction is
  better expressed by editing the allowlist.
- Wildcard syntax (`*`, `all`). The existing `ParsePortPolicy`
  doesn't have it; adding it here is unrelated to the move.

## Removing client-side gating

This is the other half of the change and arguably the more important
half — without it, the policy duplicates and drifts.

- Drop the `--ports` flag from `cmd/swe-swe-tunnel/main.go`.
- Drop the `SWE_TUNNEL_PORTS` env fallback.
- Drop the `policy` parameter from
  `tunnelclient.PortDispatchHandler` — the client unconditionally
  proxies whatever the server sent.
- Move `internal/tunnelclient/portpolicy.go` and its tests to
  `internal/portpolicy/` and re-export from there. The client no
  longer imports it; the server now does.
- Remove the `[tunnel-client] msg="port policy" spec=...` boot log
  line — it no longer reflects anything the client controls.

This is a wire-compatible change (no protocol bytes change), but it
*is* a CLI break for any downstream consumer that passes `--ports`
or `SWE_TUNNEL_PORTS`. The known consumer (swe-swe's
`tunnel_supervisor.go` `startExecChild`) does not pass either, so
the break is theoretical.

## Sequencing

Suggested commit order:

1. Move `internal/tunnelclient/portpolicy.go` → `internal/portpolicy/`
   (rename only, no behavior change). Tests come along.
2. Add server-side `--allowed-ports` flag, env, and enforcement in
   `route()`. Default value includes `9898`. New tests.
3. Strip client-side gating: drop `--ports`, drop the policy
   parameter from `PortDispatchHandler`, drop the boot log line.
   Update client tests.

Each commit is independent enough to review separately. (1) is the
rename; (2) lights up the server gate; (3) removes the redundant
client gate. After (2), the system is functional even before (3) —
the client gate is just dead weight.

## Consumer side (swe-swe)

After this lands, the consumer-side bump is just:

- Bump `SWE_SWE_TUNNEL_REF` in
  `cmd/swe-swe/templates/host/Dockerfile` to the new SHA.
- `make build golden-update`.
- One commit.

No code change in `tunnel_supervisor.go` is needed: the supervisor
already passes only `--server`, `--unique`, and `--report-format`,
so dropping `--ports` upstream is a no-op for our invocation.

The consumer's `OPEN AT https://9898.{hostname}/` URL becomes
clickable in tunnel mode for the first time.

## Default-value decision

Two reasonable defaults:

- **A. `DefaultPortSpec` + `9898`** — preserves today's port set,
  adds the one missing entry. Minimal surface change; operators who
  upgrade get the same ports they had plus the swe-swe primary.
- **B. `>=1024`** — broader, simpler to explain ("any unprivileged
  port"), matches the user's offhand suggestion. Requires a parser
  extension to express `>=N` ranges.

Pick A for v1. B is a nice-to-have follow-up that touches the
parser; doing it inline with this move would expand scope for no
operational gain (operators can already write
`1024-65535` as the spec to get the same effect).

## Boot logging

After this lands, tunneld's boot should log the active policy
exactly like the client does today, e.g.:

```
[tunneld] msg="port allowlist" spec="1977,3000-3099,...,9898" source=default
[tunneld] msg="port allowlist" spec="..." source=flag
[tunneld] msg="port allowlist" spec="..." source=env
```

The `source` tag matches the existing pattern for other config
(`identity loaded source=env`). Operators should be able to tell at
a glance which port set is in effect.

## Wire-format / protocol impact

None. The control protocol does not carry port info — port is
purely a host-header label on the data plane, and the data plane
already routes through `route()` before the client sees the request.
The change is entirely policy-layer; no `internal/control/proto.go`
edits.
