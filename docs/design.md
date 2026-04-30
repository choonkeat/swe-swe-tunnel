# swe-swe-tunnel — design

A self-hosted reverse tunnel that gives a swe-swe instance (or any localhost-bound HTTP service) a public, HTTPS-terminated, multi-port URL without opening ports on the host. Single Go binary on each side. Single :443 listener on the public side.

## Goals

- One outbound connection from the host running swe-swe; everything else (browser traffic, all ports) flows back through it.
- All exposed ports of the swe-swe-server reachable through a single public hostname pattern: `{port}.{unique}-tunnel.example.com`.
- Browser-facing TLS terminated at the tunnel server using a Let's Encrypt wildcard cert, automatically renewed.
- Stable, client-claimable identity (`unique`). Whoever first registers a name owns it; the original owner can always reclaim it via proof-of-possession.
- Tunnel server runs on a single :443 (PaaS-friendly).
- Cookies span all ports of one session: cookie scoped to `.{unique}-tunnel.example.com` covers `1977.{unique}-tunnel.example.com`, `3000.{unique}-tunnel.example.com`, etc.

## Non-goals

- Multi-tenant SaaS, accounts, billing, web UI.
- Arbitrary 1–65535 ports on the public side. Configurable port set, defaults to swe-swe's shape.
- True end-to-end encryption past the tunnel server. Server terminates browser TLS — same trust model as cloudflared/ngrok/Traefik.
- TCP/SSH passthrough in v1 (easy add later by registering a port as `mode=tcp`).
- Running `lego` on the client side. The server holds DNS API credentials and is the ACME orchestrator.

## Architecture

```
                            tunnel.example.com (server)
                                     │
   browser ──TLS──> :443  ──http.Server──┐   ┌─ DNSimple API ─┐
                                          │   │                │
                                          ├──< lego/v4 (DNS-01) > Let's Encrypt
                                          │   │                │
                                          │   └────────────────┘
                                          │
                            POST /v1/connect (HTTP Upgrade)
                            from tunnel-client; the server
                            hijacks and runs yamux over the
                            same TCP connection
                            ┌─────────────┘
                            │   yamux multiplex (one session per client)
                            ▼
                       tunnel-client (on swe-swe host)
                            │
                            ▼
                       127.0.0.1:1977/3000/4000/...
                            │
                            ▼
                         swe-swe-server
```

Key point: there is **one** public listener (`:443`). The control channel is
just an HTTP request to that same port that gets upgraded into a yamux
session. There is no separate `:7444`, no SNI peeking, no ALPN demux. Browser
data plane and tunnel control plane share `:443`; routing is decided by HTTP
`Host` header (browser) vs path (`POST /v1/connect`, control).

## Naming & DNS

- Apex `example.com` hosts marketing, docs, registration API. Independent of tunnel routing.
- Registration endpoint: `register.example.com` (or any non-`-tunnel` hostname).
- Per-session host: `{port}.{unique}-tunnel.example.com`. The `-tunnel` suffix is server-imposed; clients submit `unique`, server stores `unique-tunnel` as the actual label.
- `unique` regex: `^[a-z][a-z0-9-]{1,54}[a-z0-9]$` — must start with a letter, end with letter or digit, hyphens allowed in the middle, total ≤ 54 chars (so `{unique}-tunnel` ≤ 63, the DNS label limit).
- No reserved-name list needed — the `-tunnel` suffix is the namespace boundary. `register-tunnel` is just another user; server's own hostnames live without the suffix.

DNS records:
| Name | Type | Value | Created by |
|---|---|---|---|
| `example.com` | A | tunnel-server-IP | one-time, manual |
| `*.example.com` | A | tunnel-server-IP | one-time, manual |
| `*.{unique}-tunnel.example.com` | A | tunnel-server-IP | tunnel server, on REGISTER, via DNSimple API |

Removed by tunnel server on DEREGISTER. DNS wildcards are single-level (RFC 4592), so the per-session wildcard A record is required to reach `{port}.{unique}-tunnel.example.com`.

## TLS / certificate lifecycle

Embedded `github.com/go-acme/lego/v4` in the tunnel server. No Caddy, no cron, no separate cert-server container.

State directory layout (on the tunnel-server host):
```
~/.swe-swe-tunnel/
├── lego/
│   ├── accounts/acme-v02.api.letsencrypt.org/{email}/account.json
│   └── certificates/
│       ├── _.example.com.crt           # apex wildcard
│       ├── _.example.com.key
│       ├── _.{unique}-tunnel.example.com.crt
│       └── _.{unique}-tunnel.example.com.key
├── identities.db                       # SQLite: pubkey → unique mapping
└── config.toml
```

Certs:
1. **Apex wildcard `*.example.com`** — issued once on first server boot. Used for the registration endpoint and any non-tunnel hostnames.
2. **Per-session wildcard `*.{unique}-tunnel.example.com`** — issued on REGISTER. Used by browsers connecting to that session's per-port subdomains.

Renewal:
- Background goroutine wakes daily, checks all certs in the directory.
- If `notAfter - now < 30 days`: run `lego renew`.
- Hot-swap via `tls.Config.GetCertificate`. Lookup by SNI's middle label: `3000.abc-tunnel.example.com` → look up cert for `*.abc-tunnel.example.com`. In-flight connections keep the old cert; new handshakes get the new one.

Rate-limit awareness:
- LE: 50 new "Registered Domain" certs per `example.com` per week. New REGISTER calls are the constraint; renewals don't count.
- Per-pubkey rate limit (10/day, see "Squatting and rate limits") sits **before** the cert-issuance call in the new-unique branch, so a runaway client can't burn through the LE quota even if its keypair is compromised.
- The back-pressure mode is implemented over the typed `Deny` frame: rate-limit denies carry `retry_after_seconds` so the client can wait the precise window. The client behavior section below describes how supervisors react.
- Consider weekly capacity headroom when picking client onboarding cadence.

LE account:
- New ACME account dedicated to the tunnel server, e.g. `you@example.com`.
- Independent from existing accounts (`+devsweswe`, `+certs-swe-swe`). Lets each ACME account fail in isolation.

## Identity & registration

Self-service, keypair-based. No admin provisioning. No OAuth.

### First-time registration

```
client                                              server
  │                                                   │
  │── REGISTER unique="abc"                          │
  │   pubkey=Ed25519:...                             │
  │   sig=Ed25519(pubkey || unique || timestamp)──> │
  │                                                   │
  │                                  lookup "abc" in identities.db
  │                                  not found → store (abc → pubkey)
  │                                  call DNSimple: create *.abc-tunnel.example.com A
  │                                  call lego: issue *.abc-tunnel.example.com via DNS-01
  │                                  store cert
  │                                                   │
  │  <── REGISTER_OK unique="abc"                    │
  │       hostname="abc-tunnel.example.com"           │
```

### Reconnect / reclaim

```
client                                              server
  │                                                   │
  │── REGISTER unique="abc" pubkey=Ed25519:... ────> │
  │                                                   │
  │                                  lookup "abc" → existing pubkey
  │                                  pubkey matches → REGISTER_OK (idempotent)
  │                                  pubkey differs → CHALLENGE nonce=...
  │  <── CHALLENGE nonce=... ────────────────────────│
  │                                                   │
  │── PROOF sig=Ed25519(stored_pubkey, nonce) ─────> │
  │                                                   │
  │                                  verify sig against STORED pubkey
  │                                  match → register new pubkey, REGISTER_OK
  │                                  mismatch → DENY
```

Note: PROOF must be signed by the **stored** private key, not the new one. An impostor with a different keypair cannot produce that signature; only the original owner can. The server's response binds the new pubkey to the unique on success (allowing key rotation if the legitimate owner has both keys).

### Squatting and rate limits

- **Per-IP REGISTER rate limit:** 5/hour, sliding window. Cheap, applied before any crypto. Counts every REGISTER attempt with a valid frame shape.
- **Per-pubkey REGISTER rate limit:** 10/day, sliding window. Anti-hoarding: caps how many *new* uniques one keypair can claim. Idempotent reconnects to an already-owned unique do **not** consume the budget — they allocate no new resource. The challenge/proof path (registering against an existing unique with a different pubkey) also doesn't consume the budget; the cryptographic Proof verification is the gate there.
- **Server hint on rate-limit denies.** The Deny frame for `rate_limited:ip` and `rate_limited:pubkey` carries `retry_after_seconds` — the exact time until the offending sliding window's oldest sample expires (rounded up by one second). New clients use this to back off precisely; old clients ignore the field.
- **DEREGISTER is unrestricted** but requires PROOF.
- **Identity records are persistent;** no TTL. Squatted names stay squatted unless the owner DEREGISTERs.

### Identity storage

SQLite file `identities.db`:
```sql
CREATE TABLE identities (
  unique_name TEXT PRIMARY KEY,
  pubkey BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX idx_pubkey ON identities(pubkey);
```

Backups are critical: losing this DB means orphaned uniques, since reclaiming requires the stored pubkey. Document a backup procedure.

## Wire protocol

The same TCP/TLS port (`:443`) carries two kinds of traffic, distinguished by
the HTTP request line:

1. **Control / multiplex channel** — `POST /v1/connect` with
   `Connection: Upgrade, Upgrade: swe-swe-tunnel/1`. The server replies with
   `101 Switching Protocols`, hijacks the conn, and wraps it in a
   `hashicorp/yamux` server session. The client wraps the same conn in a yamux
   client session. Subsequent control messages travel over yamux stream 1;
   data plane traffic uses other streams (server→client direction).
2. **Browser data plane** — every other request hitting `:443`. The server
   inspects `Host`, looks up the matching session, and reverse-proxies the
   request to the client through a `yamux.Stream`-backed `http.Transport`.

### Control connection

- TLS 1.3, server cert is `*.example.com`. Client validates against the apex
  cert chain (it does not need a per-session cert for control).
- Client connects on first run; reconnects with exponential backoff (1s → 60s).
- After the upgrade, client opens yamux stream 1 and exchanges hello frames:
  - `ClientHello{ version, unique }` — Phase 2.
  - `ClientHello{ version, unique, pubkey, sig }` — Phase 3 adds REGISTER fields.
  - `ServerHello{ ok, hostname, reason }`.

Each control frame is length-prefixed: 4-byte big-endian length, then UTF-8
JSON body. Non-control bytes (yamux's own framing) are handled by yamux.

### Browser data plane (HTTP-level)

The server's catch-all handler:

1. Parses `r.Host` (lower-cased, port stripped).
2. Strips the apex suffix `.example.com`. If the remainder isn't of the form
   `{port}.{label}-tunnel`, falls through to the apex landing page.
3. Looks up `{label}-tunnel` in the in-memory session registry.
4. If absent → returns a 502 "tunnel offline" page.
5. If present → uses the session-scoped `httputil.ReverseProxy`. Each request
   opens a fresh yamux stream (`session.Open()`); `Connection: keep-alive` is
   disabled to keep stream lifecycle tied to request lifecycle. The
   `Host` header is preserved end-to-end so the client can route by port.

WebSocket / HTTP-Upgrade requests work transparently through
`httputil.ReverseProxy` (Go ≥ 1.12); after the upstream response is seen as
101, the proxy switches to bidirectional copy and the yamux stream stays open
for the duration of the WS session.

### Why yamux, not HTTP/2

- HTTP/2 server-initiated streams are awkward (PUSH is deprecated; we'd reverse
  the client/server roles). yamux makes both sides peers.
- yamux handles flow control, keepalive, graceful close.
- We're already terminating TLS at the public listener, so there's no
  TLS-in-TLS overhead inside the tunnel.

## Data plane

### Public listener

One `http.Server` on `:443`, TLS configured via `tls.Config.GetCertificate`.
The server's mux:

- `POST /v1/connect` → upgrade handler (above).
- `/...` → host-routing handler that either reverse-proxies into a tunnel or
  serves the apex hello page.

`tls.Config.GetCertificate` picks a cert by SNI (exact match → one-level
wildcard → fall back to apex). Per-session wildcards `*.{label}.{apex}` are
loaded from disk on boot via `Manager.LoadAllFromDisk()` and after each
`--ensure-cert` run.

### Port mapping

The tunnel doesn't bind a port range on the public side — it only binds
`:443`. The "port" of `{port}.{unique}-tunnel.example.com` is *encoded in the
hostname*; the actual wire port is always 443.

The browser-side server preserves the `Host` header through the proxy. The
client extracts the leftmost label as the port number and forwards to
`{target}:{port}` — by default `127.0.0.1:{port}`. Per-port overrides
(`--port-target=3000=192.168.1.50:8080`, planned) let the client redirect
specific ports elsewhere.

### HTTP-level concerns

`httputil.ReverseProxy.SetXForwarded()` injects:
- `X-Forwarded-Proto: https`
- `X-Forwarded-Host: {port}.{unique}-tunnel.example.com`
- `X-Forwarded-For: {client_addr}`

WebSocket / HTTP Upgrade is transparent (Go's ReverseProxy detects 101 and
switches to bidirectional byte copy; yamux pipes the bytes through unchanged).

Raw-TCP forwarding (planned, post-v1) would skip the HTTP layer entirely and
piggyback on a different request path, e.g. `POST /v1/tcp/{label}/{port}`.

## Configuration

### Tunnel server

Flag > env > default.

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--listen` | `SWE_TUNNEL_LISTEN` | `:443` | Public listener (also carries control via `POST /v1/connect`) |
| `--state-dir` | `SWE_TUNNEL_STATE` | `~/.swe-swe-tunnel` | All persistent state |
| `--apex-domain` | `SWE_TUNNEL_APEX` | `example.com` | DNS apex |
| `--acme-email` | `SWE_TUNNEL_ACME_EMAIL` | required | LE registration |
| `--dns-provider` | `SWE_TUNNEL_DNS_PROVIDER` | `dnsimple` | passed to lego |
| `--acme-staging` | — | false | use Let's Encrypt staging directory |
| `--ensure-cert` | — | "" | admin one-shot: issue `*.{label}.{apex}` and exit |
| `--rate-limit-register` | env | `5/hour` per IP | sliding window (Phase 3) |

DNS provider credentials follow `lego`'s env conventions (`DNSIMPLE_OAUTH_TOKEN`, `CLOUDFLARE_DNS_API_TOKEN`, etc.).

### Tunnel client

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--server` | `SWE_TUNNEL_SERVER` | required | e.g. `https://tunnel.example.com` |
| `--unique` | `SWE_TUNNEL_UNIQUE` | required | requested name (server appends `-tunnel`) |
| `--identity-key` | `SWE_TUNNEL_KEY` | `~/.swe-swe-tunnel/identity.key` | Ed25519 private key, generated on first run (Phase 3) |
| `--target` | `SWE_TUNNEL_TARGET` | `127.0.0.1` | default forward target |
| `--port-target` | repeated | none | per-port override `--port-target=3000=192.168.1.5:8080` (planned) |
| `--insecure` | — | false | skip TLS verification (testing only) |
| `--report-format` | `SWE_TUNNEL_REPORT_FORMAT` | `none` | structured event stream on stdout: `none` or `jsonl`. See `tasks/2026-04-29-supervisor-event-protocol.md`. |

## Phased delivery

Each phase is independently shippable and testable.

### Phase 1 — apex cert + hello

- Embed `lego/v4`.
- Acquire `*.example.com` via DNS-01 on first boot.
- Daily renewal goroutine.
- Hello page on `:443`. Validate green padlock end-to-end.

### Phase 2 — control channel + single-port forward

- Single `:443` listener; control channel is `POST /v1/connect` with HTTP
  Upgrade, hijacked into yamux.
- One yamux session per client; in-memory `map[label]*Session` registry.
- ClientHello/ServerHello, no auth (any `unique` accepted).
- Browser-side forward via `httputil.ReverseProxy` keyed on `Host` header;
  client picks port from leftmost label.
- Per-session wildcard cert acquired via the new `--ensure-cert <label>`
  admin subcommand on `swe-swe-tunneld`. DNS A record added manually for the
  first session.
- Smoke target: swe-swe accessible via `1977.test-tunnel.example.com`.

### Phase 3 — registration & identity

- `register.example.com` HTTPS endpoint. JSON over POST.
- SQLite identities.db, REGISTER, CHALLENGE, PROOF, DEREGISTER messages.
- Per-IP and per-pubkey rate limits.
- DNSimple API integration to create/remove `*.{unique}-tunnel.example.com` A records.
- Per-session DNS-01 issuance via lego.

### Phase 4 — multi-port polish

- Multi-port works as soon as Phase 2 ships (port encoded in Host label,
  preserved through ReverseProxy). This phase tightens it up:
- Client honors `--port-target` overrides.
- Optional allowlist of forwardable ports.
- Reject Host headers that don't match `{port}.{unique-tunnel}.{apex}`.
- Public-listener `tls.Config.GetCertificate` already keyed by SNI suffix
  match (implemented in Phase 2 via `cert.Manager`).

### Phase 5 — swe-swe integration

- swe-swe reads `SWE_PUBLIC_HOSTNAME` from tunnel state file.
- Cookie domain plumbing.
- Frontend URL builder helper (label-swap on `window.location.hostname`).
- swe-swe drops its own LE handling when tunnel mode is active.
- Coverage: see `/workspace/research/2026-04-26-swe-swe-tunnel-integration.md`.

### Phase 6 — polish & ops

- Structured logs (`slog`).
- `/metrics` Prometheus endpoint.
- Graceful drain on SIGTERM (close yamux sessions, finish in-flight requests).
- Cert-renewal hot-swap integration test.
- 502-on-client-offline page.
- Backup procedure for `identities.db`.
- Operations runbook.

### Phase 7+ (deferred)

- BYO domain mode: client supplies its own cert (for users with their own DNS).
- Raw TCP forwarding (`mode=tcp` per port).
- Geographic redundancy / multi-region tunnel servers.
- ACME alternate DNS providers (Cloudflare, Route 53) — `lego` already supports them; just plumb credentials.

## Risks & open questions

1. **LE 50/week limit on new uniques.** Acceptable for personal/small-team use. Document the ceiling. If we hit it, the back-pressure mode should be UX-friendly ("we're at this week's cert quota; try again Tuesday").
2. **DNS-01 cold-start latency** (30–60s for first request). Pre-issue eagerly during REGISTER, before client receives REGISTER_OK. User waits at REGISTER, not at first browser hit.
3. **identities.db loss = orphaned uniques.** Document backup. SQLite VACUUM + offsite copy on cron. Consider replicating to a second machine.
4. **DNSimple as single point of failure.** Other DNS providers supported by lego (Cloudflare, Route 53). Domain registrar can be moved without changing zone.
5. **Per-session wildcard cert volume.** 1000 active uniques = 1000 cert files. Filesystem-fine, but the renewal scheduler must batch renewals to avoid hitting LE rate limits when many certs come up simultaneously. Stagger by hashing `unique` to a renewal day.
6. **Browser sees "no client connected" gracefully?** TLS handshake completes; first HTTP response is 502 "tunnel offline". Document as expected behavior.
7. **Should the apex (`example.com`) itself route to the tunnel server, or to a static landing page?** v1: tunnel server serves a static landing page from the same binary. Phase 7+ split off if needed.

## Wire protocol — message reference (informative)

After the HTTP Upgrade handshake on `POST /v1/connect`, both sides wrap the
hijacked TCP/TLS conn in yamux. Stream 1 carries length-prefixed JSON control
frames. All other yamux streams (server-initiated, client-accepted) carry raw
HTTP/1.1 traffic.

### Frame format on stream 1

```
[4 bytes big-endian length][JSON payload, UTF-8, ≤ 64 KiB]
```

### Frame envelope

Each frame is a typed envelope:

```
{ "type": "<kind>", "payload": { ... } }
```

`type` is one of: `register`, `register_ok`, `challenge`, `proof`, `deny`,
`deregister`, `deregister_ok`. The Phase 2 untyped `ClientHello`/`ServerHello`
is retired.

### Frame payloads

```
Register     = { "version": 1, "unique": "abc",
                 "pubkey":   "base64-RawStd Ed25519 (32 bytes)",
                 "timestamp": 1714137600,
                 "sig":       "base64-RawStd Ed25519(domain || pubkey || unique || ts)" }

RegisterOK   = { "hostname": "abc-tunnel.example.com" }

Challenge    = { "nonce": "base64-RawStd, 32 bytes" }
Proof        = { "sig":   "base64-RawStd Ed25519(stored_priv, domain || nonce)" }

Deregister   = { "unique": "abc",
                 "timestamp": 1714137600,
                 "sig":       "base64-RawStd Ed25519(domain || unique || ts)" }
DeregisterOK = {}
```

### Deny

`Deny` is the terminal failure reply on Register, Deregister, and the
post-Register control loop. Two fields:

```
Deny = { "reason":              "<machine-readable string>",
         "retry_after_seconds": <int, omitted when 0> }
```

Reason taxonomy (current strings; treat as enum from the client's
perspective, but match by exact string):

| Reason | Semantics | Client should |
|---|---|---|
| `rate_limited:ip` | Per-IP REGISTER limit hit | Wait `retry_after_seconds` (or `RateLimitFloor`, default 5min, if absent) |
| `rate_limited:pubkey` | Per-pubkey REGISTER limit hit on a new-unique claim | Same as above |
| `bad pubkey`, `bad sig`, `signature invalid`, `key_mismatch`, `unique mismatch`, `bad register payload`, `bad deregister payload`, `bad proof payload`, `bad proof sig` | Client misconfiguration | Treat as fatal (no retry) |
| `unsupported protocol version <n>`, `invalid unique <q>`, `expected <kind>, got <kind>` | Wire-format incompatibility | Treat as fatal |
| `timestamp out of range` | Clock skew vs. server | Retry (skew may be transient) |
| `cert issuance failed`, `store error`, `internal error` | Server-side transient | Retry with normal exponential backoff |

`retry_after_seconds` is set only on `rate_limited:*` denies; clients
seeing zero on any deny fall back to local heuristics
(`RateLimitFloor` for rate-limits, exponential for everything else).
Old clients that don't read the field are unaffected (the `omitempty`
JSON tag means it's wire-compatible both directions).

### Client retry behavior

The reference client (`internal/tunnelclient.Run`) dispatches on
deny reason:

* **Permanent denies** (per the table above) → emit `fatal` and exit
  non-zero. Looping on these forever just turns a misconfiguration
  into a noisy reconnect storm; the supervisor should surface the
  fatal and let the operator fix the config.
* **`rate_limited:*` denies** → the next reconnect waits
  `retry_after_seconds` if present, else `RunOptions.RateLimitFloor`
  (default 5min). The default exponential ceiling (`BackoffMax = 30s`)
  is useless against the server's hour- and day-scale windows;
  pinging at 30s just keeps the offending budget exhausted.
* **Transient denies** (clock skew, server-side hiccups) → normal
  exponential backoff, capped at `BackoffMax`.
* **All non-deny errors** (TCP refused, TLS failure, yamux) → normal
  exponential backoff.

The supervisor JSONL stream surfaces these as `error` (retryable),
`reconnecting` (with `after_ms`), and `fatal` (with `exit_code`)
events. See `tasks/2026-04-29-supervisor-event-protocol.md` for
the full event schema.

### Forwarded streams

Each browser request to `:443` opens a fresh yamux stream toward the client.
The bytes on the stream are vanilla HTTP/1.1 — no extra framing. The server
wraps the stream in `http.Transport` via `DialContext`, and the client serves
it through `http.Server` running on the yamux session as a Listener. The
`Host` header is preserved end-to-end so the client can extract the leftmost
label and pick a forward port.
