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
   browser ──TLS──> :443 ─SNI demux─┤   ┌─ DNSimple API ─┐
                                     │   │                │
                                     ├──< lego/v4 (DNS-01) > Let's Encrypt
                                     │   │                │
                                     │   └────────────────┘
                                     │
                          control TLS │  (single conn per client)
                            ┌────────┘
                            │   yamux multiplex
                            ▼
                       tunnel-client (on swe-swe host)
                            │
                            ▼
                       127.0.0.1:1977/3000/4000/...
                            │
                            ▼
                         swe-swe-server
```

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
- Document a back-pressure mode if the limit is hit (return 503 from REGISTER with retry-after).
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

- Per-IP REGISTER rate limit: 5/hour, sliding window.
- Per-source-pubkey REGISTER rate limit: 10/day across all uniques.
- DEREGISTER is unrestricted but requires PROOF.
- Identity records are persistent; no TTL. Squatted names stay squatted unless the owner DEREGISTERs.

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

Two channels:
1. **Control / multiplex channel** — long-lived TLS connection from client to server, wrapped in `hashicorp/yamux`. Each multiplexed stream carries either a control message or a forwarded data stream.
2. **Browser data plane** — the public-facing :443 listener. Demuxes by SNI + port to a yamux stream on the right control connection.

### Control connection

- TLS 1.3, server cert is `*.example.com` (so client validates against `tunnel.example.com`).
- Client connects on first run; reconnects with exponential backoff (1s → 60s).
- After TLS handshake, client opens stream 1 and exchanges hello frames:
  - `ClientHello{ version, unique, pubkey, sig }` (the REGISTER message)
  - `ServerHello{ version, accepted, hostname, port_range_assigned }`

### Stream framing

After hello, all data is multiplexed via yamux. Each new browser connection on the public side opens a new yamux stream toward the client. The first frame on the stream is a small header:

```
StreamHeader {
  dst_port: uint16,
  client_addr: string,      // for X-Forwarded-For
  request_protocol: enum(http, http+ws, tcp),
}
```

After the header, raw bytes flow both directions until EOF or RST.

### Why yamux, not HTTP/2

- HTTP/2 server-initiated streams are awkward (PUSH is deprecated; we'd reverse the client/server roles). yamux makes both sides peers.
- yamux handles flow control, keepalive, graceful close.
- We're already terminating TLS at the public listener, so no TLS-in-TLS overhead inside the tunnel.

## Data plane

### Public listener

One `net.Listen("tcp", ":443")`. On accept:
1. Peek TLS ClientHello, extract SNI.
2. Parse SNI: `{port_label}.{unique-tunnel}.example.com`.
3. Look up `unique-tunnel` → active control connection. Reject if no client connected.
4. Look up cert for `*.{unique-tunnel}.example.com`, present in TLS handshake.
5. After handshake, open a yamux stream on the client's control connection.
6. Send `StreamHeader{dst_port=parse(port_label), ...}`.
7. `io.Copy` both directions until close.

If the unique is registered but no client is currently connected: return TLS handshake completion with a 502 Bad Gateway HTTP body. Browsers see "tunnel offline" rather than a connection error.

### Port mapping

The tunnel doesn't bind a port range on the public side — it only binds :443. The "port" of `{port}.{unique}-tunnel.example.com` is *encoded in the hostname*; the actual wire port is always 443.

The client decides where to forward. Default config: forward stream's `dst_port` to `127.0.0.1:dst_port`. Configurable per port:

```toml
[forward]
default = "127.0.0.1"
"3000" = "192.168.1.50:8080"   # override
```

### HTTP-level concerns

For `request_protocol=http` streams, the client adds:
- `X-Forwarded-Proto: https`
- `X-Forwarded-Host: {port}.{unique}-tunnel.example.com`
- `X-Forwarded-For: {client_addr}`

WebSocket upgrade is transparent (yamux just pipes bytes after the upgrade response).

For `request_protocol=tcp` streams (future, not in v1), the client skips header injection and pipes raw bytes.

## Configuration

### Tunnel server

Flag > env > default.

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--listen` | `SWE_TUNNEL_LISTEN` | `:443` | Public listener |
| `--control-listen` | `SWE_TUNNEL_CONTROL_LISTEN` | `:7444` | Control channel listener |
| `--state-dir` | `SWE_TUNNEL_STATE` | `~/.swe-swe-tunnel` | All persistent state |
| `--apex-domain` | `SWE_TUNNEL_APEX` | `example.com` | DNS apex |
| `--acme-email` | `SWE_TUNNEL_ACME_EMAIL` | required | LE registration |
| `--dns-provider` | `SWE_TUNNEL_DNS_PROVIDER` | `dnsimple` | passed to lego |
| `--rate-limit-register` | env | `5/hour` per IP | sliding window |

DNS provider credentials follow `lego`'s env conventions (`DNSIMPLE_OAUTH_TOKEN`, `CLOUDFLARE_DNS_API_TOKEN`, etc.).

### Tunnel client

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--server` | `SWE_TUNNEL_SERVER` | required | e.g. `tunnel.example.com:7444` |
| `--unique` | `SWE_TUNNEL_UNIQUE` | required | requested name |
| `--identity-key` | `SWE_TUNNEL_KEY` | `~/.swe-swe-tunnel/identity.key` | Ed25519 private key, generated on first run |
| `--target` | `SWE_TUNNEL_TARGET` | `127.0.0.1` | default forward target |
| `--port-target` | repeated | none | per-port override `--port-target=3000=192.168.1.5:8080` |
| `--state-file` | `SWE_TUNNEL_STATE_FILE` | `/workspace/.swe-swe/tunnel-state.json` | written after REGISTER_OK |

State file (consumed by swe-swe):
```json
{
  "hostname": "abc-tunnel.example.com",
  "unique": "abc",
  "registered_at": "2026-04-26T10:00:00Z"
}
```

## Phased delivery

Each phase is independently shippable and testable.

### Phase 1 — apex cert + hello

- Embed `lego/v4`.
- Acquire `*.example.com` via DNS-01 on first boot.
- Daily renewal goroutine.
- Hello page on `:443`. Validate green padlock end-to-end.

### Phase 2 — control channel + single-port forward

- TLS control listener on `:7444`.
- Yamux session per client.
- ClientHello/ServerHello with hardcoded `unique=test`.
- Forward `:1977` (only) browser-side → `127.0.0.1:1977` on the client.
- swe-swe accessible via `1977.test-tunnel.example.com` (manual DNS + cert for first cut).

### Phase 3 — registration & identity

- `register.example.com` HTTPS endpoint. JSON over POST.
- SQLite identities.db, REGISTER, CHALLENGE, PROOF, DEREGISTER messages.
- Per-IP and per-pubkey rate limits.
- DNSimple API integration to create/remove `*.{unique}-tunnel.example.com` A records.
- Per-session DNS-01 issuance via lego.

### Phase 4 — multi-port + SNI demux

- Public listener uses `tls.Config.GetCertificate` keyed by middle SNI label.
- Stream header carries `dst_port`.
- Client honors `--port-target` overrides.
- Reject SNIs that don't match `{label}.{unique-tunnel}.example.com`.

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

All messages JSON over a single yamux stream (stream 1 of the control conn). One message per frame. UTF-8.

```
{ "type": "REGISTER",
  "unique": "abc",
  "pubkey": "Ed25519:base64...",
  "timestamp": 1714137600,
  "sig": "base64..." }

{ "type": "CHALLENGE", "nonce": "base64..." }

{ "type": "PROOF", "sig": "base64..." }

{ "type": "REGISTER_OK",
  "unique": "abc",
  "hostname": "abc-tunnel.example.com" }

{ "type": "DENY", "reason": "rate_limited" | "key_mismatch" | "invalid_unique" }

{ "type": "DEREGISTER", "sig": "base64..." }
```

Forwarded streams open as new yamux streams (not stream 1). First frame is a binary `StreamHeader`:

```
struct StreamHeader {
  uint8  version;           // 1
  uint16 dst_port;
  uint8  protocol;          // 0=http, 1=tcp
  uint8  client_addr_len;
  uint8  client_addr[client_addr_len];
}
```
