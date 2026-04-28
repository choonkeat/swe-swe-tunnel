# swe-swe-tunnel

A self-hosted reverse tunnel for [swe-swe](https://github.com/choonkeat/swe-swe) (and any localhost-bound HTTP service). One binary on a VPS, one binary on the host machine, browser traffic flows over a single `:443` listener with automatic Let's Encrypt wildcard certs and signed-identity reclaim.

See [`docs/design.md`](docs/design.md) for the architecture and protocol.

## Status

* **Server** (`cmd/swe-swe-tunneld`): production-ready. Single `:443`, registration with Ed25519 identity + per-IP / per-pubkey rate limits, on-demand per-session ACME wildcard certs, `Deregister` for graceful release, `tunnel-state.json` producer for downstream consumers.
* **Client** (`cmd/swe-swe-tunnel`): production-ready. One outbound TLS connection to the server; serves all configured ports of the local host through that one connection.
* **swe-swe consumer** (lives in [the swe-swe repo](https://github.com/choonkeat/swe-swe)): v1 shipped (`--public-hostname` flag + `SWE_PUBLIC_HOSTNAME` env). v1.1 (state-file fallback) tracked in `tasks/2026-04-28-swe-swe-tunnel-state-file-fallback.md` over there.
* **Deferred**: multi-port allowlist (Phase 4), ops polish — `/metrics`, graceful drain, runbook (Phase 6).

## Quickstart

```sh
# server (one VPS)
go build -o bin/swe-swe-tunneld ./cmd/swe-swe-tunneld
DNSIMPLE_OAUTH_TOKEN=... \
  ./bin/swe-swe-tunneld \
    --apex-domain=example.com \
    --acme-email=admin@example.com \
    --state-dir=/var/lib/swe-swe-tunnel
# (issues *.example.com via DNS-01 on first run)

# client (on the host running the local service)
go build -o bin/swe-swe-tunnel ./cmd/swe-swe-tunnel
./bin/swe-swe-tunnel \
  --server=https://tunnel.example.com \
  --unique=alice \
  --target=127.0.0.1
# → registers as `alice-tunnel.example.com`; the local service on
#   127.0.0.1:1977 is now reachable at https://1977.alice-tunnel.example.com/
```

> ⚠ **Before deploying to a non-DNSimple apex, read [ADR-0001](docs/adr/0001-dns-host-multi-label-wildcards.md).** swe-swe-tunneld depends on permissive multi-label wildcard DNS resolution; not every DNS host implements that.

## Configuration

### Server flags / env

| Flag | Env | Default | Required | Notes |
|---|---|---|---|---|
| `--apex-domain` | `SWE_TUNNEL_APEX` | — | yes | DNS apex you control (e.g. `example.com`). All session hostnames are built under this. |
| `--acme-email` | `SWE_TUNNEL_ACME_EMAIL` | — | yes | Account email for Let's Encrypt. |
| `--state-dir` | `SWE_TUNNEL_STATE` | `~/.swe-swe-tunnel` | no | Persistent dir: `lego/{accounts,certificates}/`, `identities.db`. |
| `--listen` | — | `:443` | no | Address for the public listener. |
| `--dns-provider` | — | `dnsimple` | no | lego DNS-01 provider name. See "ACME DNS-01 providers" below. |
| `--ensure-cert` | — | (off) | no | Admin one-shot: issue `*.{label}.{apex}` and exit. |
| `--register-rate-ip-per-hour` | — | `5` | no | Per-IP REGISTER limit. `0` disables. |
| `--register-rate-pubkey-per-day` | — | `10` | no | Per-pubkey REGISTER limit. `0` disables. |

DNS-provider credentials are read from the lego provider's standard env vars (e.g. `DNSIMPLE_OAUTH_TOKEN` for `dnsimple`, `CF_API_TOKEN` for cloudflare, etc.).

### Client flags / env

| Flag | Env | Default | Required | Notes |
|---|---|---|---|---|
| `--server` | `SWE_TUNNEL_SERVER` | — | yes | Tunneld base URL (e.g. `https://tunnel.example.com`). |
| `--unique` | `SWE_TUNNEL_UNIQUE` | — | yes | Bare label; server appends `-tunnel` (see "Naming"). |
| `--target` | — | `127.0.0.1` | no | Forward target host. Port comes from the leftmost Host label. |
| `--identity-key` | `SWE_TUNNEL_KEY` | `~/.swe-swe-tunnel/identity.key` | no | Ed25519 private key. Auto-generated on first run. |
| `--state-file` | `SWE_TUNNEL_STATE_FILE` | `/workspace/.swe-swe/tunnel-state.json` | no | JSON file written after RegisterOK; consumers (e.g. swe-swe) read it. Empty disables. |
| `--insecure` | — | `false` | no | Skip TLS verification. Testing only. |

### Naming: `unique` vs `{unique}-tunnel`

Clients submit a **bare** unique (e.g. `alice`). The server validates it against `^[a-z][a-z0-9-]{1,52}[a-z0-9]$` and appends `-tunnel` to form the public DNS label (`alice-tunnel.example.com`). Reasons:

* Carves a namespace inside the apex so a `--unique` can never collide with operational hostnames (`tunnel.example.com`, `register.example.com`, the apex itself).
* The router only treats a host as tunneled if its session-label ends in `-tunnel` — non-tunnel traffic falls through to the apex hello handler.

> Footgun: passing `--unique=alice-tunnel` registers `alice-tunnel-tunnel.example.com`. Regex-valid but cosmetically awkward. We don't reject it (would block legitimate names ending in `-tunnel`).

## DNS-host requirements (read this before deploying)

The public hostname pattern is **3 labels deep** under the apex: `{port}.{unique}-tunnel.{apex}`. For browsers to reach the tunnel server, the apex's authoritative DNS must resolve every such name to the server's IP using a single wildcard A record:

```
*.example.com  →  <server IP>
```

This works on DNS hosts that match wildcards across **multiple** labels (DNSimple does this — `1977.alice-tunnel.example.com` resolves via `*.example.com`). It does **not** work out of the box on DNS hosts that strictly enforce one-level wildcards per RFC 1034 §4.3.3 (Cloudflare default, AWS Route 53 default, …).

| DNS host | Multi-label wildcard? | Default config works? |
|---|---|---|
| DNSimple | yes | ✅ |
| Cloudflare | no (strict) | ❌ — see ADR-0001 for options |
| AWS Route 53 | no (strict) | ❌ — see ADR-0001 |
| Hetzner DNS | no (strict) | ❌ |
| Gandi LiveDNS | mixed | check before deploying |

(Have first-hand info on a provider not listed? PRs welcome to update this table.)

The boot self-check (`internal/cert`) probes a randomised label at startup and logs a `WARN` if the apex doesn't resolve permissively — the daemon still boots, but the operator sees the misconfiguration immediately rather than from a confused user later.

For the full design rationale — why we chose this over per-session DNS-API record creation, what the integration point looks like for strict-mode hosts, and the boundary with ACME DNS-01 — see [ADR-0001](docs/adr/0001-dns-host-multi-label-wildcards.md).

## ACME DNS-01 providers

Cert issuance uses [lego](https://github.com/go-acme/lego)'s DNS-01 challenge. swe-swe-tunneld currently wires:

| `--dns-provider` | Required env | Notes |
|---|---|---|
| `dnsimple` | `DNSIMPLE_OAUTH_TOKEN` | Default. |

Adding another provider that lego supports is a 5-line change in `cmd/swe-swe-tunneld/main.go` `dnsProviderFactory`:

```go
case "cloudflare":
    return func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() }
```

…plus an import. **PRs adding additional `case` arms are explicitly welcome.** Each should:

1. Add the `case` arm.
2. Add the corresponding env-var documentation row to the table above.
3. If the provider is well-known to be strict-wildcard, note that in the DNS-host table.

The choice of ACME DNS-01 provider is **independent** of the apex DNS host's wildcard semantics. You can use Cloudflare for ACME on a DNSimple-hosted apex, or vice versa — they're orthogonal axes.

## State on disk

```
{state-dir}/
├── identities.db                    # SQLite: unique → pubkey, last_seen_at
└── lego/
    ├── accounts/
    │   └── acme-v02.api.letsencrypt.org/
    │       └── {acme-email}/
    │           ├── account.key
    │           └── account.json
    └── certificates/
        ├── _.{apex}.crt             # apex wildcard
        ├── _.{apex}.key
        ├── _.{label1}.{apex}.crt    # per-session wildcards
        └── _.{label1}.{apex}.key
```

Compatible with the standalone `lego` CLI layout — you can inspect or operate on cert state with `lego` directly if needed.

The client also persists `~/.swe-swe-tunnel/identity.key` (Ed25519 PKCS8 PEM, mode 0600) and writes the post-Connect state file (default `/workspace/.swe-swe/tunnel-state.json`).

## Deregister (graceful release)

A client can release its `unique` cleanly with `Session.Deregister(ctx)` (Go API) — sends a signed `Deregister` frame, server verifies against the stored pubkey, deletes the identity row, replies with `DeregisterOK`, tears down the session. After a successful Deregister, **another client with a different key** can claim the same unique without going through the Challenge/Proof reclaim flow.

Security: a session can only deregister the unique it's authenticated as (defense-in-depth check), and the Deregister sig must verify against the *session's* authenticated pubkey (post-rotation safe). See `cmd/swe-swe-tunneld/deregister_test.go` for the exhaustive test matrix.

## Contributing

* Issues / PRs welcome on GitHub.
* For a new ACME DNS-01 provider, see "ACME DNS-01 providers" above.
* For documentation around alternative DNS hosts (multi-label wildcard behaviour), update the table in this README and add a row to the test plan in [ADR-0001](docs/adr/0001-dns-host-multi-label-wildcards.md).
* All changes ship with extensive unit + e2e tests — `go test -race ./...` should remain clean.
