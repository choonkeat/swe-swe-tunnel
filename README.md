# swe-swe-tunnel

A self-hosted reverse tunnel for [swe-swe](https://github.com/choonkeat/swe-swe) (and any localhost-bound HTTP service). One binary on a VPS, one binary on the host machine, browser traffic flows over a single `:443` listener with automatic Let's Encrypt wildcard certs and signed-identity reclaim.

See [`docs/design.md`](docs/design.md) for the architecture and protocol.

## Status

* **Server** (`cmd/swe-swe-tunneld`): production-ready. Single `:443`, registration with Ed25519 identity + per-IP / per-pubkey rate limits, on-demand per-session ACME wildcard certs, `Deregister` for graceful release.
* **Client** (`cmd/swe-swe-tunnel`): production-ready. One outbound TLS connection to the server; serves the configured ports of the local host through that one connection. Emits a structured JSONL event stream on stdout for parent supervisors (`--report-format=jsonl`).
* **Deferred**: ops polish — `/metrics`, graceful drain, runbook (Phase 6).

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
| `--allowlist-dir` | `SWE_TUNNEL_ALLOWLIST_DIR` | (off) | no | Directory of authorized pubkey files; gates Register. See "Access control" below. |
| `--allowed-ports` | `SWE_TUNNEL_ALLOWED_PORTS` | `1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898` | no | Inline destination-port allowlist; `all` disables the gate. Restart-only. |
| `--allowed-ports-file` | `SWE_TUNNEL_ALLOWED_PORTS_FILE` | (off) | no | File path holding the port allowlist (multi-line + `#` comments OK). SIGHUP-reloadable. Mutually exclusive with the inline form. |

DNS-provider credentials are read from the lego provider's standard env vars (e.g. `DNSIMPLE_OAUTH_TOKEN` for `dnsimple`, `CF_API_TOKEN` for cloudflare, etc.).

### Client flags / env

| Flag | Env | Default | Required | Notes |
|---|---|---|---|---|
| `--server` | `SWE_TUNNEL_SERVER` | — | yes | Tunneld base URL (e.g. `https://tunnel.example.com`). |
| `--unique` | `SWE_TUNNEL_UNIQUE` | — | yes | Bare label; server appends `-tunnel` (see "Naming"). |
| `--target` | — | `127.0.0.1` | no | Forward target host. Port comes from the leftmost Host label. |
| `--identity-key` | `SWE_TUNNEL_KEY` | `~/.swe-swe-tunnel/identity.key` | no | Ed25519 private key. Auto-generated on first run. |
| `--ports` | `SWE_TUNNEL_PORTS` | (built-in safe set) | no | (deprecated; the server owns the port allowlist as of `--allowed-ports` — kept until commit 3 of `tasks/2026-05-02-server-side-port-allowlist.md`) Comma-separated allowlist of forwardable ports (ranges OK: `3000-3099`); `all` disables the gate. |
| `--report-format` | `SWE_TUNNEL_REPORT_FORMAT` | `none` | no | Structured event stream on stdout: `none` or `jsonl`. See `tasks/2026-04-29-supervisor-event-protocol.md`. |
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

The client persists `~/.swe-swe-tunnel/identity.key` (Ed25519 PKCS8 PEM, mode 0600).

## Access control: pubkey allowlist

By default, anyone who can reach `:443/v1/connect` can register a fresh keypair under any unclaimed `unique` and consume an LE issuance. For a friends-and-family deployment that's usually fine; the per-IP and per-pubkey rate limits keep blast radius small. For more control, the daemon supports an optional Ed25519 pubkey **allowlist** that gates `Register` after signature verification.

### Enabling

Pass `--allowlist-dir=<path>` (or set `SWE_TUNNEL_ALLOWLIST_DIR`). The directory contains one or more files; each file holds zero or more base64-RawStd Ed25519 pubkeys, one per line, with `#` comments and blank lines ignored. Filenames are free-form labels — `alice-laptop.pub`, `bob.pub`, `ci-runner.pub`. Dotfiles and subdirectories are ignored.

```sh
mkdir -p ./allowlist
printf '%s  # alice@laptop\n' "$ALICE_PUB_BASE64" > ./allowlist/alice-laptop.pub
swe-swe-tunneld --apex-domain=example.com ... --allowlist-dir=./allowlist
```

Three states, distinguishable in the boot log:

| Setting | Behavior | Boot log |
|---|---|---|
| flag unset | open registration (default) | `allowlist disabled (no --allowlist-dir set; open registration)` |
| flag set, dir empty | **deny everyone** (explicit operator intent) | `allowlist loaded (deny-all) ... files=0 count=0` |
| flag set, N keys | allow those N | `allowlist loaded ... files=F count=N` |

Boot fails loud (`exit 1`) if any file in the directory is malformed — silently falling back to open-registration would defeat the operator's intent.

### Adding / removing keys without a restart

Edit the directory on disk, then signal SIGHUP:

```sh
# Add — drop a file in:
printf '%s  # alice@laptop\n' "$NEW_PUB" > ./allowlist/alice-laptop.pub
# Remove — delete the file:
rm ./allowlist/alice-laptop.pub
# Signal reload + revoke:
kill -HUP $(pidof swe-swe-tunneld)
```

On a successful SIGHUP reload the daemon logs `allowlist reloaded ... added=N removed=M` and **immediately closes any live yamux sessions whose pubkey is no longer authorized**. The client's reconnect loop then receives `not_authorized` on retry and the supervisor stops. A reload that fails to parse keeps the prior in-memory set in place (with `keeping_previous=true` in the log) and does **not** drop sessions — a typo'd file mid-flight should not flip the gate to deny-all.

### Docker workflow

The shipped `docker-compose.yml` already bind-mounts `./allowlist/` (directory, not file — single-file mounts pin the container to one inode and break atomic writes / `cp` overwrites). To enable the gate, add to your `.env`:

```
SWE_TUNNEL_ALLOWLIST_DIR=/etc/swe-swe-tunneld/allowlist
```

Then drop key files into `./allowlist/` and signal:

```sh
docker kill -s HUP swe-swe-tunneld
docker logs --tail 5 swe-swe-tunneld   # expect "allowlist reloaded ..."
```

### Why gate after signature verification

A peer who can't sign for the claimed pubkey gets `signature invalid` regardless of allowlist membership — they learn nothing about the list. A peer who *can* sign but isn't allowlisted gets `not_authorized`: this is intentional disclosure to legitimate key holders so an operator can tell a friend "send me your boot fingerprint, I'll add it." The deny log carries `pubkey_fp=<12hex>` so the operator can correlate.

### Out of scope (deferred follow-ups)

- Bearer-token gate on the HTTP upgrade (cheap DoS filter, layerable in front)
- Per-key permissions (which `unique` a key may claim, expiry, labels)
- Web/admin UI — the directory is the API
- fsnotify watcher to remove the manual SIGHUP step
- Pending-approval queue (operator approves out-of-band)

## Access control: port allowlist

The destination port in `{port}.{label}-tunnel.{apex}` is gated by a server-side allowlist. The default policy is `1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898` — common dev/web ports plus 9898 (swe-swe primary UI). Anything outside the policy gets `404 "port not allowed"` at the apex, **before** the request reaches the tunnel client.

This was previously a client-side decision (and still is, until commit 3 of the migration completes). Owning it on the server means each tunnel operator picks one policy that applies to every tenant, and clients no longer need to know which ports are reachable.

### Enabling / overriding

Two mutually-exclusive flags:

| Flag | When to use | Reload? |
|---|---|---|
| `--allowed-ports=<spec>` (env: `SWE_TUNNEL_ALLOWED_PORTS`) | One-line policy that doesn't change after boot | restart-only |
| `--allowed-ports-file=<path>` (env: `SWE_TUNNEL_ALLOWED_PORTS_FILE`) | Policy lives in a file the operator edits | SIGHUP-reloadable |

The file form accepts both single-line specs and multi-line files with `#` comments and blank lines:

```
# /etc/swe-swe-tunneld/allowed-ports
1977       # swe-swe primary
3000-3099  # dev range
9898       # swe-swe UI in tunnel mode
```

`spec="all"` disables the gate (every port permitted). Don't ship that to production — the apex operator is the only thing standing between the public internet and every localhost port the tunnel client can reach.

### Reloading

```sh
$EDITOR /path/to/allowed-ports
docker kill -s HUP swe-swe-tunneld
docker logs --tail 5 swe-swe-tunneld   # expect "port allowlist reloaded ... changed=true"
```

A reload that fails to parse keeps the prior in-memory policy in place (logged as `port allowlist reload failed ... keeping_previous=true`). A typo'd file mid-flight does not flip the gate to deny-all — the operator can fix the file and HUP again.

The boot log records which source is in effect:

```
port allowlist spec=1977,3000-3099,...,9898 source=default
port allowlist spec=...                     source=flag
port allowlist spec=...                     source=env
port allowlist spec=...                     source=file:/etc/swe-swe-tunneld/allowed-ports
```

### Why server-side?

- The apex operator is the only party with authority over what ports the tunnel exposes; they're better placed than each client to keep the policy current.
- One configuration point removes drift across tenants (no "client A's `--ports` says X, client B's says Y").
- A request denied by the gate never enters the yamux session, so the tunnel client is unaware of policy decisions and doesn't need to be re-released to change them.

### Out of scope

- Per-pubkey port policies — one global set is enough for the current operator profile.
- A "deny" list — the allowlist *is* the policy; subtraction is editing the allowlist.
- `>=N` shorthand — operators can already write `1024-65535` to express "any unprivileged port".

## Deregister (graceful release)

A client can release its `unique` cleanly with `Session.Deregister(ctx)` (Go API) — sends a signed `Deregister` frame, server verifies against the stored pubkey, deletes the identity row, replies with `DeregisterOK`, tears down the session. After a successful Deregister, **another client with a different key** can claim the same unique without going through the Challenge/Proof reclaim flow.

Security: a session can only deregister the unique it's authenticated as (defense-in-depth check), and the Deregister sig must verify against the *session's* authenticated pubkey (post-rotation safe). See `cmd/swe-swe-tunneld/deregister_test.go` for the exhaustive test matrix.

## Contributing

* Issues / PRs welcome on GitHub.
* For a new ACME DNS-01 provider, see "ACME DNS-01 providers" above.
* For documentation around alternative DNS hosts (multi-label wildcard behaviour), update the table in this README and add a row to the test plan in [ADR-0001](docs/adr/0001-dns-host-multi-label-wildcards.md).
* All changes ship with extensive unit + e2e tests — `go test -race ./...` should remain clean.
