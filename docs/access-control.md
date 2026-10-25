# Access control

Two server-side gates, configured independently:

1. **Pubkey allowlist** — who may register a `unique`.
2. **Port allowlist** — which destination ports may be tunneled.

## Pubkey allowlist

The daemon refuses to start until you choose how `Register` is gated. Set exactly one of:

- `--allowlist-dir=<path>` (env `SWE_TUNNEL_ALLOWLIST_DIR`): only listed Ed25519 pubkeys may register. This is the shipped Compose default.
- `--open-registration` (env `SWE_TUNNEL_OPEN_REGISTRATION=1`): anyone who can reach `/v1/connect` can claim any unclaimed `unique` and trigger a Let's Encrypt issuance. Only the per-IP and per-pubkey rate limits stand in the way, and a stranger can use up the apex's weekly certificate quota. Boot logs a `OPEN REGISTRATION` warning.

Setting neither, or both, exits with code 2. Empty env values count as unset.

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
| neither flag | **refuses to boot** (exit 2) | `refusing to start without a registration gate ...` |
| `--open-registration` | anyone may register | `OPEN REGISTRATION: any Ed25519 key may claim a name ...` (WARN) |
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

The shipped `docker-compose.yml` bind-mounts `./allowlist/` (directory, not file — single-file mounts pin the container to one inode and break atomic writes / `cp` overwrites) and points `SWE_TUNNEL_ALLOWLIST_DIR` at it by default (`/etc/swe-swe-tunneld/allowlist`). A fresh install is deny-all until you add keys. To run open instead, put both lines in `.env`:

```
SWE_TUNNEL_ALLOWLIST_DIR=
SWE_TUNNEL_OPEN_REGISTRATION=1
```

Drop key files into `./allowlist/` and signal:

```sh
docker kill -s HUP swe-swe-tunneld
docker logs --tail 5 swe-swe-tunneld   # expect "allowlist reloaded ..."
```

### Releasing a claimed name

A claimed `unique` stays owned by its key until you release it. Removing a key from the allowlist drops its live session but does **not** free its names. Two admin subcommands work on `{state-dir}/identities.db`:

```sh
swe-swe-tunneld identity-list                       # UNIQUE, PUBKEY, CREATED, LAST_SEEN
swe-swe-tunneld identity-delete alice               # free the name "alice"
swe-swe-tunneld identity-delete --purge-cert alice  # also delete *.alice-tunnel.{apex} cert files
```

In Docker: `docker compose exec swe-swe-tunneld swe-swe-tunneld identity-list`.

`--purge-cert` needs the apex (`--apex` or `SWE_TUNNEL_APEX`, already set in the container). The running daemon keeps the deleted cert in memory until restart. `identity-delete` does not drop a live session for the name; remove the key from the allowlist and SIGHUP for that.

### Why gate after signature verification

A peer who can't sign for the claimed pubkey gets `signature invalid` regardless of allowlist membership — they learn nothing about the list. A peer who *can* sign but isn't allowlisted gets `not_authorized`: this is intentional disclosure to legitimate key holders so an operator can tell a friend "send me your boot fingerprint, I'll add it." The deny log carries `pubkey_fp=<12hex>` so the operator can correlate.

### Out of scope (deferred follow-ups)

- Bearer-token gate on the HTTP upgrade (cheap DoS filter, layerable in front)
- Per-key permissions (which `unique` a key may claim, expiry, labels)
- Automatic expiry of names not seen for N days
- Web/admin UI — the directory is the API
- fsnotify watcher to remove the manual SIGHUP step
- Pending-approval queue (operator approves out-of-band)

## Port allowlist

The destination port in `{port}.{label}-tunnel.{apex}` is gated by a server-side allowlist. The default policy is `1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898,20000-29999` — common dev/web ports plus 9898 (swe-swe primary UI) plus the 20000-29999 band (swe-swe per-session proxies for Preview / Agent View / CDP / VNC). Anything outside the policy gets `404 "port not allowed"` at the apex, **before** the request reaches the tunnel client.

> The 20000-29999 band overlaps a handful of service defaults (MongoDB 27017, RethinkDB 28015 etc.). That trade-off is intentional — the band is load-bearing for the canonical swe-swe consumer. If you run one of those services on its default port AND want `swe-swe-tunnel`, narrow the policy with `--allowed-ports` or `--allowed-ports-file`.

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
