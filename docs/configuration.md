# Configuration

All flags can be set via env. Every env var is also a flag, and vice versa.

## Server flags / env

| Flag | Env | Default | Required | Notes |
|---|---|---|---|---|
| `--apex-domain` | `SWE_TUNNEL_APEX` | — | yes | DNS apex you control (e.g. `example.com`). All session hostnames are built under this. |
| `--acme-email` | `SWE_TUNNEL_ACME_EMAIL` | — | yes (unless `--no-acme`) | Account email for Let's Encrypt. Not required in `--no-acme` mode. |
| `--no-acme` | `SWE_TUNNEL_NO_ACME` (set to `1`) | `false` | no | Skip ACME entirely; serve only pre-provisioned certs from `{state-dir}/lego/certificates/`. Operator owns issuance (lego, certbot, cert-manager). SIGHUP rescans the cert dir. See [`docs/manual-certs.md`](manual-certs.md). |
| `--state-dir` | `SWE_TUNNEL_STATE` | `~/.swe-swe-tunnel` | no | Persistent dir: `lego/{accounts,certificates}/`, `identities.db`. |
| `--listen` | — | `:443` | no | Address for the public listener. |
| `--dns-provider` | — | `dnsimple` | no | lego DNS-01 provider name. See [`docs/acme-providers.md`](acme-providers.md). Inert when `--no-acme` is set. |
| `--ensure-cert` | — | (off) | no | Admin one-shot: issue `*.{label}.{apex}` and exit. No-op in `--no-acme` mode (issuance is external). |
| `--register-rate-ip-per-hour` | — | `5` | no | Per-IP REGISTER limit. `0` disables. |
| `--register-rate-pubkey-per-day` | — | `10` | no | Per-pubkey REGISTER limit. `0` disables. |
| `--allowlist-dir` | `SWE_TUNNEL_ALLOWLIST_DIR` | (off) | no | Directory of authorized pubkey files; gates Register. See [`docs/access-control.md`](access-control.md). |
| `--allowed-ports` | `SWE_TUNNEL_ALLOWED_PORTS` | `1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898,20000-29999` | no | Inline destination-port allowlist; `all` disables the gate. Restart-only. |
| `--allowed-ports-file` | `SWE_TUNNEL_ALLOWED_PORTS_FILE` | (off) | no | File path holding the port allowlist (multi-line + `#` comments OK). SIGHUP-reloadable. Mutually exclusive with the inline form. |

DNS-provider credentials are read from the lego provider's standard env vars (e.g. `DNSIMPLE_OAUTH_TOKEN` for `dnsimple`, `CF_API_TOKEN` for cloudflare, etc.).

## Client flags / env

| Flag | Env | Default | Required | Notes |
|---|---|---|---|---|
| `--server` | `SWE_TUNNEL_SERVER` | — | yes | Tunneld base URL (e.g. `https://tunnel.example.com`). |
| `--unique` | `SWE_TUNNEL_UNIQUE` | — | yes | Bare label; server appends `-tunnel` (see "Naming" below). |
| `--target` | — | `127.0.0.1` | no | Forward target host. Port comes from the leftmost Host label. |
| `--identity-key` | `SWE_TUNNEL_KEY` | `~/.swe-swe-tunnel/identity.key` | no | Ed25519 private key. Auto-generated on first run. |
| `--report-format` | `SWE_TUNNEL_REPORT_FORMAT` | `none` | no | Structured event stream on stdout: `none` or `jsonl`. See `tasks/2026-04-29-supervisor-event-protocol.md`. |
| `--insecure` | — | `false` | no | Skip TLS verification. Testing only. |

## Naming: `unique` vs `{unique}-tunnel`

Clients submit a **bare** unique (e.g. `alice`). The server validates it against `^[a-z][a-z0-9-]{1,52}[a-z0-9]$` and appends `-tunnel` to form the public DNS label (`alice-tunnel.example.com`). Reasons:

* Carves a namespace inside the apex so a `--unique` can never collide with operational hostnames (`tunnel.example.com`, `register.example.com`, the apex itself).
* The router only treats a host as tunneled if its session-label ends in `-tunnel` — non-tunnel traffic falls through to the apex hello handler.

> Footgun: passing `--unique=alice-tunnel` registers `alice-tunnel-tunnel.example.com`. Regex-valid but cosmetically awkward. We don't reject it (would block legitimate names ending in `-tunnel`).
