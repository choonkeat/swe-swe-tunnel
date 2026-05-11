# swe-swe-tunnel

A self-hosted reverse tunnel for [swe-swe](https://github.com/choonkeat/swe-swe) (and any localhost-bound HTTP service). One binary on a VPS, one binary on the host machine — browser traffic flows over a single `:443` listener with automatic Let's Encrypt wildcard certs.

```
  3000.alice-tunnel.example.com ──┐  ┌───────────────────┐                    ┌────────────────┐  ┌──▶ 127.0.0.1:3000
  8000.alice-tunnel.example.com ──┼─▶│  swe-swe-tunneld  │◀── one TLS conn ──▶│ swe-swe-tunnel │──┼──▶ 127.0.0.1:8000
  9000.alice-tunnel.example.com ──┘  │  (your VPS, :443) │                    │  (your laptop) │  └──▶ 127.0.0.1:9000
                                     └───────────────────┘                    └────────────────┘
```

See [`docs/design.md`](docs/design.md) for the architecture and protocol.

---

## Server quickstart

Assumes a VPS, a domain at **DNSimple**, and Docker. For other DNS hosts read [`docs/dns-hosts.md`](docs/dns-hosts.md) first — not all of them resolve multi-label wildcards.

### 1. Point a wildcard A record at the server

```
*.example.com   A   <your VPS public IP>
```

That single record covers both the registration endpoint (`tunnel.example.com`) and every per-session hostname (`{port}.{unique}-tunnel.example.com`).

### 2. Drop a `.env` next to `docker-compose.yml`

```sh
# .env
SWE_TUNNEL_APEX=example.com
SWE_TUNNEL_ACME_EMAIL=admin@example.com
DNSIMPLE_OAUTH_TOKEN=dnsimple_a_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 3. Start the daemon

```sh
docker compose up -d
docker logs -f swe-swe-tunneld   # first run issues *.example.com via Let's Encrypt DNS-01
```

Done. The server now listens on `:443` and is ready to accept tunnel registrations.

> Also supports `--dns-provider=route53` (uses the AWS SDK default credential chain, so IAM roles on Lightsail/EC2/ECS-Fargate work without static keys). Other lego providers (Cloudflare, …) are a 5-line patch to `cmd/swe-swe-tunneld/main.go`. See [`docs/acme-providers.md`](docs/acme-providers.md).

> Don't want to give tunneld a DNS API token? Run with `--no-acme` and provision the certs yourself (lego, certbot, cert-manager, …). See [`docs/manual-certs.md`](docs/manual-certs.md).

---

## Client quickstart

Runs on the machine hosting the local service you want to expose.

### 1. Install the client

```sh
go install github.com/choonkeat/swe-swe-tunnel/cmd/swe-swe-tunnel@latest
```

### 2. Start something locally to expose

Any HTTP service on a port in the [default allowlist](docs/access-control.md#port-allowlist). For demo purposes, serve the current directory as browsable markdown on port 3000:

```sh
npx @choonkeat/md-serve --port 3000
```

### 3. Start the tunnel client

```sh
swe-swe-tunnel \
  --server=https://tunnel.example.com \
  --unique=alice
```

On first run it generates `~/.swe-swe-tunnel/identity.key` and registers as `alice-tunnel.example.com`.

> **Deploying on a PaaS / container with no persistent volume?**
> Hand the identity in via env var instead of a file — the client will skip disk I/O entirely. Generate the key once, locally, and stash both halves where they belong:
>
> ```sh
> # Generate the keypair, one-time, on a trusted machine.
> openssl genpkey -algorithm Ed25519 -out identity.key
>
> # Private half: base64 the PEM. This becomes the SECRET env var on the PaaS —
> # treat it like an SSH private key.
> SWE_TUNNEL_IDENTITY_KEY=$(base64 -w0 < identity.key)
>
> # Public half: 32 bytes, base64 RawStd. Send this one-liner to whoever runs
> # the tunnel server so they can drop it into the allowlist (if enabled).
> openssl pkey -in identity.key -pubout -outform DER | tail -c 32 | base64 -w0 | tr -d '='
>
> # Wipe the local key file — SWE_TUNNEL_IDENTITY_KEY now has the only copy.
> rm identity.key
> ```
>
> Set these on the PaaS (mark `SWE_TUNNEL_IDENTITY_KEY` as a secret):
>
> ```sh
> SWE_TUNNEL_SERVER=https://tunnel.example.com
> SWE_TUNNEL_UNIQUE=alice
> SWE_TUNNEL_IDENTITY_KEY=<base64-PEM from above>
> ```
>
> `SWE_TUNNEL_IDENTITY_KEY` and `SWE_TUNNEL_UNIQUE` are a bound pair — re-deploys with the same pair keep the same public hostname; a mismatched pair gets `Deny{key_mismatch, kind=fatal}` and the supervisor stops with no retry. Save them somewhere safe.

### 4. Visit your service

```
https://3000.alice-tunnel.example.com/
```

The leftmost label is the local port. To expose a different port, just visit `https://<port>.alice-tunnel.example.com/` — no client restart needed.

---

## More documentation

| Topic | Doc |
|---|---|
| All flags + env vars (server & client), naming rules | [`docs/configuration.md`](docs/configuration.md) |
| DNS-host requirements (multi-label wildcards) | [`docs/dns-hosts.md`](docs/dns-hosts.md) |
| ACME DNS-01 providers (adding new ones) | [`docs/acme-providers.md`](docs/acme-providers.md) |
| Manual cert workflow (`--no-acme`) | [`docs/manual-certs.md`](docs/manual-certs.md) |
| Pubkey allowlist + port allowlist | [`docs/access-control.md`](docs/access-control.md) |
| Deregister (graceful release) | [`docs/deregister.md`](docs/deregister.md) |
| State on disk | [`docs/state.md`](docs/state.md) |
| Architecture & protocol | [`docs/design.md`](docs/design.md) |
| ADR-0001 — multi-label wildcards | [`docs/adr/0001-dns-host-multi-label-wildcards.md`](docs/adr/0001-dns-host-multi-label-wildcards.md) |

## Contributing

* Issues / PRs welcome on GitHub.
* For a new ACME DNS-01 provider, see [`docs/acme-providers.md`](docs/acme-providers.md).
* For documentation around alternative DNS hosts, update the table in [`docs/dns-hosts.md`](docs/dns-hosts.md) and add a row to the test plan in [ADR-0001](docs/adr/0001-dns-host-multi-label-wildcards.md).
* All changes ship with extensive unit + e2e tests — `go test -race ./...` should remain clean.
