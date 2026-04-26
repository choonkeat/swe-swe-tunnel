# swe-swe-tunnel

A self-hosted reverse tunnel for swe-swe (and any localhost-bound HTTP service). One binary on a VPS, one binary on the swe-swe host, browser traffic flows over a single :443 listener with automatic Let's Encrypt wildcard certs.

See [`docs/design.md`](docs/design.md) for the architecture and protocol.

## Status

Phase 2 of 6 — control channel + single-port forward over a single `:443`
listener. Apex cert lifecycle and hello page from Phase 1 carry over.

## Build and run

```sh
# server
go build -o bin/swe-swe-tunneld ./cmd/swe-swe-tunneld
# client
go build -o bin/swe-swe-tunnel  ./cmd/swe-swe-tunnel
```

### Server (one VPS, single port :443)

```sh
DNSIMPLE_OAUTH_TOKEN=... \
./bin/swe-swe-tunneld \
  --apex-domain=example.com \
  --acme-email=you@example.com \
  --state-dir=/var/lib/swe-swe-tunnel
```

On first run it issues `*.example.com` via DNS-01 and persists everything
under `--state-dir`. On boot it also calls `LoadAllFromDisk()` to pick up any
per-session wildcards (`_.{label}.{apex}.crt`).

Issue a per-session cert (admin one-shot, exits after issuance):

```sh
./bin/swe-swe-tunneld --apex-domain=example.com --acme-email=... \
  --state-dir=/var/lib/swe-swe-tunnel \
  --ensure-cert=test-tunnel
```

Restart the server (or wait for a new TLS handshake — `LoadAllFromDisk` is
also reachable per request via the cert manager) so it picks up the new cert.

### Client (on the swe-swe host)

```sh
./bin/swe-swe-tunnel \
  --server=https://tunnel.example.com \
  --unique=test \
  --target=127.0.0.1
```

The client dials `POST /v1/connect`, upgrades to yamux, registers as
`test-tunnel`, and reverse-proxies incoming requests to local TCP services
keyed on the leftmost label of the request's Host. Once running, browsers can
hit `https://1977.test-tunnel.example.com/` and reach `127.0.0.1:1977` on the
swe-swe host.

## State layout

```
/var/lib/swe-swe-tunnel/
└── lego/
    ├── accounts/
    │   └── acme-v02.api.letsencrypt.org/
    │       └── you@example.com/
    │           ├── account.key
    │           └── account.json
    └── certificates/
        ├── _.example.com.crt
        └── _.example.com.key
```

Compatible with the `lego` CLI's layout — you can inspect or operate on the state with the standalone `lego` binary if needed.

## Roadmap

- ~~Phase 1: apex cert + hello~~ ✓
- ~~Phase 2: control channel + single-port forward~~ ✓
- Phase 3: registration + identity (proof-of-possession).
- Phase 4: multi-port polish.
- Phase 5: swe-swe integration. See `/workspace/research/2026-04-26-swe-swe-tunnel-integration.md`.
- Phase 6: ops polish (metrics, graceful drain, runbook).
