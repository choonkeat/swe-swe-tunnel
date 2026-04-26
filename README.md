# swe-swe-tunnel

A self-hosted reverse tunnel for swe-swe (and any localhost-bound HTTP service). One binary on a VPS, one binary on the swe-swe host, browser traffic flows over a single :443 listener with automatic Let's Encrypt wildcard certs.

See [`docs/design.md`](docs/design.md) for the architecture and protocol.

## Status

Phase 1 of 6 — apex cert acquisition + hello server. No tunneling yet.

## Phase 1: build and run

```sh
go build -o swe-swe-tunneld ./cmd/swe-swe-tunneld

DNSIMPLE_OAUTH_TOKEN=... \
./swe-swe-tunneld \
  --apex-domain=example.com \
  --acme-email=you@example.com \
  --state-dir=/var/lib/swe-swe-tunnel \
  --acme-staging
```

On first run it generates an ACME account key, registers with Let's Encrypt, runs DNS-01 against DNSimple to issue `*.example.com`, persists everything under `--state-dir`, and serves a hello page on `:443`.

Drop `--acme-staging` once you're ready to use the real LE production CA. Staging certs aren't trusted by browsers but don't burn rate-limit budget.

```
$ curl --resolve example.com:443:127.0.0.1 https://example.com/
swe-swe-tunnel server
apex: example.com
phase: 1 (apex cert + hello)
```

A daily renewal goroutine wakes up, checks expiry, renews any cert <30 days from expiry, and atomically swaps it into the TLS config (no restart, no dropped connections).

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

- Phase 2: control channel + single-port forward.
- Phase 3: registration + identity (proof-of-possession).
- Phase 4: multi-port + per-session DNS-01.
- Phase 5: swe-swe integration. See `/workspace/research/2026-04-26-swe-swe-tunnel-integration.md`.
- Phase 6: ops polish (metrics, graceful drain, runbook).
