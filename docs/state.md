# State on disk

## Server (`{state-dir}`)

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

### Ownership (Docker)

The image runs the daemon as UID/GID `10001` (`tunnel`), with no Linux capabilities and `no-new-privileges`. Everything under `{state-dir}` must be owned by that user. `docker-compose.yml` runs a one-shot `volume-perms` service (root, network off, only `CHOWN`/`FOWNER`) before every start, so volumes created by older root-running images are fixed automatically. Without it the daemon exits with `attempt to write a readonly database`.

If you run the image without Compose, fix ownership once yourself:

```sh
docker run --rm -v tunnel-data:/var/lib/swe-swe-tunnel alpine:3.22 chown -R 10001:10001 /var/lib/swe-swe-tunnel
```

Files in the bind-mounted `./allowlist/` only need to be world-readable (mode `0644`).

## Client

`~/.swe-swe-tunnel/identity.key` — Ed25519 PKCS8 PEM, mode `0600`. Auto-generated on first run; the path is overridable via `--identity-key` / `SWE_TUNNEL_KEY`.
