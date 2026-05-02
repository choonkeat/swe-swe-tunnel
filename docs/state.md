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

## Client

`~/.swe-swe-tunnel/identity.key` — Ed25519 PKCS8 PEM, mode `0600`. Auto-generated on first run; the path is overridable via `--identity-key` / `SWE_TUNNEL_KEY`.
