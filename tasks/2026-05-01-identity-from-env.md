# Tunnel client: identity key from env var (file-less mode)

## Status

**Shipped (2026-05-02).** `SWE_TUNNEL_IDENTITY_KEY` env loader is live
in `internal/tunnelclient/identity.go` (`LoadIdentity`,
`parseB64Identity`, `logIdentityFingerprint`) with the precedence
rule and disk-write regression gate exactly as specified below.
Commits `08dc0a4` / `6031394`. Tests in `identity_test.go` cover the
seven branches enumerated under "Tests".

Companion task in the consumer repo:
`/workspace/tasks/2026-04-29-tunnel-subprocess-pivot.md` (Update
2026-04-30 section). Consumer is `choonkeat/swe-swe`'s
`swe-swe-server`; it spawns this client as a subprocess. The deploy
story discussed in that companion is "user runs `swe-swe up` on a PaaS
in tunnel mode"; today that requires a persistent volume mount at
`/home/app/.swe-swe-tunnel/` to survive across container restarts.
This task removes the mandatory file dependency.

## Why

The empirical motivator: identity-on-disk is already burning dead
`unique` labels on the production tunneld in normal dev iteration.
The current tunneld cert dir lists four orphaned wildcards
(`_.swe-swe-test-aaaaaaaa-tunnel.example.com`,
`_.swe-swe-test-bbbbbbbb-tunnel.example.com`,
`_.swe-swe-manual-cccccccc-tunnel.example.com`,
`_.swe-swe-manual-dddddddd-tunnel.example.com`) — each one is a
container that booted with no identity on disk, generated a fresh
key, claimed a fresh `unique`, then went away. The keys are gone but
tunneld cannot free the bindings, because the only proof-of-ownership
it accepts is a signature from the original key. That's a permanent
namespace leak per dev rebuild.

The same shape causes a worse failure mode at runtime. A container
that *does* try to reuse a `unique` it previously held but lost the
key gets `key_mismatch` from tunneld, which the client now treats as
`kind=fatal` (the supervisor stops, no retry). If the operator
re-rolls the unique to escape that, they consume a slot in the
per-pubkey new-unique limit and burn another LE-cert order. The
rate-limit bucket exists to discourage abuse, not to punish a
container restart.

A second motivator, secondary in priority, is the deploy story
called out in the companion task: ephemeral PaaS dynos and immutable
infra (K8s, Cloud Run) where the operator wants identity in a Secret,
not on disk. That's a real future requirement, but the chat-driven
foot-gun above is what tips the priority into "now."

The minimal fix: let the operator hand the identity in via env var.
swe-swe-server inherits env automatically when it spawns the client,
so this becomes a clean deploy story for both cases — set one secret
env var, deploy.

## Scope

In-scope:

- New env var `SWE_TUNNEL_IDENTITY_KEY` carrying the full PKCS8 PEM
  block, base64-encoded with no embedded newlines so it round-trips
  through env vars and PaaS dashboards cleanly.
- Precedence rule: `SWE_TUNNEL_IDENTITY_KEY` > file at
  `--identity-key-file=<path>` (existing default) > auto-generate to
  that file.
- Loud-failure path when the env value fails to parse or decode (don't
  silently fall through to the file -- the operator intended the env
  path; honor that).
- The env-loaded path must NOT touch disk. No `MkdirAll`, no
  `WriteFile`, no read-attempt against `--identity-key-file`. This is
  the property that makes the feature safe on a read-only PaaS root
  filesystem.
- Boot-time identity fingerprint log line (see "Operator confidence"
  below).
- Tests for each precedence branch and for the failure modes,
  including a regression test that env-only loads make zero filesystem
  writes.

Out of scope:

- A `--identity-key=<base64>` *flag*. We deliberately don't add one
  (see "Security" below — argv leaks via `ps`). Operators who need a
  flag-style escape hatch can use `--identity-key-file=/dev/stdin`
  with the existing flag, which doesn't add a new code path.
- Removing the file path entirely. The file path remains the default
  for users running on a host with persistent disk; we just stop
  *requiring* it.
- A CLI subcommand that *generates* a key for the operator to paste
  into env. That's planned as `swe-swe tunnel-identity create` on the
  consumer side (this client doesn't need to grow the subcommand;
  the consumer has the better surface for it). Tracked as a
  follow-up — see "Sequencing".
- Loading from a Docker secret / K8s downward-API file (a "read this
  file path at boot" mode). Operators who want that can set
  `--identity-key-file=/var/run/secrets/...` -- the existing flag
  already covers it.
- A tunneld-side TTL / GC for orphaned uniques. Worth doing eventually
  but a separate concern; this task closes the *new* leaks without
  reclaiming the old ones.

## Security

`SWE_TUNNEL_IDENTITY_KEY` carries a private key. Two design choices
follow:

1. **Env-only, no flag.** A `--identity-key=<base64>` flag would put
   the private key on argv, where any user on the host can read it
   via `ps`, `/proc/<pid>/cmdline`, or any monitoring agent that
   slurps process tables. Env vars are visible to the same parties
   *in principle* (`/proc/<pid>/environ`) but in practice are far
   less commonly logged or printed by tooling, and the kernel
   permissions on `environ` are stricter than on `cmdline`. A flag
   would be a real exposure for a small ergonomic win, so we don't
   ship it.

2. **The fingerprint log line uses a SHA-256 prefix, not the key.**
   The boot log emits `identity loaded fingerprint=<first-12-hex>
   source=env|file` so the operator can confirm "yes, I deployed the
   right key." The full hash is not logged (no need; 12 hex chars =
   48 bits, plenty for human identification, no useful signal for
   an attacker who somehow gets the log).

## Operator confidence: fingerprint log line

On boot, regardless of source, log:

```
identity loaded source=env       fingerprint=ab12cd34ef56
identity loaded source=file path=/home/app/.swe-swe-tunnel/identity.key fingerprint=ab12cd34ef56
```

The fingerprint is `hex(sha256(pubkey))[:12]`. Operators can:

- Compare to the fingerprint shown by the consumer-side `swe-swe
  tunnel-identity create` command (when that lands) to verify the
  right key got into the right env.
- Diff fingerprints across deploys to confirm no identity drift.
- Cross-reference against tunneld's identity store when debugging
  `key_mismatch`.

This is two lines of code; the value-per-line is high.

## Encoding

Base64 of the full PKCS8 PEM block (i.e. `base64 -w0 < identity.key`).
Round-trips:

```sh
# Export from a running container with a file-based identity:
SWE_TUNNEL_IDENTITY_KEY=$(base64 -w0 < /home/app/.swe-swe-tunnel/identity.key)

# Decode back to PEM (e.g. when migrating between PaaS providers):
echo "$SWE_TUNNEL_IDENTITY_KEY" | base64 -d > identity.key
```

Why base64-of-PEM rather than raw base64-of-DER:
- Symmetry with the on-disk format. Operators already know PEM.
- One env var = one identity, no separate "format" knob.
- Decoded output drops straight into a file-based identity-key-file
  path -- migration between PaaS becomes "export from one, paste into
  the other," not "extract DER, re-encode PEM, write file."

Tradeoff: PEM is ~30% larger than DER. Ed25519 PKCS8 PEM is ~120
bytes; even the tightest mainstream PaaS env-var size limit (Heroku:
24KB total per dyno) has ample headroom.

## Producer ↔ consumer coordination

Identity is only half of the (`unique`, `pubkey`) pair tunneld stores.
The consumer still passes `--tunnel-unique=<label>` separately. If
the env-loaded key was originally bound to `unique=foo` on tunneld
and the operator deploys with `--tunnel-unique=bar`, the client gets
`Deny{reason="key_mismatch", kind=fatal}` and the supervisor stops
permanently (no retry).

The task does not solve this — the consumer-side `swe-swe
tunnel-identity create` follow-up (see "Sequencing") is the right
place to bind a freshly-minted key to a specific unique and emit a
single env-var blob (or a pair) that the operator pastes. In the
meantime, the README / consumer docs should call out:

> If you set `SWE_TUNNEL_IDENTITY_KEY`, you must also pass the
> `--tunnel-unique` value the key was originally claimed under.
> Mismatched pair → fatal `key_mismatch`.

## Implementation sketch

In `internal/tunnelclient/identity.go`:

```go
// LoadIdentity returns the Ed25519 private key, resolving in this
// precedence order:
//
//   1. SWE_TUNNEL_IDENTITY_KEY env var
//   2. file at filePath (existing path; auto-generate + write if absent)
//
// When the env var is set but malformed, this returns an error WITHOUT
// falling through to the file -- the operator intended the env path.
//
// When the env var is set and valid, the file at filePath is NOT read
// or written; we never touch disk in the env-loaded mode. This is the
// property that lets the client run on a read-only filesystem.
func LoadIdentity(filePath string, logger *slog.Logger) (ed25519.PrivateKey, error) {
    if envB64 := os.Getenv("SWE_TUNNEL_IDENTITY_KEY"); envB64 != "" {
        priv, err := parseB64Identity(envB64)
        if err != nil {
            return nil, fmt.Errorf("SWE_TUNNEL_IDENTITY_KEY: %w", err)
        }
        logIdentityFingerprint(logger, priv, "env", "")
        return priv, nil
    }
    priv, err := LoadOrCreateIdentity(filePath, logger)
    if err != nil {
        return nil, err
    }
    logIdentityFingerprint(logger, priv, "file", filePath)
    return priv, nil
}

func parseB64Identity(s string) (ed25519.PrivateKey, error) {
    pemBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
    if err != nil {
        return nil, fmt.Errorf("base64 decode: %w", err)
    }
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("not PEM after base64 decode")
    }
    key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("parse PKCS8: %w", err)
    }
    priv, ok := key.(ed25519.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("identity is %T, want ed25519.PrivateKey", key)
    }
    return priv, nil
}

func logIdentityFingerprint(logger *slog.Logger, priv ed25519.PrivateKey, source, path string) {
    pub := priv.Public().(ed25519.PublicKey)
    sum := sha256.Sum256(pub)
    fp := hex.EncodeToString(sum[:6]) // 12 hex chars
    if path != "" {
        logger.Info("identity loaded", "source", source, "path", path, "fingerprint", fp)
    } else {
        logger.Info("identity loaded", "source", source, "fingerprint", fp)
    }
}
```

`LoadOrCreateIdentity` stays unchanged for backwards compatibility --
this just adds `LoadIdentity` as the new public entry point, with
`LoadOrCreateIdentity` still callable directly when a caller
specifically wants the file-only path (e.g. tests).

In `cmd/swe-swe-tunnel/main.go`:

- Replace the `LoadOrCreateIdentity` call site with `LoadIdentity`,
  passing through the existing `--identity-key-file` flag value.

No new flag. No new wiring beyond that one call-site swap.

## Tests

Per the standing pattern (the existing `identity_test.go` is the
template):

- **env wins over file** (regression gate for the precedence rule):
  set env, point file to a different existing identity, assert env
  wins (file is not read).
- **invalid base64 in env fails loud**: parse error must propagate;
  no silent file fallback.
- **invalid PEM in env fails loud**: same.
- **wrong key type in env fails loud** (e.g. RSA): same.
- **valid env round-trips**: write a key to a file, base64 it, set
  env, load it, assert the loaded key matches.
- **env path makes no disk writes** (security/PaaS regression gate):
  set env, point `filePath` at a path inside a directory the test
  has marked read-only (or just observe via `os.Stat` that no file
  was created at the path). The test fails if the env-loaded code
  ever calls `MkdirAll` or `WriteFile`.
- **no env, no file**: existing auto-generate path still works
  (regression gate against the file mode).
- **no env, file present**: existing read-from-file path still works
  (regression gate).
- **fingerprint log line**: capture the slog output via a memory
  handler, assert one `identity loaded` line per call with the
  expected `source` field and a 12-hex `fingerprint` field. Don't
  pin the fingerprint value (couples test to test-only key bytes);
  just shape-check.

## Compatibility

Fully additive. Existing deployments that:

- Mount a volume at the identity-key-file path: unaffected.
- Don't set the new env: unaffected (file-based load + auto-generate
  still runs).
- Set the new env in addition to having a file on disk: env wins.
  This is intentional: env is the explicit operator intent. The file
  is left untouched (we don't read it, we don't update it, we don't
  delete it).

No deprecation, no breaking change. Consumers that don't know about
the new env var keep working byte-identically.

## Sequencing

1. Land this task in this repo (the producer). Tag a release or note
   the commit SHA.
2. Bump the consumer's `SWE_SWE_TUNNEL_REF` arg in
   `cmd/swe-swe/templates/host/Dockerfile` to pick up the change.
3. Open a follow-up in the consumer repo for `swe-swe
   tunnel-identity create` -- a subcommand that prints
   `SWE_TUNNEL_IDENTITY_KEY=<base64>` (and the fingerprint, for
   parity with the producer's boot log) for easy paste into PaaS env.
   This is the "right surface" for key minting; the producer
   intentionally doesn't grow it. Until that subcommand lands, the
   migration recipe is the `base64 -w0 < identity.key` snippet
   above.

## Coding rules to honor

- ASCII only in code/markdown.
- No silent goroutine `cmd.Wait()` (irrelevant here -- no goroutines
  added -- but the standing rule).
- Direct commits on `main`, no feature branch (matches this repo's
  shipped-pattern history).
- Loud-failure on parse errors: don't fall back silently when the
  operator clearly intended the env path.
- The env-loaded path must not touch disk. Pin this with a test, not
  just a comment.
