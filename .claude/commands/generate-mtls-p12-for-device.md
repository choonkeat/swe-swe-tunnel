---
description: Mint a PKCS#12 client cert + passphrase for a browser identity. Stages {cn}.p12 + {cn}.txt under ./generated/ so the operator can copy them to the target device.
---

You are minting a fresh **browser-user** mTLS bundle from the live
production CA in the swe-swe-tunneld container. The output is a
`.p12` (cert + freshly-minted private key, passphrase-protected) and
a sidecar `.txt` holding the passphrase. Both land under
`./generated/` (which is gitignored).

This is a sensitive action — the .p12 contains a private key. The
passphrase .txt is only useful at import time; the user is expected
to delete BOTH files after importing on the target device.

# Run

Work from the repo root: `/repos/swe-swe-tunnel/workspace`. Do
everything via the Bash tool. Report progress with `send_progress`
between steps and a final `send_message` with the on-host paths so
the operator can `scp` them off.

## Inputs

The user invokes `/generate-mtls-p12-for-device <cn>`:

- **`<cn>`** (required) — the browser identity label (e.g.
  `alice-laptop`, `alice-phone`). The CN becomes the
  Subject CN of the cert AND the filename stem under `./generated/`.
  Match `^[a-z0-9._-]{1,63}$`. Reject otherwise — the same string is
  spliced into a filesystem path and an X.509 Subject DN.

If the user omits `<cn>`, ask for one. Do not guess.

## Pre-flight

Run in parallel:

1. `docker ps --format '{{.Names}}' | grep -q '^swe-swe-tunneld$'` —
   container must be running. If not, refuse and point the user at
   `/run-production`.

2. `docker exec swe-swe-tunneld test -f /var/lib/swe-swe-tunnel/mtls/ca.pem`
   — the CA must exist (it lives in the persistent `tunnel-data`
   volume). If not, refuse and tell the operator to run
   `docker compose run --rm swe-swe-tunneld mtls-init` first.

3. Confirm `<cn>` won't clobber an existing artifact:
   ```sh
   docker run --rm -v /repos/swe-swe-tunnel/workspace/generated:/g alpine ls /g/{cn}.p12 /g/{cn}.txt 2>/dev/null
   ```
   Empty output = clean; any hit = existing files. If anything
   exists, ask the user whether to overwrite. Don't silently
   replace — the existing .p12 might already be imported on a
   device and replacing it strands that device.

## Confirm with the user

Before generating, `send_message` summarizing:

- the CN that will appear on the cert,
- the on-host paths the artifacts will land at
  (`/repos/swe-swe-tunnel/workspace/generated/<cn>.p12`,
  `.../generated/<cn>.txt`),
- a reminder: the passphrase is stdout-only at mint time — never
  recoverable later — the .txt file is the operator's single
  capture of it.

Quick replies: `Generate` / `Cancel`.

## Generate + stage

After confirmation:

1. `send_progress`: "minting {cn}.p12 from the production CA…"

2. Mint the bundle inside a `docker compose run --rm` ephemeral
   container so the daemon doesn't pause:
   ```sh
   docker compose run --rm swe-swe-tunneld \
     mtls-issue --cn "<cn>" \
       -o /var/lib/swe-swe-tunnel/mtls/<cn>.p12
   ```
   Capture stdout. Two lines of interest:
   - `wrote /var/lib/swe-swe-tunnel/mtls/<cn>.p12 (PKCS#12, N bytes)`
   - `passphrase: <RANDOM>` — extract the value after the colon.
     If no `passphrase: ` line is present, abort with an error
     (mtls-issue contract was violated).

3. Make sure `./generated/` exists on the HOST (NOT just in this
   dev container — Write goes to the dev container only, and the
   operator needs the file scp-able from the host):
   ```sh
   docker run --rm -v /repos/swe-swe-tunnel/workspace:/repo alpine \
     sh -c 'mkdir -p /repo/generated'
   ```

4. Copy the .p12 out of the `tunnel-data` volume into the host's
   `./generated/`:
   ```sh
   docker run --rm \
     -v /repos/swe-swe-tunnel/workspace/generated:/dst \
     --volumes-from swe-swe-tunneld:ro \
     alpine sh -c 'cp /var/lib/swe-swe-tunnel/mtls/<cn>.p12 /dst/<cn>.p12'
   ```
   `--volumes-from swe-swe-tunneld:ro` mounts the daemon's volumes
   (read-only) so the source path is reachable. Mount `./generated/`
   as `/dst` writable.

5. Write the passphrase to `./generated/<cn>.txt` on the host:
   ```sh
   printf '%s\n' "<passphrase>" | docker run --rm -i \
     -v /repos/swe-swe-tunnel/workspace/generated:/dst alpine \
     sh -c 'cat > /dst/<cn>.txt'
   ```
   Stdout the passphrase via stdin so it never sits in shell
   history or in process args.

6. (Optional but recommended) **Delete the .p12 from the daemon's
   volume** so the secret doesn't accumulate in production state:
   ```sh
   docker exec swe-swe-tunneld rm /var/lib/swe-swe-tunnel/mtls/<cn>.p12
   ```
   The cert is also reproducible — operator can re-issue from the
   CA whenever needed. Leaving the .p12 in the volume forever is a
   loose-secret risk.

## Report

Final `send_message`:

- on-host paths: `/repos/swe-swe-tunnel/workspace/generated/<cn>.p12`
  and `.../<cn>.txt`,
- size of each (use `ls -la`),
- the SHA-256 fingerprint of the cert inside the .p12 (extract on
  the host via `openssl pkcs12 -in <path> -nokeys -passin file:<txt>
  -info 2>/dev/null` if openssl is available; skip silently if not),
- **the post-import cleanup instructions**, verbatim:

  > After importing on the target device, delete both files:
  > `rm generated/<cn>.p12 generated/<cn>.txt`.
  > The cert is reproducible from the CA; the passphrase is not.

- a sentence reminding the operator the passphrase .txt is the
  ONLY copy of the passphrase — losing it before import means
  re-issuing the cert (the .p12 alone is useless).

## Coding rules

- Never echo the passphrase into a log line or a structured log.
- Never write the passphrase via the `Write` tool — go through the
  stdin-piped transient alpine, so the value never traverses the
  tool boundary.
- Never `rm` `./generated/` wholesale. Per-file cleanup is the
  operator's call.
- If any step fails partway, leave both files in place if any
  partial output exists (the .p12 with no .txt is useless without
  the passphrase; surface this in the failure message so the
  operator knows whether to retry or re-issue).
