---
description: Mint a PKCS#12 client cert + passphrase for a browser identity, signed by the ECDSA CA so it works on macOS. Stages {cn}.p12 + {cn}.txt + the ECDSA CA cert + a {cn}-README.txt of import instructions + a {cn}.tgz bundling all four under ./generated/ so the operator can copy them to the target device.
---

You are minting a fresh **browser-user** mTLS bundle from the live
production CA in the swe-swe-tunneld container. The output is a
`.p12` (cert + freshly-minted private key, passphrase-protected) and
a sidecar `.txt` holding the passphrase. Both land under
`./generated/` (which is gitignored) **in this dev container**, where
the operator can fetch them via the dev container's normal file
download path (the same way they fetched the earlier `alice.crt`).

This is a sensitive action — the .p12 contains a private key. The
passphrase .txt is only useful at import time; the user is expected
to delete BOTH files after importing on the target device.

# Run

Work from the repo root: `/repos/swe-swe-tunnel/workspace`. Do
everything via the Bash and Write tools. Report progress with
`send_progress` between steps and a final `send_message` with the
dev-container paths so the operator can fetch them.

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

2. `docker exec swe-swe-tunneld test -f /var/lib/swe-swe-tunnel/mtls-ecdsa/ca.pem`
   — the **ECDSA P-256** CA must exist (it lives in the persistent
   `tunnel-data` volume at `{state}/mtls-ecdsa/`). This is the CA
   that browser `.p12` bundles MUST be signed by — macOS refuses to
   import/trust the legacy Ed25519 CA at `{state}/mtls/`
   (`OSStatus -25257`), so a leaf signed by it is unusable on a Mac
   even though the leaf key itself is ECDSA. See `docs/mtls.md`
   "Apple client recipe". If `mtls-ecdsa/ca.pem` is missing, refuse
   and tell the operator to run
   `docker compose run --rm swe-swe-tunneld mtls-init --dir /var/lib/swe-swe-tunnel/mtls-ecdsa`
   first (then append its cert to the `--mtls-ca` bundle + SIGHUP).

3. Confirm `<cn>` won't clobber an existing artifact in the dev
   container:
   ```sh
   ls generated/<cn>.p12 generated/<cn>.txt 2>/dev/null
   ```
   Empty output = clean; any hit = existing files. If anything
   exists, ask the user whether to overwrite. Don't silently
   replace — the existing .p12 might already be imported on a
   device and replacing it strands that device.

## Confirm with the user

Before generating, `send_message` summarizing:

- the CN that will appear on the cert,
- that it is signed by the **ECDSA CA** (`{state}/mtls-ecdsa`) so it
  works on macOS,
- the dev-container paths the artifacts will land at
  (`./generated/<cn>.p12`, `./generated/<cn>.txt`,
  `./generated/swe-swe-tunnel-ecdsa-ca.pem`,
  `./generated/<cn>-README.txt`, `./generated/<cn>.tgz`),
- a reminder: the passphrase is stdout-only at mint time — never
  recoverable later — the .txt file is the operator's single
  capture of it.

Quick replies: `Generate` / `Cancel`.

## Generate + stage

After confirmation:

1. `send_progress`: "minting {cn}.p12 from the production CA…"

2. Mint the bundle inside a `docker compose run --rm` ephemeral
   container so the daemon doesn't pause. **Sign against the ECDSA
   CA via `--dir`** — without it `mtls-issue` defaults to
   `{state}/mtls` (the legacy Ed25519 CA) and the resulting `.p12`
   will not work on macOS. The .p12 lands in the `tunnel-data`
   volume; the passphrase prints to stdout:
   ```sh
   docker compose run --rm swe-swe-tunneld \
     mtls-issue --dir /var/lib/swe-swe-tunnel/mtls-ecdsa --cn "<cn>" \
       -o /var/lib/swe-swe-tunnel/mtls-ecdsa/<cn>.p12
   ```
   Capture stdout. Two lines of interest:
   - `wrote /var/lib/swe-swe-tunnel/mtls/<cn>.p12 (PKCS#12, N bytes)`
   - `passphrase: <RANDOM>` — extract the value after the colon.
     If no `passphrase: ` line is present, abort with an error
     (mtls-issue contract was violated).

3. Make sure `./generated/` exists in the dev container:
   ```sh
   mkdir -p generated
   ```

4. Copy the .p12 out of the `tunnel-data` volume into the dev
   container's `./generated/`. `docker cp` interprets the
   destination path relative to THIS shell — i.e. the dev
   container's filesystem — which is exactly where we want it:
   ```sh
   docker cp swe-swe-tunneld:/var/lib/swe-swe-tunnel/mtls-ecdsa/<cn>.p12 \
     generated/<cn>.p12
   ```

5. Write the passphrase to `./generated/<cn>.txt` via the Write
   tool, with content = the passphrase + one trailing newline.
   The Write goes to the dev container's filesystem at the
   absolute path `/repos/swe-swe-tunnel/workspace/generated/<cn>.txt`.

6. **Stage the ECDSA CA cert** so the operator can TRUST it on the
   Mac (step 3 of the Apple recipe — the `.p12` alone imports as an
   untrusted identity hidden from the SSL-client policy). The CA
   cert is public, not a secret:
   ```sh
   docker cp swe-swe-tunneld:/var/lib/swe-swe-tunnel/mtls-ecdsa/ca.pem \
     generated/swe-swe-tunnel-ecdsa-ca.pem
   ```

7. **Write the import instructions** to
   `./generated/<cn>-README.txt` via the Write tool, so the operator
   (or whoever receives the bundle) carries the recipe with the
   files instead of relying on chat scrollback. ASCII only,
   substitute `<cn>` and `<apex>` (the apex from the daemon's boot
   log, e.g. `example.com`). Content:
   ```text
   swe-swe-tunnel mTLS browser identity: <cn>
   Signed by the ECDSA CA (works on macOS Safari/Chrome).

   Files in this bundle:
     <cn>.p12                       cert + private key (passphrase-protected)
     <cn>.txt                       the passphrase (ONLY copy)
     swe-swe-tunnel-ecdsa-ca.pem    the CA to trust (public, not secret)
     <cn>-README.txt                this file

   macOS import (all three steps required):
     1. Import the identity:
        security import <cn>.p12 \
          -k ~/Library/Keychains/login.keychain-db \
          -P "$(cat <cn>.txt)" -T /Applications/Safari.app
     2. Trust the CA (without this the identity is hidden from the
        SSL-client policy):
        security add-trusted-cert -r trustRoot \
          -k ~/Library/Keychains/login.keychain-db \
          swe-swe-tunnel-ecdsa-ca.pem
     3. (optional) Suppress the per-host cert prompt:
        security set-identity-preference -c "<cn>" \
          -s "https://*.<apex>"
        then quit & reopen Safari.

   Verify: `security find-identity -p ssl-client` must list <cn>.
   "1 identity imported" alone is NOT enough.

   iOS/iPadOS: only step 1 is needed (no CA-trust step).

   This identity is NOT bound to any single hostname; it works across
   every *.<apex> tunnel origin.

   After importing, delete the secret files:
     rm <cn>.p12 <cn>.txt <cn>.tgz <cn>-README.txt
   The cert is reproducible from the CA; the passphrase is not.
   swe-swe-tunnel-ecdsa-ca.pem is public - keep or delete freely.
   ```

8. **Bundle a `.tgz`** of all four artifacts so the operator can
   fetch one file and copy it to the device intact:
   ```sh
   tar -czf generated/<cn>.tgz -C generated \
     <cn>.p12 <cn>.txt swe-swe-tunnel-ecdsa-ca.pem <cn>-README.txt
   ```
   The `.tgz` carries the passphrase `.txt`, so it is as sensitive
   as the `.p12` — same delete-after-import rule applies.

9. **Delete the .p12 from the daemon's volume** so the secret
   doesn't accumulate in production state (the CA cert can stay —
   it's public):
   ```sh
   docker exec swe-swe-tunneld rm /var/lib/swe-swe-tunnel/mtls-ecdsa/<cn>.p12
   ```
   The cert is reproducible — operator can re-issue from the CA
   whenever needed. Leaving the .p12 in the volume is a
   loose-secret risk.

## Report

Final `send_message`:

- dev-container paths: `./generated/<cn>.p12`,
  `./generated/<cn>.txt`, `./generated/swe-swe-tunnel-ecdsa-ca.pem`,
  `./generated/<cn>-README.txt`, and the bundled
  `./generated/<cn>.tgz` (which contains all four — the README
  travels with the cert so the import recipe isn't lost),
- size of each (use `ls -la generated/`),
- the SHA-256 fingerprint of the cert inside the .p12 if openssl
  is available in the dev container (`openssl pkcs12 -in
  generated/<cn>.p12 -nokeys -passin "file:generated/<cn>.txt" -info
  2>/dev/null` — skip silently if openssl absent or the call
  fails),
- **the macOS import recipe** (a leaf signed by the ECDSA CA still
  needs the CA trusted, or the identity is hidden from the
  SSL-client policy), verbatim:

  > On the Mac, all three steps are required:
  > 1. Import the identity:
  >    `security import <cn>.p12 -k ~/Library/Keychains/login.keychain-db -P "$(cat <cn>.txt)" -T /Applications/Safari.app`
  > 2. Trust the CA:
  >    `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db swe-swe-tunnel-ecdsa-ca.pem`
  > 3. (optional, suppresses the per-host cert prompt)
  >    `security set-identity-preference -c "<cn>" -s "https://*.<apex>"` then quit & reopen Safari.
  >
  > Verify with `security find-identity -p ssl-client` — the CN must
  > appear. "1 identity imported" alone is NOT enough.

  (iOS/iPadOS needs only step 1 — no CA-trust step — but iOS works
  off the Ed25519 CA too; this ECDSA bundle is for the Mac.)

- **the post-import cleanup instructions**, verbatim:

  > After importing on the target device, delete the secret files:
  > `rm generated/<cn>.p12 generated/<cn>.txt generated/<cn>.tgz generated/<cn>-README.txt`.
  > (The `.tgz` contains the passphrase, so treat it like the `.p12`.)
  > The cert is reproducible from the CA; the passphrase is not.
  > `swe-swe-tunnel-ecdsa-ca.pem` is public — keep or delete freely.

  (The same recipe is written into `<cn>-README.txt` inside the
  bundle, so the operator has it even off-chat.)

- a sentence reminding the operator the passphrase .txt is the
  ONLY copy of the passphrase — losing it before import means
  re-issuing the cert (the .p12 alone is useless).

## Coding rules

- Never echo the passphrase into a log line or a structured log.
- Never `rm` `./generated/` wholesale. Per-file cleanup is the
  operator's call.
- If any step fails partway, leave both files in place if any
  partial output exists (the .p12 with no .txt is useless without
  the passphrase; surface this in the failure message so the
  operator knows whether to retry or re-issue).
