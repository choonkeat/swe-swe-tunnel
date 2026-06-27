---
description: Sign a client Ed25519 pubkey into a cert. Stages {cn}.crt + a {cn}-README.txt of deploy instructions + a {cn}.tgz bundling both under ./generated/ for the operator to ship to the agent host.
---

You are signing an **agent**'s existing Ed25519 public key into an
mTLS client cert against the live production CA. Unlike the .p12
flow, the agent already owns its private key (its identity.key) —
this command never mints or sees a new private key. The output is
just a `.crt` PEM, staged at `./generated/<cn>.crt` in this dev
container.

# Run

Work from the repo root: `/repos/swe-swe-tunnel/workspace`. Do
everything via the Bash tool. Report progress with `send_progress`
between steps and a final `send_message` with the dev-container
path so the operator can fetch it (the same way they fetched the
earlier `alice.crt`).

## Inputs

The user invokes `/generate-mtls-crt-for-client <cn> <pubkey>`:

- **`<cn>`** (required) — the agent identity label (e.g.
  `alice`, `alice-laptop`). Becomes the Subject CN of the
  signed cert AND the filename stem. Match `^[a-z0-9._-]{1,63}$`.

- **`<pubkey>`** (required) — the Ed25519 public key in
  base64-RawStd encoding (43 chars, no padding). This is the same
  format `--allowlist-dir` files use, and the same format
  `Register.Pubkey` carries on the wire.

   To extract it on an agent host:
   ```sh
   openssl pkey -in ~/.swe-swe-tunnel/identity.key -pubout -outform DER \
     | tail -c 32 | base64 | tr -d '='
   ```

   If the user pastes a PEM-wrapped or padded form, refuse and
   ask for the bare 43-char base64-RawStd.

If either is omitted, ask the user. Do not guess.

## Validate + pre-flight

Run in parallel:

1. **Pubkey shape.** `printf '%s=' "<pubkey>" | base64 -d 2>/dev/null
   | wc -c` must print `32`. Ed25519 pubkeys are 32 bytes. Fail
   loud otherwise.

2. **CN safety.** Reject `/`, `..`, leading `.`, whitespace.
   `^[a-z0-9._-]{1,63}$`.

3. **Container running.** `docker ps --format '{{.Names}}' | grep -q
   '^swe-swe-tunneld$'`.

4. **CA exists.** `docker exec swe-swe-tunneld test -f
   /var/lib/swe-swe-tunnel/mtls/ca.pem`. If not, point at
   `docker compose run --rm swe-swe-tunneld mtls-init`.

5. **No clobber.** Check `./generated/<cn>.crt` in the dev
   container:
   ```sh
   ls generated/<cn>.crt 2>/dev/null
   ```
   Existing file -> ask the user before overwriting. An existing
   .crt might already be deployed to an agent host; overwriting
   means deploying again.

## Confirm with the user

`send_message` summarizing:

- the CN that will go on the cert,
- the pubkey (echo it so the operator can sanity-check the paste),
- the dev-container paths: `./generated/<cn>.crt`,
  `./generated/<cn>-README.txt`, and the bundled
  `./generated/<cn>.tgz`,
- the implicit trust delegation (a cert is issued; the pubkey
  becomes a recognised identity from the daemon's POV once mTLS
  is enabled).

Quick replies: `Sign` / `Cancel`.

## Sign + stage

After confirmation:

1. `send_progress`: "signing <cn>.crt from the production CA…"

2. Write the pubkey to a tmp path **inside the daemon container's
   shared volume**, then run mtls-sign against it. Going through
   the volume is the simplest way to give the sign subcommand a
   readable file path it can see:
   ```sh
   docker exec swe-swe-tunneld sh -c 'printf "%s\n" "<pubkey>" > /var/lib/swe-swe-tunnel/mtls/<cn>.pubin'
   docker compose run --rm swe-swe-tunneld \
     mtls-sign \
       --pubkey /var/lib/swe-swe-tunnel/mtls/<cn>.pubin \
       --cn "<cn>" \
       -o /var/lib/swe-swe-tunnel/mtls/<cn>.crt
   docker exec swe-swe-tunneld rm /var/lib/swe-swe-tunnel/mtls/<cn>.pubin
   ```
   Don't pipe via stdin — mtls-sign reads from a path, and there's
   no clean way to give a `compose run` process a file path
   pointing at the calling shell's stdin.

3. Make sure `./generated/` exists in the dev container:
   ```sh
   mkdir -p generated
   ```

4. Copy the signed .crt out of the volume into the dev
   container's `./generated/`:
   ```sh
   docker cp swe-swe-tunneld:/var/lib/swe-swe-tunnel/mtls/<cn>.crt \
     generated/<cn>.crt
   ```

5. **Write the deployment instructions** to
   `./generated/<cn>-README.txt` via the Write tool, so the recipe
   travels with the cert instead of living only in chat. ASCII
   only, substitute `<cn>` (and `<server-url>` from the daemon's
   `--server`, e.g. `https://tunnel.example.com`). Content:
   ```text
   swe-swe-tunnel mTLS agent cert: <cn>
   Signed against the production CA. This is the PUBLIC half only -
   no private key here. The agent keeps using its existing
   ~/.swe-swe-tunnel/identity.key as the TLS private key.

   Files in this bundle:
     <cn>.crt          the signed client certificate (public)
     <cn>-README.txt   this file

   Deploy on the agent host:
     scp <cn>.crt <agent-host>:~/.swe-swe-tunnel/client.crt
   Then add to the agent's launch:
     --client-cert ~/.swe-swe-tunnel/client.crt
   (or env SWE_TUNNEL_CLIENT_CERT=~/.swe-swe-tunnel/client.crt)

   The cert + the agent's identity.key are loaded once at boot. If
   the identity key was rotated since this cert was signed, the pair
   fails to load and the agent exits - re-sign against the current
   pubkey.

   Nothing here is secret; the .crt and the pubkey are both public.
   ```

6. **Bundle a `.tgz`** so the operator fetches one file:
   ```sh
   tar -czf generated/<cn>.tgz -C generated <cn>.crt <cn>-README.txt
   ```
   Nothing in this bundle is secret (public cert + instructions), so
   unlike the `.p12` flow there's no delete-after-import urgency.

7. (Recommended) **Leave the .crt in the daemon's volume too** —
   unlike the .p12 case, a signed cert is not sensitive (it's the
   public artifact). Keeping it in `/var/lib/swe-swe-tunnel/mtls/`
   makes it easy to re-fetch later without re-signing.

## Report

Final `send_message`:

- dev-container paths: `./generated/<cn>.crt`,
  `./generated/<cn>-README.txt`, and the bundled
  `./generated/<cn>.tgz` (the README travels with the cert so the
  deploy steps aren't lost),
- chain check (so the operator sees the daemon trusts this cert):
  ```sh
  docker exec swe-swe-tunneld sh -c \
    'openssl verify -CAfile /var/lib/swe-swe-tunnel/mtls/ca.pem \
       /var/lib/swe-swe-tunnel/mtls/<cn>.crt' 2>&1 \
    || echo '(openssl not present in container; skip)'
  ```
  Expected (if openssl is available): `<cn>.crt: OK`. The
  swe-swe-tunneld base image is alpine without openssl by
  default; in that case fall back to a Go-side parse from inside
  this dev container (skip if too noisy — chain correctness is
  guaranteed by mtls-sign's contract).
- on-disk size + sha256 fingerprint of the cert (`sha256sum
  generated/<cn>.crt`).
- a one-line deployment hint to the operator, verbatim:

  > scp generated/<cn>.crt <agent-host>:~/.swe-swe-tunnel/client.crt
  > Then add `--client-cert ~/.swe-swe-tunnel/client.crt`
  > (or `SWE_TUNNEL_CLIENT_CERT=...`) to the agent's launch.

  (The same steps are written into `<cn>-README.txt` inside the
  bundle, so the operator has them off-chat.)

## Coding rules

- Cert PEM is public — feel free to echo / log it.
- The pubkey is also public (it's already in the allowlist file
  for any registered agent).
- Don't leave the `.pubin` tmp file in the volume; rm it after
  mtls-sign returns regardless of exit code.
- If mtls-sign fails (e.g. malformed pubkey, CA missing), surface
  the error verbatim. Don't retry; agent operators want explicit
  failures, not silent retries.
