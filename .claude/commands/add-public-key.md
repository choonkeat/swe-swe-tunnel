---
description: Add an Ed25519 pubkey to the running swe-swe-tunneld allowlist (writes to host bind-mount source, then SIGHUPs the daemon)
---

You are about to authorize a new Ed25519 pubkey on the live tunneld
container by writing a `.pub` file into the bind-mounted allowlist
directory **on the Docker host's filesystem** (not this dev
container's filesystem) and signaling SIGHUP to reload + revoke.

Why this needs its own command instead of "drop a file into
`./allowlist/` and `kill -HUP`": this repo is edited inside a swe-swe
dev container whose filesystem is *separate* from the Docker host's
filesystem. The container at `/repos/swe-swe-tunnel/workspace/` (where
you edit) and the host at `/repos/swe-swe-tunnel/workspace/` (where
the daemon's bind-mount source lives) are different. A naive
`Write` to `./allowlist/operator.pub` lands in the dev container only;
the daemon never sees it. This command bridges that gap by writing
through a transient `alpine` container that mounts the host path RW.

# Run

Work from the repo root: `/repos/swe-swe-tunnel/workspace`. Do
everything via the Bash tool. Report progress to the user via
`send_progress` between steps and a final `send_message` when done
(or on failure).

## Inputs

The user invokes the command as `/add-public-key <pubkey> [name]`:

- **`<pubkey>`** (required) — base64-RawStd Ed25519 pubkey (43 chars,
  no padding). This is the same encoding the wire protocol uses
  for `Register.Pubkey`. If the user pasted a value with `=` padding
  or a PEM wrapper, refuse and ask for the bare 43-char form (and
  remind them: it must be the **public** half, never the private
  key — hint via `openssl pkey -in <key> -pubout -outform DER |
  tail -c 32 | base64 | tr -d '='`).

- **`[name]`** (optional) — short label for the file
  (e.g. `alice-laptop`). Used as `<name>.pub`. If omitted, ask the
  user for one rather than guessing — the filename doubles as the
  audit log of who's authorized.

If the user omits `<pubkey>` entirely, ask them to paste it. Don't
proceed without both values.

## Validate

Before touching anything, validate:

1. **Decode + length.** The pubkey must be exactly 32 bytes when
   base64-decoded. Fail loud if not — Ed25519 pubkeys are 32 bytes,
   and the daemon's loader rejects anything else with
   `os.Exit(1)` at boot (or "keeping_previous=true" at SIGHUP, but
   no point in writing a bad file). Use:

   ```sh
   printf '%s=' "$PUBKEY" | base64 -d 2>/dev/null | wc -c
   ```

   …expect `32`. (The trailing `=` covers RawStd-without-padding;
   `base64 -d` accepts it.)

2. **Filename safety.** Reject names containing `/`, `..`, leading
   `.`, or whitespace. `[a-z0-9._-]+` is the safe set.

3. **Container is running.** `docker ps --format '{{.Names}}' |
   grep -q '^swe-swe-tunneld$'`. If not, refuse — there's nothing to
   reload, and the user probably wants `/run-production` instead.

4. **No existing file with the same name.** Run
   `docker exec swe-swe-tunneld ls /etc/swe-swe-tunneld/allowlist/`
   to check the live view (which reflects host state). If
   `<name>.pub` already exists, ask whether to overwrite — name
   collisions usually mean either re-keying or a typo.

## Confirm

Send a `send_message` summarizing:

- the pubkey (echoing what the user gave so they can spot a paste
  error),
- the filename it will be written under (`<name>.pub`),
- the host path it lands at (`/repos/swe-swe-tunnel/workspace/allowlist/<name>.pub`),
- a one-line preview of the trailing comment (current date).

Quick replies:

- `Confirm` — proceed.
- `Cancel` — abort.

## Write + reload

After confirmation:

1. `send_progress`: "writing /repos/swe-swe-tunnel/workspace/allowlist/<name>.pub via transient alpine container…"

2. Write the file from a one-shot container that bind-mounts the
   host path RW. **Do NOT use `Write` or `os.WriteFile`** — those
   would land in the dev container only. The exact command:

   ```sh
   docker run --rm \
     -v /repos/swe-swe-tunnel/workspace/allowlist:/dst \
     alpine sh -c 'printf "%s  # %s\n" "$PUBKEY" "$LABEL" > /dst/'"$NAME"'.pub'
   ```

   …passing `PUBKEY`, `LABEL` (e.g. `<name> $(date -u +%F)`), and
   substituting `$NAME` directly into the path. Sanity-check exit
   code is zero.

3. Confirm the daemon now sees it:

   ```sh
   docker exec swe-swe-tunneld ls /etc/swe-swe-tunneld/allowlist/
   ```

   The new file should be there.

4. `send_progress`: "signaling SIGHUP for reload + revoke…"

5. Trigger reload:

   ```sh
   docker kill -s HUP swe-swe-tunneld
   ```

   Note: `docker kill -s HUP` does NOT kill the container — `-s
   HUP` overrides the default SIGKILL with SIGHUP, which the
   daemon's signal handler picks up to call `allow.Reload()` +
   `reg.RevokeMissing()`. Container keeps running.

6. Wait briefly (~1s) and verify the reload landed:

   ```sh
   docker logs --tail 5 swe-swe-tunneld 2>&1 | grep -E "allowlist (reloaded|reload failed)"
   ```

   Expected: `allowlist reloaded source=... files=N count=N added=1 removed=0`.
   If you see `allowlist reload failed ... keeping_previous=true`,
   the new file failed to parse — surface the error and offer to
   delete the bad file (also via the `docker run --rm -v` trick).

## Report

Final `send_message`:

- file written: `<name>.pub`,
- pubkey added (echo first 12 chars + last 4),
- daemon reload result (`added=N removed=M files=K count=K`),
- if any session was revoked as a *side effect* (shouldn't happen
  on add — RevokeMissing only acts when something is removed —
  but worth a quick `grep "session terminated: revoked"` against
  the new log lines to be sure).

If the workflow blew up at any step, stop and report — don't
attempt destructive cleanup without explicit user approval.

## Coding rules

- Never write into `./allowlist/` from the dev container side
  (`Write` tool, `cp`, `os.WriteFile`). The daemon won't see it.
- Never `docker rm -f` the container. The whole point is reload
  without recreate.
- Don't print the `.env` file or any secret value — pubkeys are
  fine.
- Only ASCII in any commit messages or files written.
