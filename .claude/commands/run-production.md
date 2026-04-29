---
description: Rebuild the swe-swe-tunneld image from the current working tree and recreate the live container at https://tunnel.example.com
---

You are about to rebuild and recreate the **production** swe-swe-tunneld
container that backs https://tunnel.example.com on this host. This is a
visible, blast-radius-affecting action — be deliberate.

# Run the production update

Work from the repo root: `/repos/swe-swe-tunnel/workspace`. Do everything
through the Bash tool; report progress to the user via `send_progress`
between steps and a final `send_message` when done (or on failure).

## Pre-flight

Run these in parallel and confirm each is healthy before proceeding:

1. `git status --short` — there should be no uncommitted source changes
   that you are about to bake into a production image without the user
   knowing. If `git status` is dirty, **stop and ask the user** whether
   they want to commit/stash first.
2. `git log --oneline -5` — show the user what HEAD will be deployed.
3. `git rev-parse --abbrev-ref HEAD` — confirm we're on `main` (or ask
   the user explicitly if not).
4. `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep swe-swe-tunneld` —
   confirm the container is currently running.
5. `test -f .env && echo ok` — `docker-compose.yml` requires
   `DNSIMPLE_OAUTH_TOKEN`, `SWE_TUNNEL_APEX`, and `SWE_TUNNEL_ACME_EMAIL`
   to be set. They normally come from `.env` in the repo root. Do NOT
   print the file contents; just confirm it exists.

If any pre-flight check fails, stop and report via `send_message`.

## Confirm with the user

Before the destructive step, send a `send_message` summarizing:

- the HEAD commit that will be built (subject + sha),
- the current image id from `docker image inspect swe-swe-tunneld --format '{{.Id}} {{.Created}}'`,
- the current container uptime from step (4),
- whether the user wants either of the two opt-in flags below.

Ask for explicit confirmation with these quick replies:

- `Proceed` — default: cached build, recreate only if image changed.
- `Force-recreate` — adds `--force-recreate` to step 4 below. Use when
  the user wants a fresh container (e.g. clear in-memory state, pick
  up a hot cert refresh) even if the image didn't change. Causes a
  brief connection flap (~1-2s) for any registered clients.
- `No-cache build` — adds `--no-cache` to step 2 below. Use when the
  user wants base-image security updates baked in even though
  `go.mod` and source are unchanged. Slower (full rebuild). Combine
  with Force-recreate to actually swap to the new image.
- `No-cache + force-recreate` — both flags.
- `Cancel` — abort.

Do NOT skip this confirmation, even if the user just asked you to run
this command. They asked for a /run-production helper — the helper
itself confirms before each invocation.

If `git status` is dirty or HEAD is not on `main`, hold the destructive
flags off the quick-reply list until the user resolves that — confirm
the tree state first, then re-prompt with the flag options.

## Build + recreate

After the user confirms, capture which flags they picked:

- `BUILD_ARGS`:
  - default: empty
  - if `No-cache build` or `No-cache + force-recreate`: `--no-cache`
- `UP_ARGS`:
  - default: empty
  - if `Force-recreate` or `No-cache + force-recreate`: `--force-recreate`

Then:

1. `send_progress`: "building image from HEAD$([[ $BUILD_ARGS ]] && echo ' (no cache)')…" — adapt the message to reflect the chosen flags.
2. `docker compose build $BUILD_ARGS swe-swe-tunneld` — capture the
   full output; on non-zero exit, stop and report via `send_message`.
3. `send_progress`: "recreating container$([[ $UP_ARGS ]] && echo ' (force)')…"
4. `docker compose up -d $UP_ARGS swe-swe-tunneld` — `up -d` recreates
   the container only when image/config changed; `--force-recreate`
   recreates unconditionally. Either way, the named `tunnel-data`
   volume is preserved.
5. `send_progress`: "verifying…"
6. Run these in parallel:
   - `docker ps --format '{{.Names}}\t{{.Status}}' | grep swe-swe-tunneld`
     — confirm "Up X seconds" (or the unchanged old uptime if neither
     flag was used and Compose detected no change).
   - `docker logs --tail 30 swe-swe-tunneld` — look for the boot-time
     DNS multi-label wildcard self-check (it logs at INFO with a
     "self-check" or "wildcard" mention) and ensure no `level=ERROR`
     lines appear in the new boot log.
   - `curl -fsS --max-time 5 -o /dev/null -w '%{http_code}\n' https://tunnel.example.com/ || true` —
     a 4xx is fine (no apex handler); the point is "TLS handshake works
     and a response came back", not the status code.

Note on the no-op case: if the user chose `Proceed` (default) and the
build produced an identical image id, `docker compose up -d` will print
something like `Container swe-swe-tunneld  Running` and not recreate.
Report this honestly — don't claim a deploy happened when nothing
changed.

## Report

Final `send_message` summarizes:

- new image id + created timestamp (from `docker image inspect`),
- container status (uptime in seconds — or "unchanged" if no recreate),
- whether the image id actually changed,
- which flags were used (`--no-cache`, `--force-recreate`),
- boot-log highlights (last 5–10 lines, redacting any IPs or tokens),
- the curl handshake result.

If `--force-recreate` was used, explicitly call out the connection flap
in the report: any registered tunnel clients were briefly disconnected
and will rely on their own retry loop to come back.

If anything in verification looked off (errors in logs, container
restarting, curl timeout), make this clear in the summary and propose
a rollback via `docker compose down && docker compose up -d` against
the previous image (the user will need to confirm any rollback).

## Coding rules

- Never run `docker compose down` without explicit user approval —
  that takes the live tunnel offline and breaks any registered clients
  beyond the recreate window.
- Never `docker rm -f` the container — `up -d` already handles
  graceful recreate.
- Never print the contents of `.env`.
- Only use ASCII in any commit messages or files you write.
