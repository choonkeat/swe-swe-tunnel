---
description: Safe git push for this repo - scans the push range (and agent-chats) for secrets BEFORE pushing. Derives the secret denylist at runtime from untracked host files, so this committed command never names a secret value.
---

You are about to push commits to a **public** remote. Before you push,
scan everything that would become public for secrets and infra details.
This command is committed to the repo, so it must NEVER hardcode a secret
value (apex, email, token, port, key, passphrase, hostname). Instead,
**derive the denylist at runtime** from untracked host files, then scan.

Work from the repo root. Use the Bash tool. Report via `send_progress`
between steps and a final `send_message`. Do NOT run `git push` until
every check below passes; if anything trips, STOP and help the user
scrub first.

## 1. Figure out the push range

```sh
branch=$(git rev-parse --abbrev-ref HEAD)
range="origin/${branch}..HEAD"          # commits not yet on the remote
git log --oneline "$range"
```
If `origin/${branch}` doesn't exist, treat the whole history as the range
and say so (first push of this branch).

## 2. Build the denylist DYNAMICALLY (never written into this file)

Collect "needles" — real values that must not appear in public content —
from files that are **gitignored** (so reading them here leaks nothing
into the repo):

- From `.env` (if present): take every value to the right of `=` that is
  non-empty and not an obvious placeholder. These cover the apex domain,
  the ACME email, and any API tokens.
- From `docker-compose.override.yml` (if present): take every scalar
  value (the register port number, listen addresses, paths).
- Any `*.key` under `backups/`, `generated/`, or the tunnel volume: their
  raw contents must never appear anywhere.

Load them into a needle list in the shell WITHOUT echoing the values to
the user (don't print the needles; print only counts and match results).
Example shape (adapt; keep values out of `send_message`):

```sh
needles=()
[ -f .env ] && while IFS='=' read -r k v; do
  v="${v%\"}"; v="${v#\"}"
  case "$k" in ''|\#*) continue;; esac
  [ -n "$v" ] && needles+=("$v")
done < .env
# add override scalars:
[ -f docker-compose.override.yml ] && \
  while read -r v; do [ -n "$v" ] && needles+=("$v"); done < <(
    grep -oE ':[[:space:]]*"?[^"#]+' docker-compose.override.yml | sed -E 's/^:[[:space:]]*"?//' )
echo "loaded ${#needles[@]} project needles (values not shown)"
```

## 3. Always-on generic patterns

Regardless of the denylist, grep the push range's added lines for:

- `-----BEGIN [A-Z ]*PRIVATE KEY-----`  (any private key)
- `passphrase[:=]` / `password[:=]` followed by a value
- public IPv4 (exclude `10.`, `127.`, `169.254.`, `172.1[6-9].`,
  `172.2[0-9].`, `172.3[0-1].`, `192.168.`)
- email addresses
- AWS-style keys `AKIA[0-9A-Z]{16}`, and long high-entropy base64/hex blobs

## 4. Scan

Scan BOTH:
- the diff of the push range: `git diff "$range"` (only `^+` added lines
  matter), and
- the working/added content under `agent-chats/` (exported transcripts —
  these routinely contain passphrases, IPs, hostnames). Note: a `.png`
  under `agent-chats/assets/` CANNOT be grepped; if any image is being
  added, warn that it needs manual review or removal (it may show real
  hostnames on screen).

For each needle and each generic pattern, report `file:line` of any hit.
Print match locations and the *category*, never the secret itself.

## 5. Verdict

- **Any hit** -> STOP. Do not push. Summarize the hits via `send_message`
  and offer to scrub: replace the real apex/hostnames with `example.com`
  placeholders, redact passphrases/IPs/emails, genericize internal names,
  and (if a secret is in already-published history) discuss whether a
  history rewrite + force-push is warranted vs. rotating the secret.
- Remember a leaked value already in PUSHED history is not removed by a
  new commit; it needs history rewrite OR rotation. Prefer rotating an
  operational secret (e.g. change the live port/token) over force-pushing
  a public repo, unless the user explicitly wants the rewrite.
- **Clean** -> confirm the count of commits to push and the branch, then:
  ```sh
  git push origin "$branch"
  ```
  Report the result.

## Notes

- Never print secret values in `send_message` or `send_progress` — only
  categories, counts, and `file:line`.
- `backups/`, `generated/`, `.env`, and `docker-compose.override.yml`
  must stay gitignored; if `git status` shows any of them as tracked or
  staged, STOP and fix `.gitignore` first.
