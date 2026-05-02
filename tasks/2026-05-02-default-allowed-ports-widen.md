# Tunneld: widen DefaultSpec to include 20000-29999

## Status

**Proposed (2026-05-02).** Follow-up to today's
`2026-05-02-server-side-port-allowlist.md` (commits `3c7c157`,
`bd12271`, `560aaf3`, `77af59b`). Surfaced by manual end-to-end
testing on the consumer side after the consumer bumped
`SWE_SWE_TUNNEL_REF` to `77af59b`.

## Symptom

The consumer's `https://1977.{hostname}/` URL (swe-swe-server itself)
loads successfully. But when a user clicks Preview or Agent View
inside the swe-swe UI, the iframe shows the body
`port not allowed` returned by tunneld's `route()` 404.

## Why

swe-swe-server allocates *per-session* proxy ports at offset
`20000`. From the consumer's `cmd/swe-swe/templates/host/swe-swe-server/main.go`:

```go
proxyPortOffset    = 20000

func previewProxyPort(port int) int    { return proxyPortOffset + port }
func agentChatProxyPort(port int) int  { return proxyPortOffset + port }
func cdpProxyPort(port int) int        { return proxyPortOffset + port }
func vncProxyPort(port int) int        { return proxyPortOffset + port }
```

So a session whose preview is bound to `3000` is reached at proxy
port `23000`, agent-chat at `24000`, etc. The frontend's URL builder
constructs `https://{proxyPort}.{publicHostname}/` for these.

Today's `DefaultSpec`:

```
1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898
```

does not include any port in `20000-29999`, so every per-session
proxy URL the consumer's UI generates is rejected by the server's
`route()` allowlist check.

## Fix

Add `20000-29999` to `DefaultSpec` in `internal/portpolicy/portpolicy.go`:

```go
const DefaultSpec = "1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081,9898,20000-29999"
```

Rationale: this 10k-port band is the load-bearing range for the
canonical consumer (swe-swe). Any tunneld operator running for
swe-swe consumers will need it, so making it the compiled default
is right. Operators with non-swe-swe consumers can still override
via `--allowed-ports` or `--allowed-ports-file` to a narrower set.

## Scope

In-scope:

- One-line constant change in `internal/portpolicy/portpolicy.go`.
- Update the `DefaultSpec` reference in
  `cmd/swe-swe-tunneld/main.go`'s `--allowed-ports` flag help string
  if it embeds the literal (it currently uses the constant, so this
  may be a no-op).
- `portpolicy_test.go` table-test row for `DefaultSpec` should
  continue to pass; add an assertion that the spec includes
  `25000` (mid-range sentinel) as future-proofing against narrowing
  the default.
- A line in the deploy doc explaining that `20000-29999` is the
  per-session proxy band and why operators should not narrow the
  default unless they know what they're doing.

Out-of-scope:

- Documenting swe-swe internals further (`proxyPortOffset` lives in
  the consumer; the tunneld doc only needs to say "swe-swe
  consumers use 20000-29999").
- Making the offset configurable on the consumer side. swe-swe is
  free to change `proxyPortOffset` later — when it does, this task
  file's rationale stays load-bearing as a record of why the band
  exists in the default.

## Sequencing

Single commit:
- Update constant + test + flag-help (if needed) + deploy-doc note.

Then a `/run-production` deploy at `tunnel.example.com` so the live
operator's `(source=default)` policy picks up the wider default
without an explicit `--allowed-ports` override.

## Consumer side

After this lands and the live `tunnel.example.com` tunneld is
redeployed:

- No change in our `Dockerfile` `SWE_SWE_TUNNEL_REF` (the wider
  default flows in automatically since we don't pin a narrower
  `--allowed-ports` either as a flag or env var on our build).
- We *should* bump `SWE_SWE_TUNNEL_REF` to pick up the new default
  for the swe-swe-tunnel client image baked into our consumer
  container, but that's only a consistency matter — the client no
  longer gates ports as of `560aaf3`.

## How to verify

End-to-end on the consumer side:

```sh
make tunnel-up-manual
# Wait for register_ok, extract hostname from logs, then:
curl -sS -o /dev/null -w '%{http_code}\n' \
    "https://1977.{hostname}/"      # expect 302 (or 200)
curl -sS -o /dev/null -w '%{http_code}\n' \
    "https://23000.{hostname}/"     # expect != 404 (i.e. tunneld
                                    # passes the port through)
curl -sS -o /dev/null -w '%{http_code}\n' \
    "https://24000.{hostname}/"     # same
```

Today (pre-fix), `23000` and `24000` return `404 "port not allowed"`
from tunneld's `route()`. Post-fix they return whatever
swe-swe-server replies (often `302` to auth login or `502` if no
session has bound that proxy port yet — both indicate the gate
opened).
