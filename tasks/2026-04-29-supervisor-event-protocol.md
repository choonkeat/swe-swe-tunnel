# Tunnel client: structured stdout event protocol for supervisors

## Status

**Proposed (2026-04-29).** No code changes yet; this file captures
the contract a parent supervisor (e.g. swe-swe-server) needs from
the swe-swe-tunnel client when it runs as a child process.

Companion plan in the consumer repo:
`/workspace/tasks/2026-04-29-tunnel-subprocess-pivot.md`.

## Why

Today the tunnel client logs human-readable text to stderr and
optionally writes a JSON state file (`tunnel-state.json`) at a
configured path. Both are observation outputs. Neither is suitable
for a parent process that needs to:

1. Learn the assigned hostname **the moment it is assigned**, not
   "some time after a file lands on disk."
2. Distinguish lifecycle phases — registering, registered, label
   rotated, deregistered, disconnected, reconnecting, fatal error —
   so the supervisor can drive UI state, restart logic, and
   observability.
3. Stay decoupled from a specific consumer. The event stream is a
   contract; multiple supervisors (swe-swe-server today, others
   later) consume the same shape.

This task adds a single opt-in flag and a small JSON-lines event
schema on stdout. It is fully additive: existing consumers that
ignore stdout, parse the state file, or read stderr logs are
unaffected.

## Scope

In-scope:

- New CLI flag and the JSON-lines event emitter.
- A versioned event schema (1 to start) covering hostname lifecycle
  and connection lifecycle.
- Tests for emitter shape and ordering.

Out of scope:

- Removing the state-file writer. It stays as-is. A future task can
  delete it once no one reads it; today the gate is just "supervisors
  prefer events, file is a fallback we no longer document for new
  consumers."
- Bidirectional control. The supervisor sends signals (SIGTERM for
  graceful shutdown), not structured input. If we ever need control
  beyond signals, it goes on stdin in a follow-up.
- Replacing stderr logs. Human-readable diagnostics still go to
  stderr.

## CLI surface

Add one flag to `cmd/swe-swe-tunnel`:

```
--report-format <none|jsonl>   default: none
```

Or the env equivalent `SWE_TUNNEL_REPORT_FORMAT`.

- `none` (default): existing behavior. Stderr logs. Stdout silent
  except for whatever the current code prints (audit and remove any
  stray `fmt.Println` on stdout to keep the channel clean for
  future use).
- `jsonl`: one JSON event per line on stdout, terminated by `\n`.
  Stderr unchanged. The state-file writer is unaffected.

The flag is opt-in so non-supervised invocations (interactive ops,
existing CI scripts) see no change. swe-swe-server passes
`--report-format=jsonl` when it spawns the child.

## Event schema (version 1)

Every event is a single JSON object on its own line:

```jsonc
{
  "v": 1,                         // schema version, always 1 for now
  "ts": "2026-04-29T10:00:00Z",   // RFC3339 UTC, monotonic per process
  "kind": "register_ok",          // see kinds below
  "data": { ... }                 // shape varies per kind, see below
}
```

### Kinds

| Kind | When | `data` shape |
|---|---|---|
| `starting` | First line emitted, before any network I/O | `{"unique":"alpha","server_url":"https://tunnel.example.com"}` |
| `connecting` | Dialing the tunnel server | `{"server_url":"https://tunnel.example.com","attempt":1}` |
| `register_ok` | Server replied with the assigned hostname | `{"hostname":"alpha-tunnel.example.com","unique":"alpha"}` |
| `relabel` | Server reassigned a different hostname mid-session (rare; reserved for future) | `{"hostname":"alpha2-tunnel.example.com","old_hostname":"alpha-tunnel.example.com"}` |
| `disconnected` | yamux session lost | `{"reason":"control stream EOF"}` |
| `reconnecting` | Backoff-and-retry loop entered | `{"after_ms":1000,"attempt":2}` |
| `deregister_ok` | Clean Deregister round-trip completed | `{"unique":"alpha"}` |
| `error` | Recoverable error worth surfacing | `{"message":"...","retryable":true}` |
| `fatal` | Last line emitted before exit | `{"message":"...","exit_code":1}` |

Ordering guarantees:

- `starting` is always the first line.
- `register_ok` precedes any `disconnected`.
- After `disconnected`, the next state event is either `reconnecting`
  (then back to `connecting` → `register_ok`) or `fatal`.
- `fatal` is always the last line.
- `deregister_ok` is emitted on graceful shutdown only (SIGTERM
  acknowledged); SIGKILL produces no event.

Forward-compat rule: consumers that see an unknown `kind` MUST log
and continue. Producers may add new kinds in v1; bumping `v` to 2
is reserved for incompatible breaks.

### Sample lines

Real wire output, one event per line:

```
{"v":1,"ts":"2026-04-29T10:00:00Z","kind":"starting","data":{"unique":"alpha","server_url":"https://tunnel.example.com"}}
{"v":1,"ts":"2026-04-29T10:00:00.120Z","kind":"connecting","data":{"server_url":"https://tunnel.example.com","attempt":1}}
{"v":1,"ts":"2026-04-29T10:00:00.480Z","kind":"register_ok","data":{"hostname":"alpha-tunnel.example.com","unique":"alpha"}}
{"v":1,"ts":"2026-04-29T10:05:12.300Z","kind":"disconnected","data":{"reason":"control stream EOF"}}
{"v":1,"ts":"2026-04-29T10:05:13.300Z","kind":"reconnecting","data":{"after_ms":1000,"attempt":2}}
{"v":1,"ts":"2026-04-29T10:05:13.450Z","kind":"register_ok","data":{"hostname":"alpha-tunnel.example.com","unique":"alpha"}}
{"v":1,"ts":"2026-04-29T10:30:00.000Z","kind":"deregister_ok","data":{"unique":"alpha"}}
```

Note that `register_ok` may appear more than once across a process
lifetime (after each reconnect). The supervisor compares the new
hostname against the cached value and re-broadcasts only when it
differs.

## Wire conventions

- One event per line. No trailing comma, no pretty-printing, no
  multi-line JSON. `bufio.Scanner` on the consumer side must work.
- `\n` line terminator. No `\r\n`.
- UTF-8. ASCII-only field names.
- Stdout is line-buffered on tty, block-buffered on pipe. The
  emitter must `Flush` after every event so a supervisor reading
  off a pipe sees events promptly. (This is the most common bug in
  child-process observability — verify in tests.)
- A `fatal` event is followed by process exit; the parent should
  treat reading EOF after a non-`fatal` last line as a crash.

## Implementation sketch

A new file `internal/tunnelclient/events.go` with:

```go
type Emitter interface {
    Emit(kind string, data any)
}

type jsonlEmitter struct {
    out io.Writer
    mu  sync.Mutex
}

type noopEmitter struct{}
```

`tunnelclient.Connect` and `Serve` accept an `Emitter` in their
options struct. `cmd/swe-swe-tunnel` constructs the right emitter
from the `--report-format` flag and passes it in.

The emitter is concurrency-safe (the connect/disconnect path and a
future reconnect goroutine both write).

Lock-free is not required; the event rate is at most a few per
second in normal operation.

## Tests

### Unit

- `events_test.go`:
  - **Shape.** Each kind round-trips through `json.Marshal` /
    `json.Unmarshal` and matches the documented `data` shape.
  - **Ordering invariants.** A scripted lifecycle (start → connect →
    register → disconnect → reconnect → register → deregister →
    exit) produces the expected sequence of kinds.
  - **Forward-compat.** A consumer that ignores unknown `kind`
    values does not crash on a synthetic future kind.
  - **Flush.** Pipe stdout into a `bytes.Buffer` wrapper that fails
    the test if `Flush` is not called between events.

### Integration

- A small in-process e2e in this repo:
  - Boot a fake tunneld that accepts a register and immediately
    closes the control stream.
  - Run `cmd/swe-swe-tunnel --report-format=jsonl` against it,
    capture stdout, assert the event sequence is
    `starting`, `connecting`, `register_ok`, `disconnected`,
    `reconnecting`, ... and finally `fatal` after the supervisor
    cancels.

### Backwards compat

- `--report-format=none` (default) produces zero stdout output
  during a normal lifecycle. Test the empty-stdout invariant.

## Sequencing

The producer (this repo) must ship before the consumer (swe-swe)
can rip out its state-file fallback. Order:

1. Land this task on `swe-swe-tunnel`'s `main`.
2. Tag a release.
3. swe-swe-server's pivot task lands, importing the new tunnel-client
   binary version.

## Open questions

1. **Should events also carry per-event sequence numbers** for the
   supervisor to detect drops? Probably not for v1 — events are
   in-order over a single pipe; nothing in between to drop.
2. **Should we expose connection metrics** (bytes in/out per stream)
   in events? Out of scope for v1; if needed later, add a `metrics`
   kind that the supervisor can sample.
3. **Versioning.** The `"v": 1` field is included from day one so
   v2 can break the schema cleanly. Producers must not emit a
   higher version unless explicitly requested in the future.

## Acceptance

The task is done when all of the following hold:

1. **Default behavior unchanged.** Running
   `cmd/swe-swe-tunnel` with no new flags produces zero bytes on
   stdout across a full happy-path lifecycle (start, register,
   disconnect, deregister, exit). Verified by an integration test.
2. **Opt-in JSONL stream.** With `--report-format=jsonl`, the same
   happy path emits the documented event sequence (`starting`,
   `connecting`, `register_ok`, ..., `deregister_ok`) one JSON
   object per line, in the exact `{"v":1,"ts":...,"kind":...,"data":...}`
   shape, terminated by `\n`, with `Flush` called between events.
3. **Crash + reconnect path.** Forcing the tunneld stream to close
   mid-session produces `disconnected` then `reconnecting` then a
   second `register_ok` on the same line stream. Integration test
   covers this with a scripted fake tunneld.
4. **Fatal exit.** A non-recoverable error emits `fatal` as the
   final line and exits non-zero. SIGKILL produces no event (parent
   distinguishes "EOF without `fatal`" as crash).
5. **Forward-compat.** A consumer seeing an unknown `kind` value
   logs and continues — verified by a unit test with a synthetic
   future kind.
6. **Concurrency.** The emitter is safe to call from the connect
   goroutine and any future reconnect goroutine concurrently —
   verified by a race-tagged test (`-race`).
7. **Coding rules respected.** ASCII-only, direct commit on `main`,
   no silent error swallow, `cmd.Wait()` not silent (if the
   integration test fakes tunneld via subprocess, log PID + exit).
8. **Cross-repo handoff ready.** A swe-swe-server agent reading
   the companion task file
   (`/workspace/tasks/2026-04-29-tunnel-subprocess-pivot.md`) has
   everything needed to consume the stream.

## Coding rules to honor

- **ASCII only in code / markdown / event payloads.**
- **Direct commits on `main`** per project convention.
- The emitter must not silently swallow write errors. If stdout is
  closed (parent died), the next event write fails; log that on
  stderr and continue (the parent is gone but the tunnel might still
  be useful for whoever finds the still-running orphan).
