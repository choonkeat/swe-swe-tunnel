# Tunnel client: ctx-cancelable Connect

## Status

**Proposed (2026-05-02).** Companion follow-up:
`tasks/2026-05-02-server-issuance-grace.md` — adds a server-side
grace window so a Ctrl-C during cert issuance also saves an LE
budget slot.

## Why

Empirical reproducer from a 2026-05-02 dev session:

```
$ env SWE_TUNNEL_SERVER=https://tunnel.example.com \
      SWE_TUNNEL_UNIQUE=alice-2m94n \
      SWE_TUNNEL_IDENTITY_KEY=$(base64 -w0 < identity.key) \
      swe-swe-tunnel
time=...  level=INFO msg="identity loaded" source=env fingerprint=...
time=...  level=INFO msg=dialing addr=tunnel.example.com:443
^C^C^C^C    # unresponsive for ~2.5 minutes
```

Server logs showed the client wasn't *crashed* — it was blocked
waiting for `RegisterOK` while tunneld synchronously provisioned
the per-session wildcard cert via Let's Encrypt DNS-01 (two
challenges, ~2m 37s end-to-end on a fresh label).

Root cause: `Connect` in `internal/tunnelclient/client.go` mixes
ctx-aware steps (TCP `DialContext`, `tls.HandshakeContext`) with a
sequence of non-ctx-aware blocking I/O calls on the same
connection:

1. `req.Write(tlsConn)` — HTTP/1.1 upgrade request
2. `http.ReadResponse(br, req)` — wait for `101 Switching Protocols`
3. `yamux.Client(...)` / `yam.OpenStream()` — yamux session init
4. `registerWithServer(stream, ...)` — `control.WriteMessage` and
   `control.ReadMessage` on the yamux stream

Once the goroutine is parked in any of these `Read`/`Write` syscalls,
SIGINT cancels the parent ctx but the runtime cannot preempt the
syscall. `signal.NotifyContext` fires correctly; `Run`'s caller never
gets a chance to act on it. The process appears hung.

The bug is reproducible against any slow-but-responsive server. The
2.5-minute LE issuance wait surfaced it; a network blip mid-handshake
or a deadlocked server would behave identically.

## Scope

In-scope:

- A single ctx-watcher goroutine installed in `Connect`, immediately
  after `dialer.DialContext` succeeds. On `<-ctx.Done()` it closes
  `rawConn`, which cascades: TLS Read/Write returns
  `use of closed network connection`, every layer above (HTTP upgrade,
  yamux, control stream) returns an error, `Connect` unwinds, the
  caller observes `ctx.Err()`.
- The watcher is retired via a `done` channel closed by `defer` when
  `Connect` returns (success or error). On success the watcher exits
  *without* closing — the returned `Session` owns the connection from
  there, and `Run`'s outer ctx-watch already handles graceful
  shutdown via `sess.Deregister + sess.Close`. On error paths
  `Connect` already closes the conn itself; a late watcher fire is a
  harmless no-op on an already-closed conn.
- A single `INFO` log line emitted just before `registerWithServer`
  blocks on the control stream, so the operator staring at a
  silent-looking client during first-time cert issuance sees
  *something*:

  ```
  msg="awaiting RegisterOK from server"
  unique=alice
  hint="first-time uniques can take 1–3 min while the server provisions a wildcard cert"
  ```

- Tests covering the three blocking-I/O phases plus a happy-path
  goroutine-leak gate.

Out of scope (worth follow-ups, not this commit):

- `Session.Deregister` has the same shape (5s timeout but
  non-ctx-aware control-frame I/O). Bounded so less urgent.
- `cmd/swe-swe-tunneld` connect handler has analogous server-side
  blocking reads on the control stream. Server-side ungraceful close
  paths exist; not driving any reported pain today.
- `errmain` refactor to ban `context.Background()` outside `main` —
  separate hygiene pass; this commit does not require it.

## Implementation sketch

`internal/tunnelclient/client.go` `Connect`:

```go
rawConn, err := dialer.DialContext(ctx, "tcp", addr)
if err != nil {
    return nil, fmt.Errorf("dial: %w", err)
}

// closeOnCancel: from this point until Connect returns, ctx
// cancellation closes rawConn. That unblocks every layered Read/Write
// (TLS, HTTP upgrade, yamux, control stream) that is otherwise not
// ctx-aware. On a successful return the watcher exits without
// closing — the Session takes ownership of rawConn from here.
done := make(chan struct{})
defer close(done)
go func() {
    select {
    case <-ctx.Done():
        _ = rawConn.Close()
    case <-done:
    }
}()
```

…and just before the `registerWithServer` call:

```go
logger.Info("awaiting RegisterOK from server",
    "unique", opts.Unique,
    "hint", "first-time uniques can take 1–3 min while the server provisions a wildcard cert")
hostname, err := registerWithServer(stream, opts.Unique, opts.PrivateKey, logger)
```

No new flag, no new option, no API change. Pure additive.

## Tests

`internal/tunnelclient/connect_cancel_test.go` (new file):

- **`TestConnect_CtxCancelDuringUpgradeRead`** — listener accepts
  TCP+TLS, then `time.Sleep(forever)` (well, until the test ends)
  without writing the 101 response. Caller cancels ctx after a
  short wait; assert `Connect` returns within ~200ms with an error
  whose chain includes ctx.Err.

- **`TestConnect_CtxCancelDuringYamuxRead`** — listener completes
  the 101 upgrade then sleeps. Same shape: cancel, assert quick
  return with ctx error.

- **`TestConnect_CtxCancelDuringRegisterRead`** — listener completes
  the 101 + yamux handshake but never replies to the `Register`
  control frame. Same shape.

- **`TestConnect_NoGoroutineLeakOnHappyPath`** — pre-count
  `runtime.NumGoroutine()`, run a normal Connect through a fast
  in-process server, Close the session, post-check the count
  returns to baseline (small slop for runtime noise).

The first three exercise distinct blocking-Read sites; the fourth is
the regression gate for "ctx watcher must exit on success."

## Compatibility

Fully additive. No flag changes, no protocol changes, no new env vars.
Existing deployments keep working byte-identically; the only observable
difference is that a previously-stuck Ctrl-C now exits within
milliseconds, and one extra INFO log line appears between `dialing` and
`registered` (or between `dialing` and a Deny/error). Operators who
parse the logs with line-shape-sensitive scripts will see one new line
per Connect attempt — additive, no removed lines.

## Coding rules to honor

- ASCII only in code/markdown.
- Direct commits on `main`, no feature branch (matches this repo's
  shipped-pattern history).
- Loud-failure on parse errors: not applicable (no parsing added).
- All changes ship with extensive unit tests — `go test -race ./...`
  must remain clean.
