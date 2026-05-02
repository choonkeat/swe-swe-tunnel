# Deregister (graceful release)

A client can release its `unique` cleanly with `Session.Deregister(ctx)` (Go API) — sends a signed `Deregister` frame, server verifies against the stored pubkey, deletes the identity row, replies with `DeregisterOK`, tears down the session. After a successful Deregister, **another client with a different key** can claim the same unique without going through the Challenge/Proof reclaim flow.

## Security

- A session can only deregister the unique it's authenticated as (defense-in-depth check).
- The Deregister sig must verify against the *session's* authenticated pubkey (post-rotation safe).

See `cmd/swe-swe-tunneld/deregister_test.go` for the exhaustive test matrix.
