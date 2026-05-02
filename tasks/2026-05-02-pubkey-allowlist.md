# Tunneld: server-side Ed25519 pubkey allowlist

## Status

**Proposed (2026-05-02).** No code changes yet; this file captures the
scope and rationale for option (1) of the "how do I keep internet
strangers from connecting clients to my tunneld?" discussion.

Companion options that are *not* this task:

- (2) **Shared bearer token on the HTTP upgrade** — cheap DoS filter,
  one secret, no per-user revoke. Layerable in front of this task as
  a future follow-up; intentionally out of scope here.
- Network-layer gates (Tailscale / WireGuard / VPC), mTLS at the TLS
  edge — discussed and ruled out as too heavy for the current
  operator profile (single-operator, friends-and-family clients).

## Why

The control protocol already cryptographically identifies clients —
every `Register` carries an Ed25519 pubkey and a signature over the
canonical payload (`internal/control/proto.go:64`). What's missing is
a *gate* on which pubkeys the server is willing to accept.

Today, anyone who can reach `:443/v1/connect` and complete the
`Upgrade: swe-swe-tunnel/1` handshake can register a fresh keypair
under any unclaimed `unique`, get a wildcard cert minted in their
name, and consume IP + pubkey rate-limit budget. The IP limit
throttles abuse but does not stop it — a determined stranger with a
handful of source IPs can still:

- Register `unique` labels under the operator's apex (DNS-namespace
  squat — every `Register` mints a `*.foo-tunnel.<apex>` cert).
- Burn Let's Encrypt issuance budget against the operator's
  ACME account (LE has its own per-account-per-week limits; a
  stranger consuming them denies *legitimate* clients).
- Park free hostnames on the operator's apex indefinitely (there is
  no GC for orphaned uniques today — see the
  `2026-05-01-identity-from-env.md` task for the broader leak
  discussion).

The minimal fix: maintain a small list of authorized pubkeys on the
server, reject `Register` from anything else *after* signature
verification but *before* cert issuance / store write. The crypto
primitive is already in the protocol; this task adds the policy.

## Scope

In-scope:

- New tunneld config: an allowlist of authorized Ed25519 pubkeys,
  loaded from disk on boot and refreshed on SIGHUP (no restart
  required to add/remove a key).
- Source of truth: a **directory** of files passed via flag/env.
  Each regular file in the directory is parsed; format is one
  base64-RawStd Ed25519 pubkey per line, `#` starts a comment, blank
  lines ignored, and a file may contain one or more keys. The
  encoding matches what the wire protocol uses for `Register.Pubkey`
  (`internal/control/proto.go:67`), so an operator copy-pasting from
  the boot fingerprint of a client trivially produces the right
  value. Directory layout is up to the operator: one file per friend
  (`alice.pub`, `bob-laptop.pub`) is the recommended pattern because
  it makes `ls allowlist/` the audit log, but grouped files are
  fine. Dotfiles and subdirectories are skipped (matches `sshd`'s
  `authorized_keys.d` convention); symlinks within the directory are
  followed.
- Flag: `--allowlist-dir=<path>` (env: `SWE_TUNNEL_ALLOWLIST_DIR`).
  When unset, the gate is **disabled** and the server behaves
  exactly as it does today (open-registration). This preserves the
  no-op upgrade path for the public demo at `tunnel.example.com`.
  When set, even an empty directory means **deny everyone** —
  presence of the flag turns the gate on; key count determines who
  passes. The two states are distinct in logs.
- Enforcement point: in `handleRegister` (`tunnel.go:244`),
  immediately after `ed25519.Verify` succeeds at line 309 and
  before the per-pubkey rate limit / cert ensure / store write.
  Rejection sends `Deny{reason:"not_authorized"}` (terminal — same
  shape as other Deny paths) and returns false.
- **Live revoke**: when a SIGHUP reload removes a pubkey, the
  server immediately closes any *currently-open* yamux sessions
  whose Register'd pubkey is no longer in the set. Without this,
  a client that registered before being revoked keeps tunneling
  traffic until its connection happens to drop on its own — i.e.
  the gate would only stop *new* registrations, never an
  in-flight session. The client's existing fatal-deny handling
  takes over from there: its reconnect loop hits `not_authorized`
  on retry and the supervisor stops.
- **Operator workflow** (the chat-driven add/remove pattern this
  feature is designed for): the running tunneld container
  bind-mounts the host allowlist directory, so the operator (or a
  chat agent acting on their behalf) drops/removes a `*.pub` file
  on the host and signals the container with
  `docker kill -s HUP swe-swe-tunneld`. No container recreation,
  no `/run-production` re-run. See "Operator workflow" below for
  the compose change and the rename-based-editor gotcha.
- Boot log: one line per allowlist load summarizing
  `count=<n> source=<path>`. On SIGHUP reload, log the diff
  (`added=<n> removed=<n>`) so the operator can confirm intent.
- Per-allowlist-key fingerprint exposure: when an allowed key
  registers, include the SHA-256 fingerprint prefix in the existing
  Register success log alongside `unique` so the operator can
  cross-reference "who claimed what." Same `hex(sha256(pub))[:12]`
  shape used by the client-side identity log
  (`tasks/2026-05-01-identity-from-env.md`).
- Tests for: gate-off (no flag) preserves current behavior;
  gate-on with key in list registers normally; gate-on with key
  *not* in list gets `not_authorized` Deny and no store write, no
  cert ensure call; SIGHUP reload picks up an added file (`cp
  alice.pub allowlist/`); SIGHUP reload picks up a removed file
  (`rm allowlist/alice.pub`) and that key is now denied; SIGHUP
  reload that removes a key whose session is currently open
  closes that session within a small bound (target: under 100 ms
  in-process); malformed file at boot fails loud (server exits
  non-zero, not silent open-registration); malformed file on
  SIGHUP keeps the previous in-memory list (don't atomically
  swap to a broken state); empty directory with the flag set
  means "deny everyone" (explicit operator intent — not the same
  as flag-unset); dotfiles and subdirectories under the
  allowlist dir are ignored.

Out of scope:

- Option (2), the bearer-token gate at the HTTP upgrade. Layerable
  later; tracked as a follow-up.
- A web/admin UI for managing the allowlist. The directory is the API.
- Per-key permissions (which `unique` a given key is allowed to
  claim, expiry, labels, etc.). The gate is binary: in-list or not.
  Per-key policy is a follow-up if/when needed.
- A "pending approval" queue (stranger registers → operator
  approves out-of-band). Adds a stateful side-channel and a UX
  surface; deferred. Operators can mint and add keys
  out-of-band today.
- DEREGISTER side: today's deregister path verifies the signature
  against the *stored* pubkey (the key that originally claimed the
  unique). That's already correct — a stranger with a brand new
  key cannot deregister someone else's unique. The allowlist does
  not change deregister behavior; an operator who removes a key
  from the allowlist disables future *new* registrations from it
  but leaves existing claims intact (the stranger can still
  deregister their own claim, which is the desired behavior — it
  frees the namespace).
- A tunneld-side TTL / GC for orphaned uniques. Same scope-cut as
  the identity-from-env task; tracked separately.

## Security

The allowlist is operator-controlled access policy. Two design
choices follow:

1. **Directory of files, not env-based.** The list is a small set
   of public, non-secret values, but it's also expected to grow
   over time (add a friend, rotate a key). A directory of drop-in
   files is the natural shape: `cp alice.pub allowlist/`,
   `kill -HUP <pid>`, done; revoke is `rm allowlist/alice.pub`.
   Filenames double as ownership labels and `ls allowlist/` is the
   audit log. An env var would force a restart per change and
   turns the list into a single long string that's awkward to
   diff. The directory is also the right shape for config
   management (Ansible, Nix, etc.) if the operator wants to
   template it, and matches the muscle memory operators have from
   `sshd`'s `authorized_keys.d`.
2. **Loud-failure on malformed boot config; preserve-old on
   malformed reload.** If the operator boots with a typo'd
   allowlist, exit non-zero — the alternative ("fall back to
   open-registration") silently disables the gate the operator
   asked for, which is the dangerous direction. On SIGHUP, however,
   keep serving the previously-loaded list and log loudly: a
   running server with a known-good allowlist should not
   regress to open-registration mid-flight just because a sysadmin
   mistyped one line in an editor.

The allowlist itself contains *public* keys only, so leaking the
directory is not a credential exposure — it's a list of who the
operator trusts. Treat it like an `authorized_keys.d` directory
(and, in fact, the analogy is exact: Ed25519 pubkeys, line-per-key,
`#` comments, one or more keys per file).

## Operator confidence: boot + reload log lines

On boot:

```
allowlist loaded source=/etc/swe-swe-tunneld/allowlist files=3 count=4
```

(Or `count=0 (deny-all)` when the directory exists but contains no
keys — empty dir + flag set is an explicit operator intent.)

On SIGHUP:

```
allowlist reloaded source=/etc/swe-swe-tunneld/allowlist files=4 count=5 added=1 removed=0
allowlist reload failed source=/etc/swe-swe-tunneld/allowlist err="alice.pub line 2: bad base64" keeping_previous=true
```

When gate-off (no flag):

```
allowlist disabled (no --allowlist-dir set; open registration)
```

This last line is deliberately loud — operators who think they
turned the gate on but mistyped the flag name should see it on
boot. (Same rationale as the loud "DNS provider not configured"
warning the cert manager already prints.)

When an allowed key registers, augment the existing success log:

```
register ok unique=foo label=foo-tunnel pubkey_fp=ab12cd34ef56 ...
```

When a not-allowed key registers and is rejected:

```
register denied: not_authorized unique=foo pubkey_fp=99887766aabb remote=1.2.3.4
```

The fingerprint in the deny log is the operator's hook for "is this
just so-and-so on a new laptop, or a stranger?" If it matches a
fingerprint they recognize (or the boot fingerprint of a client
they were trying to onboard), the action is "add this line to the
allowlist + SIGHUP." If not, it's a real stranger and the operator
has an audit trail.

## Operator workflow (chat-driven add/remove on the live container)

The intended day-to-day pattern: a friend pastes their pubkey into a
chat session in this repo; an agent (or the operator directly) drops
a one-line file into the allowlist directory, signals the daemon,
and the new key is live with no container recreation. Revoke is
`rm` on that same file plus a SIGHUP.

For this to work end-to-end on the live container at
`tunnel.example.com` (managed by the `/run-production` skill), the
daemon must be reading a directory the host can also write to. Two
specifics matter:

1. **Bind-mount the directory.** Add to `docker-compose.yml`:

   ```yaml
   volumes:
     - tunnel-data:/var/lib/swe-swe-tunnel
     - ./allowlist:/etc/swe-swe-tunneld/allowlist:ro
   ```

   …and pass `--allowlist-dir=/etc/swe-swe-tunneld/allowlist`
   (or the env equivalent). Bind-mounting a *directory* is what
   makes drop-in / rename-based writes work cleanly. Bind-mounting
   a single file pins the container's view to one inode; an editor
   that writes via "create temp + rename" — and `cp` over an
   existing target — leaves the container looking at the
   now-unlinked original forever. Mounting the directory means
   `cp alice.pub allowlist/` and `rm allowlist/alice.pub` show up
   immediately on the daemon's next read.

   `:ro` is fine — the daemon only reads the directory. The host
   process doing the editing isn't subject to the read-only flag,
   which only constrains the *container's* view.

2. **The reload signal.** From the host:

   ```sh
   docker kill -s HUP swe-swe-tunneld
   ```

   That delivers SIGHUP to PID 1 inside the container, which the
   daemon's signal goroutine picks up and calls `Reload`. Total
   round trip: drop file, send signal, daemon logs
   `allowlist reloaded ... added=1 removed=0`. New keys can
   register on the very next attempt; revoked keys' sessions are
   closed in the same call (see "Implementation sketch" below).

The chat-agent recipe becomes a three-step shell snippet:

```sh
# Add alice's laptop key:
printf '%s  # alice@laptop %s\n' "$NEW_KEY" "$(date -u +%Y-%m-%d)" \
    > ./allowlist/alice-laptop.pub
docker kill -s HUP swe-swe-tunneld
docker logs --tail 5 swe-swe-tunneld   # confirm the reload line

# Revoke alice's laptop key:
rm ./allowlist/alice-laptop.pub
docker kill -s HUP swe-swe-tunneld
docker logs --tail 5 swe-swe-tunneld   # expect "session terminated: revoked" if active
```

Out of scope (intentionally — both are easy follow-ups if this UX
proves clunky):

- **fsnotify watcher** in the daemon to remove the manual SIGHUP
  step. Adds a dependency and the standing rename-vs-write event
  debounce concern; not worth it for the first cut. SIGHUP is
  one extra command.
- **Admin HTTP endpoint** (`POST /admin/allowlist/add` etc.) so a
  chat agent never touches the host filesystem. Cleaner UX but
  introduces auth surface that itself needs gating, exactly the
  problem this whole task is supposed to solve. File + SIGHUP is
  the right starting point.

## Encoding & file format

Layout — a directory of regular files, each with one or more keys.
Recommended (and used by the example below): one file per friend/
laptop, with the filename as the human label. A single bundle file
with everyone's keys is also fine; the parser unions all files.

```
allowlist/
├── alice-laptop.pub
├── alice-desktop.pub
├── bob-laptop.pub
└── ci-runner.pub
```

Each file:

```
# alice@laptop — base64 RawStd of Ed25519 pubkey (32 bytes)
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh
```

Or grouped:

```
# Friends & laptops — base64 RawStd of Ed25519 pubkey (32 bytes)
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh   # alice@laptop
ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210hgfedcba   # alice@desktop
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ   # bob@laptop
```

Skipped at load time: dotfiles (`.gitkeep`, `.DS_Store`,
`.swp` etc.) and subdirectories — matches `sshd`'s
`authorized_keys.d` convention. Symlinks are followed, so an
operator can `ln -s ~/keys-repo/alice.pub allowlist/alice.pub`
to track keys from a separate git checkout.

Why base64-RawStd:

- It's exactly the encoding the wire protocol uses for `Register.Pubkey`
  (see `internal/control/proto.go:67`). An operator who copies a
  pubkey out of a tunneld debug log gets a value that drops straight
  into a file with zero re-encoding.
- It's URL/JSON-safe and one canonical form (no padding ambiguity).
- It's exactly what the consumer-side `swe-swe tunnel-identity create`
  follow-up (planned in the identity-from-env task) is going to
  print as the public half. Operators will paste it directly.

The optional `# comment` after the key is just for human bookkeeping
and is ignored by the parser. The filename itself is also free-form
metadata that survives across reloads — `alice-laptop.pub` is a
sufficient label without a comment. Future per-key metadata
(labels, expiry) would replace the inline comment with a structured
second column; today, it's free-form.

## Implementation sketch

New package `internal/allowlist/` (single file, mirrors the shape of
`internal/identity/store.go`):

```go
// Package allowlist holds the set of Ed25519 public keys tunneld is
// willing to accept Register from. Loaded from a directory of files
// at boot and refreshed on SIGHUP. Safe for concurrent reads.
package allowlist

import (
    "bufio"
    "crypto/ed25519"
    "encoding/base64"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "sync/atomic"
)

type Set struct {
    keys  atomic.Pointer[map[[32]byte]struct{}] // pubkey bytes → present
    files atomic.Int64                          // count of files read on last load (for log lines)
    dir   string
}

// Load walks dir, parses every regular file it finds, and returns a
// fresh Set. Returns error if the directory cannot be read or any
// non-comment / non-blank line in any file fails to parse — the
// caller decides whether that's fatal (boot) or recoverable (SIGHUP
// reload).
func Load(dir string) (*Set, error) {
    set, files, err := parseDir(dir)
    if err != nil {
        return nil, err
    }
    s := &Set{dir: dir}
    s.keys.Store(&set)
    s.files.Store(int64(files))
    return s, nil
}

// Reload re-reads the configured directory. On parse error, the
// in-memory set is unchanged and the error is returned for the
// caller to log.
func (s *Set) Reload() (added, removed, files int, err error) {
    next, files, err := parseDir(s.dir)
    if err != nil {
        return 0, 0, 0, err
    }
    prev := *s.keys.Load()
    for k := range next {
        if _, ok := prev[k]; !ok {
            added++
        }
    }
    for k := range prev {
        if _, ok := next[k]; !ok {
            removed++
        }
    }
    s.keys.Store(&next)
    s.files.Store(int64(files))
    return added, removed, files, nil
}

// Contains reports whether pub is in the current allowlist.
func (s *Set) Contains(pub ed25519.PublicKey) bool {
    if len(pub) != ed25519.PublicKeySize {
        return false
    }
    var k [32]byte
    copy(k[:], pub)
    m := *s.keys.Load()
    _, ok := m[k]
    return ok
}

// Len returns the current allowlist size (for log lines).
func (s *Set) Len() int { return len(*s.keys.Load()) }

// Files returns the number of files contributing to the current
// set (for log lines).
func (s *Set) Files() int { return int(s.files.Load()) }

// parseDir reads dir and returns the union of keys across every
// regular file. Dotfiles and subdirectories are skipped (matches
// sshd's authorized_keys.d). Symlinks are followed via os.Open.
// Files are processed in lexical order so a duplicate-key error
// names a deterministic file.
func parseDir(dir string) (map[[32]byte]struct{}, int, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return nil, 0, fmt.Errorf("read allowlist dir: %w", err)
    }
    sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

    out := make(map[[32]byte]struct{})
    files := 0
    for _, e := range entries {
        name := e.Name()
        if strings.HasPrefix(name, ".") {
            continue // dotfiles
        }
        // Stat through symlinks so we follow links to regular files.
        info, err := os.Stat(filepath.Join(dir, name))
        if err != nil {
            return nil, 0, fmt.Errorf("stat %s: %w", name, err)
        }
        if !info.Mode().IsRegular() {
            continue // subdirs, devices, sockets, broken symlinks
        }
        if err := parseInto(filepath.Join(dir, name), name, out); err != nil {
            return nil, 0, err
        }
        files++
    }
    return out, files, nil
}

func parseInto(path, displayName string, out map[[32]byte]struct{}) error {
    f, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", displayName, err)
    }
    defer f.Close()

    sc := bufio.NewScanner(f)
    lineNo := 0
    for sc.Scan() {
        lineNo++
        line := strings.TrimSpace(sc.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        // Strip trailing "  # comment".
        if i := strings.Index(line, "#"); i >= 0 {
            line = strings.TrimSpace(line[:i])
        }
        b, err := base64.RawStdEncoding.DecodeString(line)
        if err != nil {
            return fmt.Errorf("%s line %d: bad base64: %w", displayName, lineNo, err)
        }
        if len(b) != ed25519.PublicKeySize {
            return fmt.Errorf("%s line %d: pubkey is %d bytes, want %d",
                displayName, lineNo, len(b), ed25519.PublicKeySize)
        }
        var k [32]byte
        copy(k[:], b)
        out[k] = struct{}{} // duplicate keys across files are silently unioned
    }
    if err := sc.Err(); err != nil {
        return fmt.Errorf("scan %s: %w", displayName, err)
    }
    return nil
}
```

In `cmd/swe-swe-tunneld/main.go`:

- Add `--allowlist-dir` flag (env fallback `SWE_TUNNEL_ALLOWLIST_DIR`).
- After ratelimit setup, if the flag is set, call `allowlist.Load(dir)`;
  exit non-zero on error. Log "allowlist loaded ... files=F count=N"
  (and "(deny-all)" suffix when `count=0`).
- If unset, log the loud "allowlist disabled" line and pass `nil`
  through.
- Pass the `*allowlist.Set` (or nil) into `connectHandler` and on
  into `handleRegister`. Also pass it (and the `*registry`) into
  the SIGHUP goroutine so reload can trigger live-revoke.
- Wire SIGHUP: existing signal handling (if any — check) plus a
  `for sig := range sigCh { if set != nil { added, removed, files,
  err := set.Reload(); ... reg.RevokeMissing(set, logger) } }`
  goroutine. Log success or "reload failed ... keeping_previous=true"
  on error. Run `RevokeMissing` only on successful reload — don't
  drop sessions when the new directory failed to parse.

### Live revoke: registry changes

The current `registry` (`tunnel.go:58`) indexes only by label
(`{unique}-tunnel`). To close sessions for a revoked key on
reload, add a parallel pubkey index. One pubkey can hold multiple
labels (a single client could register several uniques over time),
so the index value is a set:

```go
type registry struct {
    mu       sync.RWMutex
    sessions map[string]*tunnelSession    // label → session
    byPubkey map[[32]byte]map[string]*tunnelSession // pubkey → label → session
}

func (r *registry) add(label string, pub []byte, ts *tunnelSession) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    if _, ok := r.sessions[label]; ok {
        return fmt.Errorf("label %q already connected", label)
    }
    r.sessions[label] = ts
    var k [32]byte
    copy(k[:], pub)
    if r.byPubkey[k] == nil {
        r.byPubkey[k] = make(map[string]*tunnelSession)
    }
    r.byPubkey[k][label] = ts
    return nil
}

func (r *registry) remove(label string, pub []byte, ts *tunnelSession) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if cur, ok := r.sessions[label]; ok && cur == ts {
        delete(r.sessions, label)
    }
    var k [32]byte
    copy(k[:], pub)
    if m := r.byPubkey[k]; m != nil {
        if cur, ok := m[label]; ok && cur == ts {
            delete(m, label)
        }
        if len(m) == 0 {
            delete(r.byPubkey, k)
        }
    }
}

// RevokeMissing closes every live session whose pubkey is no longer
// in allow. Safe to call concurrently with Register/data-plane
// traffic; sess.Close on yamux is idempotent and unblocks the
// connectHandler goroutine that's parked on <-sess.CloseChan().
func (r *registry) RevokeMissing(allow *allowlist.Set, logger *slog.Logger) {
    if allow == nil {
        return // gate disabled — nothing to revoke
    }
    var victims []*tunnelSession
    var labels []string
    var fps []string
    r.mu.RLock()
    for k, byLabel := range r.byPubkey {
        if !allow.Contains(k[:]) {
            for label, ts := range byLabel {
                victims = append(victims, ts)
                labels = append(labels, label)
                fps = append(fps, fingerprint(k[:]))
            }
        }
    }
    r.mu.RUnlock()
    for i, ts := range victims {
        logger.Warn("session terminated: revoked",
            "label", labels[i], "pubkey_fp", fps[i])
        _ = ts.Close()
    }
}
```

The `Close` happens *outside* the lock — yamux `Close` may take
real time (it writes a GoAway frame and waits briefly for ACK),
and we don't want to block concurrent `add`/`remove` callers
behind that. The eventual `remove` triggered by the
`connectHandler` defer at `tunnel.go:170` (`defer sess.Close()`
plus the cleanup that runs when `<-sess.CloseChan()` fires) cleans
the pubkey index entry the normal way.

Existing `add` / `remove` call sites (search `tunnel.go` for `reg.add(` /
`reg.remove(`) need their pubkey-bytes argument added — currently
the pubkey is local to `handleRegister` (the `pub` variable
returned in `registerResult{...pubkey: pub}` at lines 356, 367)
and just needs to thread to where `reg.add` is called.

In `cmd/swe-swe-tunneld/tunnel.go`:

- Extend `handleRegister` signature with `allow *allowlist.Set`.
- Insert the gate immediately after the existing `ed25519.Verify`
  check at line 309:

  ```go
  if allow != nil && !allow.Contains(pub) {
      logger.Warn("register denied: not_authorized",
          "remote", remoteAddr, "unique", reg.Unique,
          "pubkey_fp", fingerprint(pub))
      sendDeny(stream, "not_authorized")
      return registerResult{}, false
  }
  ```

- Tiny helper `fingerprint(pub []byte) string` returning
  `hex.EncodeToString(sha256.Sum256(pub)[:6])` — same shape the
  client emits at boot. Put it next to `sendDeny` in `tunnel.go`
  (or in `internal/control/` if it's reused; start local).

## Tests

In `internal/allowlist/`:

- `Load`: valid directory with several files (mixed
  comments/blanks/inline-comments, multi-key files) returns the
  right key set; `Files()` reports the number of regular files
  parsed.
- `Load`: missing directory returns wrapped error containing the
  path.
- `Load`: empty directory + flag set returns an empty set, no
  error (the deny-all case).
- `Load`: malformed line in some file returns an error naming the
  *filename* and the line number (e.g. `alice.pub line 2: bad
  base64`) — this is the error the boot path treats as fatal.
- `Load`: wrong key length (e.g. 30 bytes) returns an error naming
  filename + line number.
- `Load`: dotfiles (`.gitkeep`, `.swp`) are skipped silently.
- `Load`: subdirectories under the allowlist dir are skipped
  silently — a nested `archive/` full of old keys does not affect
  the result.
- `Load`: symlink to a regular file is followed and parsed.
- `Load`: duplicate key across two files is unioned (no error,
  one entry in the set).
- `Reload`: add a new file, reload, `Contains` for new key flips
  false→true, `added=1 removed=0 files=N+1` returned.
- `Reload`: remove a file, reload, `Contains` flips true→false,
  `added=0 removed=1 files=N-1` returned.
- `Reload`: rename a file (same key contents, different filename)
  is a no-op — `added=0 removed=0` (set is keyed by pubkey, not by
  filename).
- `Reload`: parse error after a successful initial load — error
  returned, in-memory `Contains` for all previously-allowed keys
  still true (state preserved), `Files()` still reports the
  previous count.
- `Contains`: nil set (allowlist disabled) is the *caller*'s job to
  short-circuit; `Contains` on a `nil *Set` is not a supported call
  (verify with a "skip if nil" pattern in `handleRegister`).
- `Contains` is concurrent-safe: spin a goroutine doing `Reload` in
  a loop while another goroutine does `Contains`; race detector
  must stay quiet (this is what the `atomic.Pointer` is buying).

In `cmd/swe-swe-tunneld/register_test.go` (extending the existing
table):

- `gate_off`: no allowlist passed (nil) — current open-registration
  behavior preserved (existing tests keep passing).
- `gate_on_allowed`: allowlist contains the test client's pubkey —
  Register succeeds, store write happens, cert ensured.
- `gate_on_denied`: allowlist does NOT contain the test client's
  pubkey — Register receives `Deny{reason:"not_authorized"}`, store
  has no row for the unique, certEnsurer recorded zero calls.
- `gate_on_after_signature`: signature is invalid AND key is
  in-list — must still fail with `signature invalid` (the gate runs
  *after* sig verification; we don't leak whether a key is on the
  list to a peer who can't sign for it).
- `gate_on_after_signature_inverse`: signature is valid AND key is
  NOT in list — must fail with `not_authorized` (the inverse: we
  do reveal "your key isn't on the list" to peers who *can* sign
  for it; this is by design — the operator wants to be able to tell
  a friend "your boot fingerprint isn't on the list yet, send it
  to me").

In `cmd/swe-swe-tunneld/register_test.go` (registry-level):

- `RevokeMissing_dropsRemoved`: register two sessions under
  different pubkeys; reload allowlist with only one of them;
  call `reg.RevokeMissing(allow, logger)`; assert the
  unallowed-pubkey session's `Close` was called and the allowed
  session's was not.
- `RevokeMissing_noopWhenAllAllowed`: same setup, but reload
  keeps both pubkeys; `RevokeMissing` closes nothing.
- `RevokeMissing_nilAllow`: nil allow returns immediately and
  closes nothing (gate-disabled invariant).
- `add_remove_pubkeyIndex`: assert the `byPubkey` index stays
  consistent across add/remove pairs and across multiple labels
  per pubkey.

In `cmd/swe-swe-tunneld/e2e_test.go`:

- One end-to-end variant: spin tunneld with `--allowlist-dir`
  pointing to a `t.TempDir()`, run the existing register-handshake
  helper with a key NOT in any file — assert the client receives
  `not_authorized` and the server logs the deny line (capture via
  the existing test slog handler).
- One end-to-end variant: same but with the key dropped into
  `<dir>/test.pub` — asserts the existing happy-path still works
  with the gate on.
- Add-and-allow variant: start with empty directory, attempt
  register → denied; `os.WriteFile(<dir>/new.pub, ...)` to add
  the key, send SIGHUP (or call the in-process `Reload` hook —
  see below), retry register → succeeds.
- **Live-revoke variant**: start with key K in `<dir>/k.pub`,
  register K, run an HTTP request through the tunnel to confirm
  the session is live; `os.Remove(<dir>/k.pub)`; SIGHUP; assert
  the client sees its session dropped within a small bound
  (target: under 100 ms after the reload returns); the client's
  reconnect attempt then receives `not_authorized` and stops.
  This is the test that proves the chat-driven revoke story
  actually works end-to-end.

(If the existing e2e harness runs tunneld in-process rather than
as a child, expose `Reload` as a test hook on the registry
struct or the connectHandler closure rather than relying on
signal delivery — same effect, less flake. The signal-delivery
path is already covered by the standalone signal-handler test
in main; the e2e doesn't need to re-prove that wiring.)

## Compatibility

Fully additive. Existing deployments that:

- Don't pass `--allowlist-dir`: unaffected. Same open-registration
  behavior as today. The boot log gains the "allowlist disabled"
  line — operators can grep for it if they want to confirm.
- Pass `--allowlist-dir` for the first time: any client whose
  pubkey isn't in some file under the directory gets
  `not_authorized`. The operator's obligation is to seed the
  directory with their *own* clients' pubkeys before flipping the
  flag — the "register denied" log line gives them a clean way to
  spot any they missed.

No deprecation, no breaking change to the wire protocol. The new
`Deny.Reason="not_authorized"` value is just another string in an
already-extensible field; old clients display it the same as any
other Deny.

## Sequencing

1. Land `internal/allowlist/` (package + tests) in its own commit.
2. Extend the `registry` with the pubkey index + `RevokeMissing`,
   plus the unit tests above. This commit doesn't yet wire the
   allowlist into the Register flow — it just makes the registry
   capable of revoke. Independently testable.
3. Wire the flag, the boot load, and the SIGHUP reload in
   `cmd/swe-swe-tunneld/main.go` in the next commit. The
   `connectHandler` signature change and the
   `RevokeMissing(set, logger)` call inside the SIGHUP handler
   ride along. Run `RevokeMissing` only on successful reload —
   don't drop sessions when the new file failed to parse.
4. Add the `handleRegister` gate + register_test.go gate cases +
   e2e variants (including the live-revoke e2e) in the fourth
   commit. Each commit independently compiles + passes tests
   (matches the repo's shipped-pattern small-commit cadence).
5. Update `docker-compose.yml` to bind-mount `./allowlist/` and
   pass `--allowlist-dir=/etc/swe-swe-tunneld/allowlist`, plus a
   one-paragraph note in `docs/design.md` and the README's
   "running your own tunneld" section. Ship the `./allowlist/`
   directory with a `.gitkeep` (so the empty dir survives `git
   clone`); live operators drop their own `*.pub` files into it.
6. Decide separately whether to enable the gate on the
   `tunnel.example.com` production instance. The default-off
   behavior means landing this code does not change the live
   server's policy. The user's stated motivation is "stop
   strangers"; flipping it on is a one-flag deploy after seeding
   the file with the operator's own keys. After the first
   `/run-production` run *with* the bind-mount in place, all
   subsequent add/remove operations are SIGHUP-only and never
   need `/run-production` again.

## Coding rules to honor

- ASCII only in code/markdown.
- Direct commits on `main`, no feature branch (matches this repo's
  shipped-pattern history).
- Loud-failure on boot when the operator clearly asked for the
  gate; preserve-previous on hot-reload to avoid mid-flight
  regressions.
- Tests gate every behavior change: extensive unit + e2e is the
  standing bar (see `feedback_testing_coverage.md`).
- `Contains` must be concurrent-safe with `Reload`; pin with the
  race-detector test, not just a comment.
- Don't conflate "gate disabled" (nil) with "gate enabled but
  empty directory" (deny everyone). The two are operator intents
  and must stay distinguishable in code AND in logs.
- `RevokeMissing` must close sessions *outside* the registry
  lock. yamux `Close` writes a GoAway and waits briefly for ACK;
  blocking `add`/`remove` callers behind that would stall the
  whole control-plane during a reload.
- `RevokeMissing` only runs on a *successful* reload. A reload
  that returned an error must not drop sessions — the in-memory
  set didn't change, so the allowlist policy didn't change, so
  no revoke is warranted.
