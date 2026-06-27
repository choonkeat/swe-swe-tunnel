# Finding: an Ed25519 mTLS CA cannot be used by Apple (macOS/iOS) clients

**Date:** 2026-06-23
**Status:** RESOLVED 2026-06-27 — fix applied, but this finding's root
cause was **incomplete**; see the correction below.
**Affects:** browser/device mTLS on the public `:443` listener. Does **not**
affect agents (they use the cert-less register port).

---

## RESOLUTION & CORRECTION (2026-06-27)

macOS mTLS now works. Two claims in the original finding below were
wrong, discovered by actually completing the fix:

1. **iOS/iPadOS were NEVER broken.** They work with the *Ed25519* CA and
   always did (verified against the live instance). The "macOS/iOS"
   framing was wrong about iOS — only **macOS** was affected.
2. **The CA algorithm was necessary but not sufficient.** Switching the
   CA to ECDSA P-256 is required (macOS won't import an Ed25519 CA,
   `-25257`), but the missing step was **trusting the CA on the Mac**:
   `security add-trusted-cert -r trustRoot …`. Without it the ECDSA
   identity imports yet stays `CSSMERR_TP_NOT_TRUSTED` and `-p
   ssl-client` lists 0 — the *same* "0 identities" symptom the original
   finding blamed on the signature being unevaluable. It was a trust
   problem, not (only) a signature problem. (We confirmed the ECDSA leaf
   is cryptographically usable by presenting it to the live daemon in a
   real handshake — HTTP 302 — before importing it on the Mac.)

**Complete recipe + commands now live in `docs/mtls.md` → "Apple client
recipe (corrected 2026-06-27)".** Summary: ECDSA CA + import leaf +
trust CA; suppress Safari's per-origin prompt with `security
set-identity-preference`.

**Deployment (no flap):** the daemon's `--mtls-ca` is a *bundle*. A new
ECDSA CA was generated at `{state}/mtls-ecdsa/`, its cert appended to
`{state}/mtls/ca.pem`, and the daemon SIGHUP-reloaded (`count 1->2`).
The original Ed25519 block is byte-unchanged, so existing iPad/iOS certs
keep working; new certs are issued from the ECDSA CA.

**Code:** `InitCA` now mints ECDSA P-256; `CA.key` is a `crypto.Signer`;
`LoadCA` accepts ECDSA *or* legacy Ed25519 (backward compatible). Tests
cover the ECDSA root, the legacy-Ed25519 load/issue/chain path, and the
ECDSA leaf signature.

---

> The original 2026-06-23 finding follows, preserved for the record.
> Treat its "iOS also broken" and "signature unevaluable is the whole
> story" claims as corrected above.

## TL;DR

Our mTLS CA (`internal/mtls/ca.go`, `InitCA`) signs with an **Ed25519**
key. Client leaves are ECDSA P-256 *keys* but carry an **Ed25519
signature** from the CA. Apple's Security framework cannot evaluate the
Ed25519 signature algorithm (OID `1.3.101.112`), so a leaf signed by
this CA **imports but is unusable** for SSL client auth on macOS/iOS.

A `.p12` minted by `mtls-issue` therefore:
- imports cleanly (`1 identity imported`), but
- never appears under `security find-identity -p ssl-client`, and
- is never presented by Safari/Chrome during the TLS handshake.

**Fix:** make the CA sign with ECDSA P-256 (or RSA). Packaging tweaks
cannot work around it.

## How this was missed before

The 2026-05-23 work (`docs/mtls.md` "Apple Keychain" section + the
`IssueClientCert` comments in `ca.go`) correctly fixed the `.p12`
**import** path:
- leaf *key* → ECDSA P-256 (Ed25519 leaf keys fail to decode),
- PKCS#12 cipher combo → `LegacyRC2` + `macIterations=2048`,
- omit the CA cert from the bundle (Apple rejects an Ed25519-signed
  cert in the bundled chain at import).

It then **assumed** that a successful import meant the browser would
present the cert ("the browser only needs the leaf to present during
the TLS handshake" — `docs/mtls.md`, now corrected; and `ca.go:193`
"the CA itself stays Ed25519 (cross-algorithm chains are normal
X.509)"). That assumption was never verified with an actual handshake.
It is false: the leaf's Ed25519 *signature* makes it unusable even
when imported alone.

## Reproduction / symptoms (macOS, 2026-06-23)

```sh
security import user-laptop.p12 -k ~/Library/Keychains/login.keychain-db \
  -P "$(cat user-laptop.txt)" -T /Applications/Safari.app
# => 1 identity imported.

security find-identity -p ssl-client
#   Policy: SSL (client)
#     Matching identities
#        0 identities found        <-- not even matching, under any policy

security find-identity
#   Policy: X.509 Basic
#     Matching identities
#        0 identities found
```

Daemon side, every attempt:
```
http: TLS handshake error from <client>: tls: client didn't provide a certificate
```

Importing the CA cert to "help" makes it worse:
```
Unable to import "swe-swe-tunnel mTLS CA". Error: -25257
```
(Apple won't even parse the Ed25519 CA cert — do not attempt this.)

## Correct verification rule

Never declare an Apple mTLS client cert "working" based on
`1 identity imported`. Require BOTH:

1. `security find-identity -p ssl-client` lists the CN (run WITHOUT
   `-v`; the `-v` "valid" count is a separate red herring tied to chain
   trust and is irrelevant to presentation).
2. A real handshake presents it: the browser cert picker appears, and
   the daemon stops logging `client didn't provide a certificate`.

## The fix (code change — pending approval)

`internal/mtls/ca.go`:
- `InitCA`: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` instead of
  `ed25519.GenerateKey`.
- `CA.key`: type `crypto.Signer` instead of `ed25519.PrivateKey` (holds
  ECDSA *or* Ed25519; keeps `LoadCA` backward-compatible).
- `LoadCA`: accept `rawKey.(crypto.Signer)`.
- `signPub` / `IssueClientCert` / `SignClientPubkey`: unchanged — leaves
  inherit the new ECDSA signature automatically.
- Tests: ECDSA root, `LoadCA` on both algorithms, assert
  `IssueClientCert` emits an ECDSA-signed leaf, e2e mTLS handshake.

### Migration blast radius

- New CA ⇒ **all existing mTLS client certs must be re-issued**:
  `user-laptop`, `user-phone`, `user-ipad`.
- **Agents are unaffected** — `agent-prod` & co. authenticate on the
  cert-less `:<register-port>` register port (allowlist + Ed25519 Register
  signature), which doesn't use the mTLS CA. (Confirm whether any agent
  actually *presents* the leftover `agent-prod.crt` on `:443` before the
  swap; if so, re-sign it with `mtls-sign`.)
- `--mtls-ca` is SIGHUP-reloadable; or do a clean `/run-production`
  recreate. Snapshot/back up the old `ca.key`/`ca.pem` first.

## Process fixes applied alongside this finding

- `docs/mtls.md` "Apple Keychain" section corrected (removed the false
  "leaf is enough to present" claim; added the limitation + verification
  rule).
- This findings file added.
- Cross-session memory entry recorded so future sessions recall the
  limitation without re-deriving it.
- TODO (not yet done): have `/generate-mtls-p12-for-device` read this
  doc in pre-flight and require the two-step verification above before
  reporting success.
