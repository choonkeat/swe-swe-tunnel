# mTLS on the public listener

`swe-swe-tunneld` can require that every browser AND every agent connecting
to the public listener present a client certificate signed by a CA the
operator trusts. This is opt-in: until `--mtls-ca` is set, the daemon's
behaviour is byte-identical to before.

The flag and its accompanying toolkit cover three deployment patterns:

1. **Personal / hobby**: one operator wants the tunnel reachable only from
   their own laptop + phone.
2. **Team / internal**: a handful of named humans need browser access;
   admin issues each a `.p12`.
3. **Enterprise**: an existing internal CA is authoritative; `tunneld`
   trusts certs signed by that CA without doing the issuance itself.

Cases (1) and (2) use the built-in CA toolkit below. Case (3) brings its
own CA bundle and points `--mtls-ca` at it.

## Known limitations

### TLS-intercepting middleboxes

mTLS at the daemon is incompatible with any network path that terminates
TLS at an intermediary and re-originates the connection to the daemon.
The intermediary doesn't have the client's private key, so the
re-originated connection arrives at the daemon with no client cert and
the `RequireAndVerifyClientCert` policy rejects it. This isn't specific
to swe-swe-tunneld — it's intrinsic to mutual TLS over any kind of
HTTPS inspection.

Common cases:

* "SSL inspection" or "HTTPS inspection" appliances and proxies.
* VPN clients that do TLS interception (some commercial / managed VPN
  products do this; consumer VPNs usually don't).
* DLP / endpoint-security tools that proxy outbound HTTPS through a
  local agent.

Symptoms: the browser shows a generic 502 / "bad gateway" page styled
by the intermediary (not by our daemon), and the daemon log shows
`tls: client didn't provide a certificate` for connections from the
intermediary's IP. There's no daemon-side fix.

If you need a host to bypass mTLS, options are: route that host's
traffic around the intermediary (split-tunnel by hostname), or run a
second daemon without `--mtls-ca` on a separate hostname.

### Apple Keychain / iOS profile installer

> ✅ **RESOLVED 2026-06-27.** Apple-client mTLS works. The complete
> recipe has THREE parts; the 2026-06-23 finding had only one:
> 1. **The CA must be ECDSA P-256, not Ed25519** — macOS refuses to
>    import/trust an Ed25519 CA (`OSStatus -25257`), so the chain can
>    never validate. `InitCA` now mints ECDSA P-256.
> 2. **macOS must explicitly TRUST that CA** (`security add-trusted-cert
>    -r trustRoot`). Skipping this leaves the imported identity
>    `CSSMERR_TP_NOT_TRUSTED`, hidden from the SSL-client policy.
> 3. The `.p12` packaging constraints below (for a clean import).
>
> **iOS/iPadOS were never broken** — they work with the *Ed25519* CA and
> need no separate CA-trust step. The 2026-06-23 claim that macOS *and*
> iOS were both broken was wrong about iOS. The daemon trusts a *bundle*
> of both CAs, so existing iOS (Ed25519) certs and new macOS (ECDSA)
> certs coexist. See "Apple client recipe" below.

Apple's PKCS#12 import path is pickier than the format spec allows.
`IssueClientCert` produces `.p12` files that *import* because it matches
what `openssl pkcs12 -export -legacy` emits. The four constraints
baked into `internal/mtls/ca.go`:

* **MAC**: HMAC-SHA-1 with iterations ≥ 2048. The PKCS#12 default
  `macIterations=1` (which most encoders use) is rejected with
  `OSStatus -26276` ("PKCS#12 verify failure").
* **Cert bag encryption**: `pbeWithSHAAnd40BitRC2-CBC` (RC2-40).
  3DES for the cert bag is rejected even when the leaf cert is
  otherwise acceptable. RC2-40 is weak, but it's protecting only
  the public cert bag — the private-key bag stays 3DES.
* **Key bag encryption**: `pbeWithSHAAnd3-KeyTripleDES-CBC` (3DES).
* **Chain certs**: omit from the `.p12` (nil third arg). The client
  presents only the leaf during the handshake; the CA is imported and
  trusted separately (see "Apple client recipe" below). Historically
  Apple's import pre-flight also refused a bundle whose chain contained
  an Ed25519-signed CA — moot now that the CA is ECDSA, but omitting is
  still simplest.
* **Leaf key algorithm**: ECDSA P-256. Ed25519 leaves are rejected
  with "Unable to decode the provided data" on older macOS / iOS,
  inconsistently on newer.

The agent flow (`SignClientPubkey`, `mtls-sign`) is NOT affected by
any of this — agents reuse their Ed25519 `identity.key` and the
signed `.crt` is delivered as a raw PEM, never wrapped in PKCS#12.

#### Apple client recipe (corrected 2026-06-27)

The 2026-06-23 finding diagnosed only the CA *algorithm*, wrongly
concluded both macOS and iOS were broken, and claimed "the browser only
needs the leaf." Re-tested end-to-end on 2026-06-27 — including
verifying the live daemon accepts an ECDSA-CA leaf in a real mTLS
handshake *before* touching the Mac (a cert-less request gets
`certificate required`; one presenting the ECDSA leaf gets through).

**iOS / iPadOS** — work with the **Ed25519** CA, no special steps:
install the `.p12` and the identity is offered. None of the macOS steps
below apply; do not re-issue working iOS certs.

**macOS (Safari/Chrome)** needs all three:

1. **ECDSA P-256 CA.** macOS will not import an Ed25519 CA cert
   (`OSStatus -25257`), so that chain can never be trusted. `InitCA`
   now mints ECDSA P-256; `LoadCA` still loads a legacy Ed25519 CA for
   backward compatibility.
2. **Import the leaf identity:**
   ```sh
   security import user-mac.p12 \
     -k ~/Library/Keychains/login.keychain-db \
     -P "$(cat user-mac.txt)" -T /Applications/Safari.app
   ```
3. **Trust the CA** (the step the old finding missed):
   ```sh
   security add-trusted-cert -r trustRoot \
     -k ~/Library/Keychains/login.keychain-db swe-swe-tunnel-ecdsa-ca.pem
   # if still untrusted, use the system domain:
   # sudo security add-trusted-cert -d -r trustRoot \
   #   -k /Library/Keychains/System.keychain swe-swe-tunnel-ecdsa-ca.pem
   ```
   Without this the identity imports but `security find-identity` shows
   `CSSMERR_TP_NOT_TRUSTED` and `-p ssl-client` lists 0 — macOS hides an
   untrusted identity from the SSL-client policy.

**Verification rule — never declare an Apple mTLS cert "working" on
"1 identity imported" alone.** Require BOTH:

```sh
# 1. macOS lists it as VALID for the SSL-client policy:
security find-identity -p ssl-client      # must contain the CN
# 2. a real handshake presents it (Safari cert picker -> page loads;
#    daemon stops logging "client didn't provide a certificate").
```

**Per-origin prompt.** Safari asks which client cert to use once per
host. With many `<port>.<tunnel>-tunnel.<apex>` origins that is a lot of
prompts. Suppress with an Identity Preference (one wildcard covers all
tunnels):

```sh
security set-identity-preference -c "user-mac" -s "https://*.example.com"
# then quit & reopen Safari
```

**Server side.** `--mtls-ca` is a *bundle*; the daemon trusts every CA
in it (`LoadCABundle`, SIGHUP-reloadable). Production carries BOTH the
original Ed25519 CA (for existing iOS/iPad certs) and a new ECDSA CA at
`{state}/mtls-ecdsa/` (for macOS and all new certs); the ECDSA cert is
appended to `{state}/mtls/ca.pem` and SIGHUP-reloaded — no recreate, no
flap. New certs (including future iPad/iOS) should be issued from the
ECDSA CA. Tracked in
`docs/findings-2026-06-23-macos-mtls-ed25519-ca.md`.

iOS displays imported certs with the generic label "Identity
Certificate" because go-pkcs12's `Encode` doesn't expose the
`friendlyName` bag attribute. Workaround: rename the profile after
import via Settings → General → VPN & Device Management → tap the
profile → Edit name.

## Quick start (built-in CA)

```sh
# 1. Mint a self-signed CA. Writes ca.key (0600) + ca.pem into
#    {state-dir}/mtls/ by default; --dir overrides.
swe-swe-tunneld mtls-init

# 2a. For each browser user, issue a fresh keypair + p12 bundle.
swe-swe-tunneld mtls-issue --cn alice -o /tmp/alice.p12
# stdout prints the passphrase exactly once — capture it before scrolling.

# 2b. For each agent host, sign its existing identity pubkey.
# On the agent host:
openssl pkey -in ~/.swe-swe-tunnel/identity.key -pubout -out agent-01.pub
# Copy agent-01.pub back to the operator, then:
swe-swe-tunneld mtls-sign --pubkey agent-01.pub --cn agent-01 -o agent-01.crt
# Ship agent-01.crt back to the agent host.

# 3. Restart the daemon with mTLS enabled.
swe-swe-tunneld --mtls-ca {state-dir}/mtls/ca.pem ...
```

**Order matters**: do steps (1)/(2) before (3). Enabling `--mtls-ca` on a
daemon that already has live agents cuts those agents off until they are
re-deployed with `--client-cert`.

## Browser side: installing the `.p12`

Distribute `alice.p12` + the printed passphrase out-of-band (e.g. a 1Password
share, a signed Slack DM). The user imports it into:

* **macOS / Safari / Chrome / Firefox**: double-click the `.p12`, type the
  passphrase, leave the import location as login keychain.
* **iOS / iPadOS**: AirDrop the `.p12` to the device → Settings → Profile
  Downloaded → install → enter passphrase.
* **Windows / Edge / Chrome**: double-click → personal certificate store,
  passphrase prompt.
* **Firefox** (own cert store on every platform): Preferences → Privacy &
  Security → Certificates → View Certificates → Your Certificates →
  Import.

Once imported, navigating to the tunneled host triggers the browser's
client-cert chooser. Pick the certificate matching the `--cn` issued
above; the browser remembers per-origin so the prompt only fires once
per session.

If the user doesn't have a cert (or picks the wrong one), the browser
shows its native cert-error page — TLS rejects the handshake before any
of our HTTP code runs. There is no in-band 403 fallback by design (a
graceful 403 would mean keeping a pre-auth attack surface in our Go
HTTP stack).

## Agent side: `--client-cert`

The agent reuses its existing `identity.key` as the TLS private key — one
Ed25519 keypair per agent host, signing both the TLS `CertificateVerify`
and the existing Register-frame Ed25519 signature. There is **no**
`--client-key` flag by design.

```sh
swe-swe-tunnel \
  --server https://tunnel.example.com \
  --unique alice \
  --identity-key ~/.swe-swe-tunnel/identity.key \
  --client-cert /etc/swe-swe-tunnel/agent-01.crt
```

The cert + key pair is loaded once at boot via `tls.X509KeyPair`. If the
agent's identity key was rotated since the cert was issued, the pair fails
to load and the agent exits with `tls config: pair cert+key: ...` —
which is the right behaviour; pinging the daemon with a stale cert wouldn't
help.

The supervisor classifier treats common TLS-handshake failures as
**permanent**: `bad certificate`, `certificate required`,
`unknown certificate authority`, `x509: certificate signed by unknown
authority`, `failed to find any PEM data`, `private key does not match
public key`. On any of those the agent emits one `error` event followed
by `fatal` and exits, instead of looping forever against a server that
will reject every retry the same way.

## Defence-in-depth on `/v1/connect`

When mTLS is on, the agent path runs TWO checks in series:

1. **TLS layer**: client cert is signed by a CA in `--mtls-ca`. Failure →
   handshake aborted before any HTTP.
2. **Register layer**: the Ed25519 signature in the Register frame
   verifies against the claimed pubkey, AND that pubkey equals the
   pubkey in the TLS cert.

The second match is enforced by the daemon. A peer who somehow has a
valid client cert but claims a different pubkey in Register gets a
`Deny{Reason: "not_authorized"}` (same shape as the allowlist refusal;
the log carries `reason_detail=cert_key_mismatch`). The agent treats
that as a permanent deny and exits — saves an operator from running an
agent that can't ever register.

If `--allowlist-dir` is also set, the allowlist check still applies on
top of mTLS (see [`docs/access-control.md`](access-control.md)).
Concretely: the agent must present a CA-signed cert *AND* the pubkey
must appear in some allowlist file. Either gate alone refuses.

## Cert-less agent registration (`--register-listen-without-mtls`)

Turning `--mtls-ca` on locks every live agent out at the TLS layer
until each one is re-deployed with `--client-cert` — which means
minting, distributing, and installing a cert per agent host. When you
want mTLS protecting **browser** access but don't want to issue a cert
to every agent, run a second listener that accepts registration
without one:

```sh
swe-swe-tunneld \
  --mtls-ca {state-dir}/mtls/ca.pem \
  --allowlist-dir /etc/swe-swe-tunnel/allowlist \
  --register-listen-without-mtls :8443 \
  ...
```

- The main listener (`--listen`, default `:443`) is **unchanged**:
  `RequireAndVerifyClientCert` for both the browser proxy *and*
  `/v1/connect`. Agents that hold a `--client-cert` keep using it.
- The new listener mounts **only** `/v1/connect` (plus `/healthz`).
  It does not serve the browser proxy, so there is no cert-less path
  to the data plane. A cert-less agent points its `--server` at this
  port: `--server https://tunnel.example.com:8443`.

This is **additive** — it does not remove the ability to register over
mTLS on `:443`. Agents with certs and agents without can run side by
side; you choose per agent.

The `:8443` above is just an illustration. Treat the actual port as
per-deployment and keep it out of the repo: pick a high, non-obvious
number (avoid 8443/8080/9000 — scanners probe those). With Compose,
wire it via a gitignored `docker-compose.override.yml` (copy
`docker-compose.override.yml.example`) so neither the port nor its
publish mapping is public. Hiding the port cuts opportunistic scan
noise but is **not** a security boundary — the allowlist below is what
actually stops an attacker who finds the port.

### Why it's safe (and the two requirements)

Agent registration is already strongly authenticated without mTLS:
the Ed25519-signed Register frame, a ±5min replay window, per-IP and
per-pubkey rate limits, a slow-loris timeout, and the `--allowlist-dir`
gate. mTLS on the agent path is pure defence-in-depth. So the flag has
two hard preconditions (boot fails loudly without them):

* **`--mtls-ca` is required.** Without mTLS on the main listener, that
  listener already accepts cert-less registration — a second cert-less
  port would be meaningless.
* **`--allowlist-dir` is required.** The allowlist is the gate that
  replaces mTLS here. Without it, the register port is open
  registration reachable by anyone on the internet (rate-limited only).

The register listener uses `VerifyClientCertIfGiven`: a cert-less agent
passes, but an agent that *does* present a cert must present one signed
by `--mtls-ca`, and that verified cert still flows through the
`cert_key_mismatch` binding above (opportunistic defence-in-depth). Its
CA pool is SIGHUP-reloadable, same as the main listener's.

## SIGHUP reload

`kill -HUP <pid>` re-reads the CA bundle from disk. The reload is
atomic; existing TLS connections keep their old pool, new connections
see the new pool. Parse failures keep the prior pool in place and log
`mTLS CA reload failed ... keeping_previous=true`, same shape as the
allowlist reload.

This lets an operator add or rotate trusted CAs without restarting the
daemon.

## Revocation

Phase 1 (this doc) ships with no revocation mechanism. To kick a user out:

* If they hold a cert issued by the built-in CA: rotate the CA
  (`swe-swe-tunneld mtls-init --force`), re-issue certs to remaining
  users, restart the daemon.
* If they hold a cert issued by an external CA: revoke it in the
  external CA, then rotate.

Phase 2 will add a fingerprint denylist file (`revoked.txt`,
SIGHUP-reloadable) so a single user can be kicked without rotating
the CA. The plan is in `tasks/2026-05-21-mtls-public-listener.md`
under "Phase 2".

## Identity propagation to upstream apps

When a request reaches the upstream behind the tunnel, the daemon
attaches two headers derived from the verified peer cert:

* `X-Client-CN`: the cert's Subject Common Name.
* `X-Client-Cert-Fingerprint`: `sha256:` + hex(SHA-256(DER)).

Any inbound copies of these headers are stripped first — even when mTLS
is off — so a fronting load balancer that doesn't know about these
headers can't smuggle a forged identity through to the application.

The upstream can trust these headers because (a) they are stripped on
every request before being re-set, and (b) when mTLS is on, they are
only set when a verified cert is present.

## Pubkey file formats accepted by `mtls-sign`

`--pubkey` accepts either:

* **SPKI PEM**: the format `openssl pkey -in id.key -pubout` emits — a
  PEM block of type `PUBLIC KEY` holding the PKIX-encoded Ed25519
  public key.
* **base64-RawStd**: a single line of raw 32-byte Ed25519 pubkey,
  encoded with `base64 -w0` (no padding, no newline). This is the same
  format `--allowlist-dir` files use, so a single pubkey file works in
  both places.

The two formats are detected by content (PEM block vs raw base64).

## Mixed deployments

mTLS is per *daemon instance*; you cannot turn it on for some
hostnames and off for others on the same listener. To support a mix,
run two daemons with separate `--listen` ports / separate hostnames
and route in front (e.g. a TCP load balancer matching on SNI).
