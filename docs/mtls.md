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

Apple's PKCS#12 import path is pickier than the format spec allows.
`IssueClientCert` produces `.p12` files that work because it matches
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
* **Chain certs**: omit. Apple's pre-flight refuses the entire
  bundle if any cert in the bundled chain has an Ed25519 signature
  (OID `1.3.101.112`). Our internal CA is Ed25519-signed, so we
  don't bundle the CA in the `.p12` — the browser only needs the
  leaf to present during the TLS handshake, and the daemon already
  has the CA via `--mtls-ca`.
* **Leaf key algorithm**: ECDSA P-256. Ed25519 leaves are rejected
  with "Unable to decode the provided data" on older macOS / iOS,
  inconsistently on newer.

The agent flow (`SignClientPubkey`, `mtls-sign`) is NOT affected by
any of this — agents reuse their Ed25519 `identity.key` and the
signed `.crt` is delivered as a raw PEM, never wrapped in PKCS#12.

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
