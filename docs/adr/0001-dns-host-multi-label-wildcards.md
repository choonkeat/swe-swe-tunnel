# ADR 0001 — Multi-label wildcard resolution as a hard DNS-host requirement

* **Status:** Accepted (as of 2026-04-28)
* **Decision driver:** operational simplicity vs DNS-host portability
* **Affected components:** `cmd/swe-swe-tunneld`, `internal/cert`, the deployment runbook

## Context

The public address of a tunneled service is `{port}.{unique}-tunnel.{apex}` — three labels deep beneath the apex. For a browser request to `1977.alice-tunnel.example.com` to reach the tunnel server, **the apex's authoritative DNS must resolve that 3-label name to the server's IP address**, even though no per-host A record exists for it.

There are two ways to satisfy that:

1. **Permissive wildcard** — the apex publishes a single A record (`*.example.com → IP`) and the DNS host returns that IP for *any* descendant, regardless of label depth. New session names work instantly with zero DNS-API traffic.
2. **Per-session A records** — when a tunnel registers, the server calls the DNS provider's API to create `*.{unique}-tunnel.{apex} → IP` (or specific port labels). Standards-pure, but every register/deregister now traverses the DNS API and waits for propagation.

A strict reading of [RFC 1034 §4.3.3](https://www.rfc-editor.org/rfc/rfc1034#section-4.3.3) and [RFC 4592 §2.1](https://www.rfc-editor.org/rfc/rfc4592#section-2.1) says wildcards match exactly **one** label. By that reading, `*.example.com` covers `foo.example.com` but **not** `bar.foo.example.com`. Many DNS hosts (Cloudflare, AWS Route 53 in their default mode, …) implement that strict semantic. Others — DNSimple is the one we run on — extend the match to descendants of any depth, which is the behaviour we rely on.

## Decision

Adopt **option 1** (permissive multi-label wildcard) as the default deployment model and document it as a **hard requirement** of the DNS host operating the apex. Per-session DNS-API integration is **out of scope** for the default configuration; we surface a clear error if it's needed and document the integration point so a future operator can add it.

## Consequences

### What we get

- **Zero DNS-API calls on the hot path.** Register and deregister never touch the DNS host. Operationally important: if the DNS provider's API is down, existing sessions keep working and new sessions can register (cert issuance separately depends on DNS-01, but only on first registration of that label — see "boundary" below).
- **Sub-second registration latency.** A new tunnel is reachable as soon as the cert is on disk and the registry entry exists. No DNS propagation wait.
- **Smaller blast radius for credentials.** The DNS API token still has to exist (for ACME DNS-01), but it isn't exercised on every connection, so we can rotate or scope it more aggressively.

### What it costs

- **DNS-host portability is reduced.** swe-swe-tunnel will not work out of the box on any DNS host that strictly enforces single-label wildcards.
- **Operators have to verify wildcard behaviour at boot.** A misconfigured DNS host produces a confusing failure mode (TLS handshake reaches the cert manager, but the browser request never arrives because DNS resolved to nowhere). We mitigate this with a boot-time self-check (see "Mitigations").
- **The `*.example.com` cert covers more than the strict reading of "wildcard" implies.** TLS clients accept exact-match SANs and one-level wildcards; for the data-plane hostnames (`{port}.{label}.example.com`) we therefore issue a **second**, per-session wildcard `*.{label}.example.com` to satisfy the chain. This isn't a correctness issue (it's how the cert manager already works), but it explains why we pay for two wildcards per session even though the DNS layer is happy with one.

### Boundary: ACME DNS-01

Cert issuance via DNS-01 *does* still call the DNS provider — but only at:
- Server boot (apex cert) once per ~60 days.
- First registration of a new `{unique}-tunnel` label (per-session cert), once per session lifetime.

These calls go through `lego`'s provider abstraction (`internal/cert/manager.go` `Manager.NewProvider`), which is independent of the wildcard-resolution decision above. **You can use any provider lego supports for ACME, regardless of whether your A-record wildcard is permissive or strict.**

## Alternatives considered

### A. Per-session A-record creation (rejected for v1)

On REGISTER, after `EnsureName` issues the cert, also create `*.{unique}-tunnel.{apex} → IP` via the DNS provider's API. On Deregister, delete the record.

* **Pros**: works on any DNS host; standards-pure; no operator surprise.
* **Cons**: REGISTER now blocks on DNS API + propagation (typically 5–60s); DNS-API outages break new tunnels; doubles the credential surface (need write access on every register).
* **When to revisit**: if/when we want to ship to operators on Cloudflare or strict-mode Route 53. The integration point is well-isolated — see "Integration point" below.

### B. CNAME at every depth (rejected as unworkable)

Pre-create a fixed set of port-label CNAMEs (`1977.*.example.com → *.example.com`, …). Doesn't actually work — CNAME at a wildcard label has the same one-level-match issue and isn't widely supported.

### C. SNI proxy in front (rejected as scope creep)

Run a stripped-down DNS server *inside* `swe-swe-tunneld` and have operators delegate the apex (or a sub-domain) to it. Fixes wildcard depth at the source. Massive operational complexity (now we own the apex's auth-NS), out of scope for v1, but logged here for completeness.

## Integration point (future)

If a future operator wants per-session A-record creation, the hook is one function in `cmd/swe-swe-tunneld/tunnel.go` — `handleRegister`, in the `errors.Is(err, identity.ErrNotFound)` branch, immediately after the existing `certMgr.EnsureName(ctx, label)` call. Symmetric on Deregister: `cmd/swe-swe-tunneld/tunnel.go` `handleDeregister`, immediately after `store.Delete`. The DNS-provider abstraction already exists at `cert.Manager.NewProvider` — reuse the same provider factory, just call its A-record API instead of (or alongside) DNS-01.

A minimal v1 of this would be ~30 lines + a `--per-session-dns` flag that gates it.

## Mitigations

To make the failure mode loud rather than silent for operators with strict DNS hosts:

1. **Boot-time self-check** (implemented as a follow-up to this ADR). After the apex cert is loaded, swe-swe-tunneld resolves a randomised label (`probe-{nanos}.{apex}`) via the system resolver. If the result includes the server's own external IP, the wildcard is permissive ✅. Otherwise it logs a `WARN` pointing the operator at this ADR and **boots anyway** — strict-DNS deployments may have wired per-session A records and that's their call.
2. **Documentation** — README links to this ADR and lists known-permissive providers (DNSimple) and known-strict providers (Cloudflare default, Route 53 default).
3. **Test coverage** — the e2e tests in `cmd/swe-swe-tunneld/e2e_test.go` use `httptest` URLs and don't exercise the live DNS path, so there's no test-suite regression risk from the wildcard quirk. Per-session A-record integration, if later added, would need its own provider-stub.

## DNS-provider compatibility (separate axis)

`dnsProviderFactory` in `cmd/swe-swe-tunneld/main.go` currently wires only `"dnsimple"`. Adding another provider for **ACME DNS-01** purposes is a 5-line `case` arm — lego supports dozens. The choice of ACME provider is **independent** of the wildcard-resolution decision recorded here: you can use Cloudflare for ACME DNS-01 even on a deployment whose authoritative DNS is permissive, and vice versa.

External contributions of additional `case` arms are explicitly welcome — see README §"Contributing a DNS provider".

---

## Recap

* If you operate `swe-swe-tunneld` on a domain whose authoritative DNS resolves multi-label names under a wildcard (DNSimple-style): you're good, default config works.
* If your DNS host is strict (one-label wildcard): you must either (a) switch to a permissive host, (b) add per-session A records via the integration point above, or (c) operate behind a permissive DNS rewriter you control.
* The boot self-check will tell you which camp you're in within seconds of starting the daemon.
