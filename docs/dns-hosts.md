# DNS host requirements

**Read this before deploying to a non-DNSimple apex.** swe-swe-tunneld depends on permissive multi-label wildcard DNS resolution, and not every DNS host implements that. Full design rationale lives in [ADR-0001](adr/0001-dns-host-multi-label-wildcards.md).

## The pattern

The public hostname pattern is **3 labels deep** under the apex: `{port}.{unique}-tunnel.{apex}`. For browsers to reach the tunnel server, the apex's authoritative DNS must resolve every such name to the server's IP using a single wildcard A record:

```
*.example.com  →  <server IP>
```

This works on DNS hosts that match wildcards across **multiple** labels (DNSimple does this — `1977.alice-tunnel.example.com` resolves via `*.example.com`). It does **not** work out of the box on DNS hosts that strictly enforce one-level wildcards per RFC 1034 §4.3.3 (Cloudflare default, AWS Route 53 default, …).

## Provider matrix

| DNS host | Multi-label wildcard? | Default config works? |
|---|---|---|
| DNSimple | yes | ✅ |
| Cloudflare | no (strict) | ❌ — see ADR-0001 for options |
| AWS Route 53 | no (strict) | ❌ — see ADR-0001 |
| Hetzner DNS | no (strict) | ❌ |
| Gandi LiveDNS | mixed | check before deploying |

(Have first-hand info on a provider not listed? PRs welcome to update this table.)

## Boot self-check

The boot self-check (`internal/cert`) probes a randomised label at startup and logs a `WARN` if the apex doesn't resolve permissively — the daemon still boots, but the operator sees the misconfiguration immediately rather than from a confused user later.

## See also

For why we chose this over per-session DNS-API record creation, what the integration point looks like for strict-mode hosts, and the boundary with ACME DNS-01: [ADR-0001](adr/0001-dns-host-multi-label-wildcards.md).

The choice of **ACME DNS-01 provider** is independent of the apex DNS host's wildcard semantics. You can use Cloudflare for ACME on a DNSimple-hosted apex, or vice versa — they're orthogonal axes. See [`docs/acme-providers.md`](acme-providers.md).
