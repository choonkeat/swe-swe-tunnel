# ACME DNS-01 providers

Cert issuance uses [lego](https://github.com/go-acme/lego)'s DNS-01 challenge. swe-swe-tunneld currently wires:

| `--dns-provider` | Required env | Notes |
|---|---|---|
| `dnsimple` | `DNSIMPLE_OAUTH_TOKEN` | Default. |

## Adding a provider

Adding another provider that lego supports is a 5-line change in `cmd/swe-swe-tunneld/main.go` `dnsProviderFactory`:

```go
case "cloudflare":
    return func() (challenge.Provider, error) { return cloudflare.NewDNSProvider() }
```

…plus an import. **PRs adding additional `case` arms are explicitly welcome.** Each should:

1. Add the `case` arm.
2. Add the corresponding env-var documentation row to the table above.
3. If the provider is well-known to be strict-wildcard, note that in [`docs/dns-hosts.md`](dns-hosts.md).

## Independence from apex DNS host

The choice of ACME DNS-01 provider is **independent** of the apex DNS host's wildcard semantics. You can use Cloudflare for ACME on a DNSimple-hosted apex, or vice versa — they're orthogonal axes.
