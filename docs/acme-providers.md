# ACME DNS-01 providers

Cert issuance uses [lego](https://github.com/go-acme/lego)'s DNS-01 challenge. swe-swe-tunneld currently wires:

| `--dns-provider` | Required env | Notes |
|---|---|---|
| `dnsimple` | `DNSIMPLE_OAUTH_TOKEN` | Default. |
| `route53` | AWS SDK default credential chain (env `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_REGION`, or shared credentials file, or EC2 IMDS / ECS task role / EKS IRSA). `AWS_HOSTED_ZONE_ID` is optional — set it to skip the `ListHostedZonesByName` lookup. | IAM principal needs `route53:ChangeResourceRecordSets` + `route53:GetChange` on the zone, and `route53:ListHostedZonesByName` if `AWS_HOSTED_ZONE_ID` is not set. |

## AWS Route 53

When `swe-swe-tunneld` runs on AWS compute (Lightsail, EC2, ECS/Fargate, EKS), attach an instance / task role with the IAM permissions above and **set no static AWS keys**. The lego provider goes through the AWS SDK default credential chain, which picks up IMDSv2 / task-role / IRSA creds automatically — `--dns-provider=route53` is the only flag you need.

DNS-01 only requires write access to the **apex zone** (to create `_acme-challenge.{apex}` TXT records). Your apex A/wildcard records can live anywhere; the cert pipeline is independent of where the user-facing wildcard points. See [`docs/dns-hosts.md`](dns-hosts.md) for the apex-resolution requirement (Route 53 is **strict** on multi-label wildcards, so you'll either need separate A records per `*.{unique}-tunnel.{apex}` or an apex on a permissive host — that's an apex-resolution question, not an ACME question).

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
