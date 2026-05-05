# Manual cert workflow (`--no-acme`)

Run `swe-swe-tunneld` against pre-provisioned certs and let an external
orchestrator (lego CLI, certbot, cert-manager, a CI job, ...) own
issuance. Useful when:

* The apex DNS is at a registrar with no lego-supported API.
* Cert issuance lives in a separate pipeline (cert-manager, a GitHub
  Action, a `certbot` cron) on a different host that holds the DNS API
  token; the cert files are pushed to a shared volume tunneld reads.
* The deployment is air-gapped or otherwise can't reach a public ACME
  endpoint.

## How tunneld behaves with `--no-acme`

* `cert.Manager` is not constructed. `--acme-email`, `--dns-provider`,
  `--dns-propagation-timeout`, `--dns-polling-interval`,
  `--acme-staging` are inert.
* `--ensure-cert` becomes a no-op with a one-line hint.
* On a Register for label `X` whose cert isn't on disk, the server
  replies `Deny{reason="cert not provisioned"}`. The client treats
  this as **permanent** — the supervisor exits instead of looping. Drop
  the cert, send `SIGHUP`, then reconnect.
* SIGHUP rescans `{state-dir}/lego/certificates/`. New files are added,
  existing entries are refreshed with the latest disk bytes. (SIGHUP
  also rescans in normal ACME mode — useful as a manual override
  during an ACME outage.)
* No background renewal. Your orchestrator owns that too.

## Required certs

For an apex of `example.com` and one client registered as
`alice-tunnel.example.com`, tunneld needs two cert pairs in
`{state-dir}/lego/certificates/`:

| File | SANs |
|---|---|
| `_.example.com.crt` + `.key` | `example.com`, `*.example.com` |
| `_.alice-tunnel.example.com.crt` + `.key` | `alice-tunnel.example.com`, `*.alice-tunnel.example.com` |

The `_.{fqdn}` filename convention is what the lego CLI produces by
default — it's the same layout `cert.Manager` writes to in ACME mode,
so you can flip an existing deployment to `--no-acme` without moving
files.

You need one per-session pair per active `unique`. Add a new pair
before the client registers (or fail-then-add-then-SIGHUP and let the
client reconnect).

## Recipe: lego CLI

`lego` understands DNS-01 against ~50 providers. Run it on a host that
has the DNS API token, then sync the resulting `certificates/` dir to
tunneld's `{state-dir}/lego/`.

```sh
# On the host that holds the DNS API token.
lego --email ops@example.com \
     --dns dnsimple \
     --domains example.com --domains '*.example.com' \
     --path /path/to/lego-out \
     run

lego --email ops@example.com \
     --dns dnsimple \
     --domains alice-tunnel.example.com --domains '*.alice-tunnel.example.com' \
     --path /path/to/lego-out \
     run

# Sync to tunneld's state dir.
rsync -a /path/to/lego-out/certificates/ tunneld-host:/var/lib/swe-swe-tunneld/lego/certificates/

# Tell tunneld to pick them up.
ssh tunneld-host 'pkill -HUP -f swe-swe-tunneld'
```

## Recipe: certbot

certbot writes to its own layout (`live/{domain}/fullchain.pem`,
`privkey.pem`). You need a tiny adapter step to rename into
`_.{fqdn}.{crt,key}`:

```sh
DOMAIN=alice-tunnel.example.com
certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.cf.ini \
        -d "$DOMAIN" -d "*.$DOMAIN" --non-interactive --agree-tos \
        -m ops@example.com

cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
   /var/lib/swe-swe-tunneld/lego/certificates/_.${DOMAIN}.crt
cp /etc/letsencrypt/live/$DOMAIN/privkey.pem \
   /var/lib/swe-swe-tunneld/lego/certificates/_.${DOMAIN}.key

pkill -HUP -f swe-swe-tunneld
```

Hook the rename + SIGHUP into certbot's `--deploy-hook` so renewals
publish themselves automatically.

## Recipe: cert-manager (Kubernetes)

Mount a `Secret` containing `tls.crt` + `tls.key` as
`{state-dir}/lego/certificates/_.{fqdn}.{crt,key}` (a small init or
sidecar that copies+renames is fine). Subscribe to `Secret` updates
and `kill -HUP 1` the tunneld process when the bytes change.

## Renewal

Re-issue with whatever cadence your orchestrator picks (lego/certbot
default to 30 days before expiry; cert-manager has a `renewBefore`
field). After overwriting the files on disk, send `SIGHUP`:

```sh
pkill -HUP -f swe-swe-tunneld
# or, in a container:
docker kill -s HUP swe-swe-tunneld
```

`LoadAllFromDisk` is idempotent — re-loading an unchanged file is
free. There's no required ordering between the file write and the
HUP, but a HUP arriving *before* the new files land just reloads the
old ones.

## Switching from ACME mode

Stop tunneld, restart with `--no-acme`. The on-disk layout is
unchanged, so the existing certs (originally issued by `cert.Manager`)
keep serving until they expire. Add your renewal job before that
window closes.

To go the other way (`--no-acme` → ACME), drop the flag and provide
`--acme-email` + a working DNS-01 provider. Existing on-disk certs
will be reused; expired ones will be re-issued via ACME.

## What you don't get

* No file-watcher. SIGHUP is the publish primitive on purpose —
  matches how the allowlist and the port-allowlist file work.
* No `--cert-dir` override. Use `--state-dir` to control the parent.
* No built-in CA / self-signed minting. Bring your own issuer.
* No pre-flight that walks the identity DB at boot and warns about
  missing certs. The first Register for an unprovisioned label
  surfaces the gap loudly enough.
