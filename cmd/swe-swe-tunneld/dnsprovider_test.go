package main

import (
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
)

// dnsProviderFactory must let operators override lego's lego-default
// PropagationTimeout/PollingInterval — the defaults (60s/2s) are too tight
// for DNSimple's edge nameservers, which is what tipped us into the cert
// flake on /run-production. The provider implements challenge.ProviderTimeout,
// so the override is observable through the Timeout() method.
func TestDNSProviderFactory_DNSimple_HonorsTimeoutOverride(t *testing.T) {
	t.Setenv("DNSIMPLE_OAUTH_TOKEN", "test-token-not-real")

	want := struct {
		timeout, interval time.Duration
	}{7 * time.Minute, 11 * time.Second}

	factory := dnsProviderFactory("dnsimple", want.timeout, want.interval)
	prov, err := factory()
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	pt, ok := prov.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("dnsimple provider must implement challenge.ProviderTimeout")
	}
	gotT, gotI := pt.Timeout()
	if gotT != want.timeout || gotI != want.interval {
		t.Errorf("Timeout() = (%v, %v), want (%v, %v)", gotT, gotI, want.timeout, want.interval)
	}
}

// Zero values fall back to lego defaults. We assert non-zero return rather
// than pinning the exact lego-default constant so the test doesn't break
// if upstream tunes its defaults — what matters is that we don't smuggle
// a 0 into the provider and freeze the polling loop forever.
func TestDNSProviderFactory_DNSimple_ZeroFallsBackToLegoDefaults(t *testing.T) {
	t.Setenv("DNSIMPLE_OAUTH_TOKEN", "test-token-not-real")

	prov, err := dnsProviderFactory("dnsimple", 0, 0)()
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	pt, ok := prov.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("dnsimple provider must implement challenge.ProviderTimeout")
	}
	gotT, gotI := pt.Timeout()
	if gotT == 0 || gotI == 0 {
		t.Errorf("zero override should fall back to lego defaults, got (%v, %v)", gotT, gotI)
	}
}

// Route53 uses the AWS SDK default credential chain (env → shared file →
// IMDS), so unit tests can construct a provider without any static creds:
// LoadDefaultConfig defers credential resolution to API-call time, and
// our factory only assembles config. We assert the lego override knobs
// land on the constructed provider — same contract as DNSimple, since
// stretched PropagationTimeout / PollingInterval are the reason we
// route config through this factory at all.
func TestDNSProviderFactory_Route53_HonorsTimeoutOverride(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")

	want := struct {
		timeout, interval time.Duration
	}{9 * time.Minute, 13 * time.Second}

	factory := dnsProviderFactory("route53", want.timeout, want.interval)
	prov, err := factory()
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	pt, ok := prov.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("route53 provider must implement challenge.ProviderTimeout")
	}
	gotT, gotI := pt.Timeout()
	if gotT != want.timeout || gotI != want.interval {
		t.Errorf("Timeout() = (%v, %v), want (%v, %v)", gotT, gotI, want.timeout, want.interval)
	}
}

func TestDNSProviderFactory_Route53_ZeroFallsBackToLegoDefaults(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")

	prov, err := dnsProviderFactory("route53", 0, 0)()
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	pt, ok := prov.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("route53 provider must implement challenge.ProviderTimeout")
	}
	gotT, gotI := pt.Timeout()
	if gotT == 0 || gotI == 0 {
		t.Errorf("zero override should fall back to lego defaults, got (%v, %v)", gotT, gotI)
	}
}

func TestDNSProviderFactory_UnknownNameErrors(t *testing.T) {
	_, err := dnsProviderFactory("acme-corp-megaprovider", time.Minute, time.Second)()
	if err == nil {
		t.Fatal("unknown provider name must return an error")
	}
}
