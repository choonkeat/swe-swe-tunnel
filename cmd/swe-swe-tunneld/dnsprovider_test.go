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

func TestDNSProviderFactory_UnknownNameErrors(t *testing.T) {
	_, err := dnsProviderFactory("acme-corp-megaprovider", time.Minute, time.Second)()
	if err == nil {
		t.Fatal("unknown provider name must return an error")
	}
}
