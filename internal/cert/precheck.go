package cert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// AuthoritativePreCheck wraps a challenge.Provider so that after the inner
// provider writes the DNS-01 TXT record, we don't return success until the
// apex's authoritative nameservers themselves serve the expected value.
//
// Why this exists: lego's default propagation check resolves through the
// recursive resolver lego is running on, which sees a cached/edge view of
// DNS. With DNSimple in particular, the API write returns 200 OK while the
// edge nameservers (ns3.dnsimple.com, ns4.dnsimple-edge.org, …) still serve
// the old data for tens of seconds to minutes. Lego's poll is happy long
// before the LE validator's poll succeeds — we tell LE "go validate", LE
// hits an authoritative NS that's still stale, validation fails, and
// every failed validation counts against LE's per-account "60 failures
// per hour" budget.
//
// Querying the authoritative NS directly closes that gap: we only return
// from Present when every authoritative NS for the apex returns the TXT
// we just wrote. After that lego's own poll will succeed on the first
// try, and the LE validator (which queries authoritative NS) will too.
//
// CleanUp is delegated unchanged. The wrapper does not implement Timeout,
// so the lego solver uses the inner provider's timeout if it defines one.
type AuthoritativePreCheck struct {
	Inner        challenge.Provider
	Apex         string
	WaitTimeout  time.Duration // total budget for the authoritative-NS poll
	WaitInterval time.Duration // poll interval inside the wait loop
	Logger       *slog.Logger

	// LookupNS resolves the apex's authoritative nameservers. Defaults
	// to net.LookupNS. Injectable so tests don't depend on real DNS.
	LookupNS func(apex string) ([]string, error)

	// LookupTXTAt resolves the FQDN's TXT records by sending the query
	// directly to the given nameserver (host or host:port — :53 is
	// implied). Defaults to a small UDP/TCP-via-Go-resolver helper.
	// Injectable for tests.
	LookupTXTAt func(ctx context.Context, ns, fqdn string) ([]string, error)
}

var _ challenge.Provider = (*AuthoritativePreCheck)(nil)
var _ challenge.ProviderTimeout = (*AuthoritativePreCheck)(nil)

// Present writes the TXT via the inner provider, then blocks until every
// authoritative NS for the apex serves the expected value, or the
// configured timeout elapses.
func (a *AuthoritativePreCheck) Present(domain, token, keyAuth string) error {
	if err := a.Inner.Present(domain, token, keyAuth); err != nil {
		return err
	}
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return a.waitAuthoritative(info.EffectiveFQDN, info.Value)
}

// CleanUp delegates to the inner provider.
func (a *AuthoritativePreCheck) CleanUp(domain, token, keyAuth string) error {
	return a.Inner.CleanUp(domain, token, keyAuth)
}

// Timeout reports the timeout/interval lego should use for its OWN
// propagation poll *after* our authoritative check completes. We
// delegate to the inner provider when it advertises a timeout (so an
// operator who tuned --dns-propagation-timeout still sees that value
// downstream); otherwise fall back to lego's defaults. Our own
// authoritative-poll timeout is separate (a.Timeout / a.Interval) and
// not exposed here — it's consumed inside Present.
func (a *AuthoritativePreCheck) Timeout() (time.Duration, time.Duration) {
	if pt, ok := a.Inner.(challenge.ProviderTimeout); ok {
		return pt.Timeout()
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

func (a *AuthoritativePreCheck) waitAuthoritative(fqdn, value string) error {
	logger := a.Logger
	if logger == nil {
		logger = slog.Default()
	}
	lookupNS := a.LookupNS
	if lookupNS == nil {
		lookupNS = defaultLookupNS
	}
	lookupTXTAt := a.LookupTXTAt
	if lookupTXTAt == nil {
		lookupTXTAt = defaultLookupTXTAt
	}
	timeout := a.WaitTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	interval := a.WaitInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}

	nss, err := lookupNS(a.Apex)
	if err != nil {
		return fmt.Errorf("authoritative pre-check: lookup NS for %q: %w", a.Apex, err)
	}
	if len(nss) == 0 {
		return fmt.Errorf("authoritative pre-check: no NS records for %q", a.Apex)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	queryFQDN := strings.TrimSuffix(fqdn, ".")

	// Poll each authoritative NS until it serves `value` (or until ctx
	// expires). Servers are checked sequentially; this is intentional —
	// DNSimple's edge replicates from a single source, so any one server
	// being slow tends to mean the others will be slow too. We log
	// per-server progress so operators can tell which NS is the laggard.
	for _, ns := range nss {
		if err := a.waitOneNS(ctx, lookupTXTAt, logger, ns, queryFQDN, value, interval); err != nil {
			return err
		}
	}
	return nil
}

func (a *AuthoritativePreCheck) waitOneNS(
	ctx context.Context,
	lookupTXTAt func(ctx context.Context, ns, fqdn string) ([]string, error),
	logger *slog.Logger,
	ns, fqdn, value string,
	interval time.Duration,
) error {
	attempt := 0
	for {
		attempt++
		txts, err := lookupTXTAt(ctx, ns, fqdn)
		if err == nil {
			for _, t := range txts {
				if t == value {
					logger.Info("authoritative TXT confirmed",
						"ns", ns, "fqdn", fqdn, "attempts", attempt)
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("authoritative pre-check: TXT %s not seen on %s within timeout (last attempt err=%v): %w",
				fqdn, ns, err, ctx.Err())
		case <-time.After(interval):
		}
	}
}

func defaultLookupNS(apex string) ([]string, error) {
	nss, err := net.LookupNS(apex)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		host := strings.TrimSuffix(ns.Host, ".")
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable NS records")
	}
	return out, nil
}

func defaultLookupTXTAt(ctx context.Context, ns, fqdn string) ([]string, error) {
	// Pin a Go-native resolver to the requested authoritative NS so the
	// query bypasses the local recursive resolver's cache.
	addr := ns
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	return resolver.LookupTXT(ctx, fqdn)
}
