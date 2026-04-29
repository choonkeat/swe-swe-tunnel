package cert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"
)

// LookupFunc is the subset of net.Resolver.LookupHost the wildcard probe
// needs. Injectable so tests don't depend on real DNS.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// DefaultLookup is the production resolver. Wraps net.DefaultResolver.
func DefaultLookup(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// ProbeWildcardResult captures what ProbeWildcard observed. Useful for
// tests; in production only the side-effect log lines matter.
type ProbeWildcardResult struct {
	// Probe is the randomised name we resolved. Always 3 labels under apex
	// (matches the deepest browser-facing pattern: {port}.{label}.{apex}).
	Probe string

	// Permissive is true iff the lookup returned at least one A/AAAA address.
	// That's the property swe-swe-tunneld depends on. We do not check that
	// the IP matches the server's own — operators may legitimately point
	// `*.{apex}` at a load balancer or a different IP.
	Permissive bool

	// Err is the lookup error, if any. ENOTFOUND / NXDOMAIN-ish errors
	// indicate strict-wildcard behaviour and are handled distinctly from
	// transient errors.
	Err error
}

// ProbeWildcard resolves a randomised 3-label name under apex to check
// whether the apex's authoritative DNS supports multi-label wildcards
// (the property documented in docs/adr/0001-dns-host-multi-label-wildcards.md).
//
// Always logs the outcome; never blocks boot, never returns an error to
// the caller. The returned struct exists for tests.
func ProbeWildcard(ctx context.Context, apex string, lookup LookupFunc, logger *slog.Logger) ProbeWildcardResult {
	if logger == nil {
		logger = slog.Default()
	}
	if lookup == nil {
		lookup = DefaultLookup
	}

	// 3 labels: {randHex}.probe.{apex}. Two intermediate labels mirror the
	// deepest browser-facing shape ({port}.{label}-tunnel.{apex}); a
	// permissive wildcard host returns the apex A record for this name,
	// a strict host returns NXDOMAIN.
	var rb [4]byte
	_, _ = rand.Read(rb[:])
	probe := hex.EncodeToString(rb[:]) + ".probe." + apex

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := lookup(probeCtx, probe)
	res := ProbeWildcardResult{Probe: probe, Err: err, Permissive: err == nil && len(addrs) > 0}

	switch {
	case res.Permissive:
		logger.Info("DNS multi-label wildcard verified",
			"probe", probe,
			"resolved_to", addrs,
			"adr", "docs/adr/0001-dns-host-multi-label-wildcards.md")
	case isNotFoundErr(err):
		logger.Warn("DNS apex does not support multi-label wildcards — strict-wildcard host detected",
			"probe", probe,
			"hint", "either switch to a permissive DNS host (e.g. DNSimple) or wire per-session A records (see ADR-0001)",
			"adr", "docs/adr/0001-dns-host-multi-label-wildcards.md")
	case err != nil:
		logger.Warn("DNS wildcard probe failed (transient or resolver issue) — multi-label wildcard support unknown",
			"probe", probe,
			"err", err,
			"adr", "docs/adr/0001-dns-host-multi-label-wildcards.md")
	default:
		// err == nil but no addresses returned. Treat as strict-equivalent.
		logger.Warn("DNS wildcard probe returned no addresses — multi-label wildcards likely unsupported",
			"probe", probe,
			"adr", "docs/adr/0001-dns-host-multi-label-wildcards.md")
	}

	return res
}

// isNotFoundErr reports whether err is the canonical "no such host"
// outcome (NXDOMAIN-ish). net.DNSError carries IsNotFound on modern Go;
// for portability across resolver implementations we also string-match.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	return strings.Contains(err.Error(), "no such host")
}
