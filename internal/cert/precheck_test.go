package cert

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// fakeProvider is a stub challenge.Provider that records its inputs and
// returns the configured presentErr. Optionally implements ProviderTimeout
// when timeout != 0.
type fakeProvider struct {
	mu          sync.Mutex
	presentErr  error
	cleanupErr  error
	presentArgs []presentCall
	cleanupArgs []presentCall

	timeout, interval time.Duration // implements ProviderTimeout iff timeout != 0
}

type presentCall struct {
	domain, token, keyAuth string
}

func (f *fakeProvider) Present(domain, token, keyAuth string) error {
	f.mu.Lock()
	f.presentArgs = append(f.presentArgs, presentCall{domain, token, keyAuth})
	err := f.presentErr
	f.mu.Unlock()
	return err
}

func (f *fakeProvider) CleanUp(domain, token, keyAuth string) error {
	f.mu.Lock()
	f.cleanupArgs = append(f.cleanupArgs, presentCall{domain, token, keyAuth})
	err := f.cleanupErr
	f.mu.Unlock()
	return err
}

// fakeProviderWithTimeout is a thin wrapper that adds a Timeout() method.
// We keep this separate (rather than putting it on fakeProvider) so we can
// test the inner-doesn't-implement-ProviderTimeout fallback path.
type fakeProviderWithTimeout struct {
	*fakeProvider
}

func (f *fakeProviderWithTimeout) Timeout() (time.Duration, time.Duration) {
	return f.timeout, f.interval
}

// stubLookups builds the LookupNS / LookupTXTAt closures that the tests
// drive. nss is the static NS list; txtPlan[ns] is a sequence of TXT
// responses to return for that NS, advancing one per call.
type stubLookups struct {
	nss      []string
	nssErr   error
	txtPlan  map[string][][]string // ns → ordered TXT responses
	txtErr   map[string][]error    // ns → ordered errors (nil = no error)
	mu       sync.Mutex
	calls    map[string]int       // ns → calls made so far
	allCalls []txtCall
}

type txtCall struct {
	ns, fqdn string
}

func newStubLookups(nss []string) *stubLookups {
	return &stubLookups{
		nss:     nss,
		txtPlan: map[string][][]string{},
		txtErr:  map[string][]error{},
		calls:   map[string]int{},
	}
}

func (s *stubLookups) lookupNS(_ string) ([]string, error) {
	if s.nssErr != nil {
		return nil, s.nssErr
	}
	return append([]string(nil), s.nss...), nil
}

func (s *stubLookups) lookupTXT(_ context.Context, ns, fqdn string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.calls[ns]
	s.calls[ns] = idx + 1
	s.allCalls = append(s.allCalls, txtCall{ns, fqdn})

	var ts []string
	if plan, ok := s.txtPlan[ns]; ok {
		if idx < len(plan) {
			ts = plan[idx]
		} else {
			ts = plan[len(plan)-1] // sticky last
		}
	}
	var err error
	if errs, ok := s.txtErr[ns]; ok {
		if idx < len(errs) {
			err = errs[idx]
		} else {
			err = errs[len(errs)-1]
		}
	}
	return ts, err
}

func (s *stubLookups) callCount(ns string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[ns]
}

// --------------------------------------------------------------------------
// Present
// --------------------------------------------------------------------------

// Present must call inner.Present, then poll until every authoritative NS
// returns the expected TXT value. We simulate a real-world DNSimple flake
// where ns3 serves the right value immediately but ns4 is slow — Present
// should not return until both have caught up.
func TestAuthoritativePreCheck_Present_WaitsForAllNSToServeValue(t *testing.T) {
	const domain = "swe-swe-manual-tunnel.example.com"
	const keyAuth = "kx-1"
	value := expectedValue(domain, keyAuth)

	inner := &fakeProvider{}
	stub := newStubLookups([]string{"ns3.dnsimple.com", "ns4.dnsimple-edge.org"})
	// ns3 serves the right value immediately.
	stub.txtPlan["ns3.dnsimple.com"] = [][]string{{value}}
	// ns4 returns wrong/empty TXT for the first 3 polls, then the right value.
	stub.txtPlan["ns4.dnsimple-edge.org"] = [][]string{
		{},                  // not yet
		{"old-stale-value"}, // still stale
		{},                  // still not
		{value},             // finally!
	}

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  2 * time.Second,
		WaitInterval: 5 * time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}

	if err := pc.Present(domain, "tok", keyAuth); err != nil {
		t.Fatalf("Present: %v", err)
	}
	// Inner.Present must have been called exactly once.
	if got := len(inner.presentArgs); got != 1 {
		t.Errorf("inner.Present calls = %d, want 1", got)
	}
	// ns3 confirmed on first poll.
	if got := stub.callCount("ns3.dnsimple.com"); got != 1 {
		t.Errorf("ns3 polls = %d, want 1 (confirmed on first try)", got)
	}
	// ns4 took 4 polls (3 stale + 1 success).
	if got := stub.callCount("ns4.dnsimple-edge.org"); got != 4 {
		t.Errorf("ns4 polls = %d, want 4 (3 stale + 1 success)", got)
	}
}

// If inner.Present errors, the wrapper must return that error WITHOUT
// running any DNS lookups — there's no TXT to wait for.
func TestAuthoritativePreCheck_Present_InnerErrorShortCircuits(t *testing.T) {
	innerErr := errors.New("DNSimple API down")
	inner := &fakeProvider{presentErr: innerErr}
	stub := newStubLookups([]string{"ns1"})

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  100 * time.Millisecond,
		WaitInterval: time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}
	err := pc.Present("any.example.com", "tok", "auth")
	if !errors.Is(err, innerErr) {
		t.Errorf("err = %v, want chain to %v", err, innerErr)
	}
	if got := stub.callCount("ns1"); got != 0 {
		t.Errorf("LookupTXTAt should not run when inner Present fails; got %d calls", got)
	}
}

// When the wait budget elapses with at least one NS still serving the
// wrong value, Present must surface a clear error (so the caller knows
// to retry rather than silently hand a half-baked challenge to LE).
func TestAuthoritativePreCheck_Present_TimeoutErrors(t *testing.T) {
	inner := &fakeProvider{}
	stub := newStubLookups([]string{"ns-stuck"})
	stub.txtPlan["ns-stuck"] = [][]string{{"never-the-right-value"}}

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  50 * time.Millisecond,
		WaitInterval: 5 * time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}
	err := pc.Present("any.example.com", "tok", "kx-2")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err chain should include context.DeadlineExceeded, got: %v", err)
	}
}

// LookupNS errors propagate — without an NS list we can't know which
// servers to poll.
func TestAuthoritativePreCheck_Present_NSLookupErrorPropagates(t *testing.T) {
	nsErr := errors.New("apex has no NS records")
	inner := &fakeProvider{}
	stub := newStubLookups(nil)
	stub.nssErr = nsErr

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  time.Second,
		WaitInterval: time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}
	err := pc.Present("any.example.com", "tok", "auth")
	if !errors.Is(err, nsErr) {
		t.Errorf("err = %v, want chain to %v", err, nsErr)
	}
}

// An empty NS list (lookup succeeded but found nothing) is still a fatal
// configuration problem — don't silently succeed.
func TestAuthoritativePreCheck_Present_EmptyNSListErrors(t *testing.T) {
	pc := &AuthoritativePreCheck{
		Inner:        &fakeProvider{},
		Apex:         "example.com",
		WaitTimeout:  time.Second,
		WaitInterval: time.Millisecond,
		LookupNS:     func(string) ([]string, error) { return nil, nil },
		LookupTXTAt:  func(context.Context, string, string) ([]string, error) { return nil, nil },
	}
	if err := pc.Present("any.example.com", "tok", "auth"); err == nil {
		t.Error("empty NS list must produce an error, got nil")
	}
}

// Transient lookup errors (e.g. UDP packet loss) must be retried, not
// fatal, as long as the wait budget allows. We model 2 errors followed
// by a successful lookup.
func TestAuthoritativePreCheck_Present_TransientLookupErrorsRetried(t *testing.T) {
	const domain = "any.example.com"
	const keyAuth = "kx-3"
	value := expectedValue(domain, keyAuth)

	inner := &fakeProvider{}
	stub := newStubLookups([]string{"ns1"})
	stub.txtPlan["ns1"] = [][]string{{}, {}, {value}}
	stub.txtErr["ns1"] = []error{
		errors.New("udp timeout"),
		errors.New("udp timeout"),
		nil,
	}

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  500 * time.Millisecond,
		WaitInterval: 2 * time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}
	if err := pc.Present(domain, "tok", keyAuth); err != nil {
		t.Fatalf("transient errors should be retried, got: %v", err)
	}
	if got := stub.callCount("ns1"); got != 3 {
		t.Errorf("ns1 calls = %d, want 3 (2 errors + 1 success)", got)
	}
}

// --------------------------------------------------------------------------
// CleanUp / Timeout
// --------------------------------------------------------------------------

func TestAuthoritativePreCheck_CleanUp_DelegatesToInner(t *testing.T) {
	inner := &fakeProvider{}
	pc := &AuthoritativePreCheck{Inner: inner, Apex: "example.com"}
	if err := pc.CleanUp("d", "t", "k"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if got := len(inner.cleanupArgs); got != 1 {
		t.Fatalf("inner.CleanUp calls = %d, want 1", got)
	}
	if c := inner.cleanupArgs[0]; c.domain != "d" || c.token != "t" || c.keyAuth != "k" {
		t.Errorf("CleanUp args = %+v, want {d,t,k}", c)
	}
}

func TestAuthoritativePreCheck_CleanUp_PropagatesError(t *testing.T) {
	want := errors.New("DNSimple delete failed")
	inner := &fakeProvider{cleanupErr: want}
	pc := &AuthoritativePreCheck{Inner: inner, Apex: "example.com"}
	if err := pc.CleanUp("d", "t", "k"); !errors.Is(err, want) {
		t.Errorf("CleanUp err = %v, want %v", err, want)
	}
}

// Timeout delegates to inner if inner implements ProviderTimeout. This is
// what lets the lego solver still benefit from --dns-propagation-timeout
// after our authoritative pre-check completes.
func TestAuthoritativePreCheck_Timeout_DelegatesWhenInnerImplements(t *testing.T) {
	innerCore := &fakeProvider{timeout: 7 * time.Minute, interval: 13 * time.Second}
	inner := &fakeProviderWithTimeout{fakeProvider: innerCore}
	pc := &AuthoritativePreCheck{Inner: inner, Apex: "example.com"}
	gotT, gotI := pc.Timeout()
	if gotT != 7*time.Minute || gotI != 13*time.Second {
		t.Errorf("Timeout() = (%v, %v), want delegated (7m, 13s)", gotT, gotI)
	}
}

// When inner doesn't implement ProviderTimeout, fall back to lego defaults.
// We assert non-zero rather than pinning the exact constant so that an
// upstream tweak doesn't break us.
func TestAuthoritativePreCheck_Timeout_FallsBackToDefaults(t *testing.T) {
	pc := &AuthoritativePreCheck{Inner: &fakeProvider{}, Apex: "example.com"}
	gotT, gotI := pc.Timeout()
	if gotT == 0 || gotI == 0 {
		t.Errorf("Timeout() = (%v, %v); want non-zero defaults when inner has no Timeout()", gotT, gotI)
	}
}

// --------------------------------------------------------------------------
// Concurrency sanity
// --------------------------------------------------------------------------

// Two concurrent Present calls (e.g. the apex cert and a per-session cert
// being issued at the same time) must not race on the wrapper.
func TestAuthoritativePreCheck_Present_ConcurrentCallsAreSafe(t *testing.T) {
	const callers = 8
	const keyAuth = "shared-key-auth" // info.Value depends only on keyAuth, not domain
	value := expectedValue("any.example.com", keyAuth)

	inner := &fakeProvider{}
	stub := newStubLookups([]string{"ns1"})
	stub.txtPlan["ns1"] = [][]string{{value}}

	pc := &AuthoritativePreCheck{
		Inner:        inner,
		Apex:         "example.com",
		WaitTimeout:  time.Second,
		WaitInterval: time.Millisecond,
		LookupNS:     stub.lookupNS,
		LookupTXTAt:  stub.lookupTXT,
	}

	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < callers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			domain := fmt.Sprintf("d%d.example.com", i)
			if err := pc.Present(domain, "tok", keyAuth); err != nil {
				failures.Add(1)
				t.Errorf("caller %d Present: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Errorf("%d concurrent Present calls failed", failures.Load())
	}
	if got := len(inner.presentArgs); got != callers {
		t.Errorf("inner.Present calls = %d, want %d", got, callers)
	}
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// expectedValue returns the TXT value that lego would compute for the
// given (domain, keyAuth) pair. We use this in tests so the stub's TXT
// plan uses the same literal value the wrapper is comparing against.
func expectedValue(domain, keyAuth string) string {
	return dns01.GetChallengeInfo(domain, keyAuth).Value
}
