package cert

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// captureLogger returns a slog.Logger that writes to a bytes.Buffer at
// the given level (Info captures everything; Warn captures only Warn+).
func captureLogger(buf io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level}))
}

func TestProbeWildcard_Permissive_LogsInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)

	lookup := func(_ context.Context, host string) ([]string, error) {
		return []string{"203.0.113.7"}, nil
	}

	res := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if !res.Permissive {
		t.Errorf("Permissive = false, want true")
	}
	if !strings.HasSuffix(res.Probe, ".probe.example.com") {
		t.Errorf("Probe = %q, want it to end in .probe.example.com", res.Probe)
	}
	out := buf.String()
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "DNS multi-label wildcard verified") {
		t.Errorf("expected INFO log about verified wildcard, got: %s", out)
	}
	if !strings.Contains(out, "203.0.113.7") {
		t.Errorf("log should include the resolved address; got: %s", out)
	}
}

func TestProbeWildcard_StrictHost_LogsWarnWithADRPointer(t *testing.T) {
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)

	lookup := func(_ context.Context, host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	res := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if res.Permissive {
		t.Errorf("Permissive = true, want false on NXDOMAIN")
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected WARN log; got: %s", out)
	}
	if !strings.Contains(out, "strict-wildcard") {
		t.Errorf("WARN should call out strict-wildcard host; got: %s", out)
	}
	if !strings.Contains(out, "0001-dns-host-multi-label-wildcards.md") {
		t.Errorf("WARN should point to ADR-0001; got: %s", out)
	}
}

func TestProbeWildcard_NotFoundViaStringMatch(t *testing.T) {
	// Some resolver implementations (OS-specific stubs, mocks) return a
	// plain error whose message contains "no such host" but whose type is
	// not *net.DNSError. We still need to classify those as NotFound.
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)

	lookup := func(_ context.Context, host string) ([]string, error) {
		return nil, errors.New("lookup " + host + ": no such host")
	}

	res := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if res.Permissive {
		t.Errorf("Permissive = true, want false")
	}
	out := buf.String()
	if !strings.Contains(out, "strict-wildcard") {
		t.Errorf("string-matched 'no such host' should be classified as strict; got: %s", out)
	}
}

func TestProbeWildcard_TransientError_LogsWarnButDistinct(t *testing.T) {
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)

	lookup := func(_ context.Context, _ string) ([]string, error) {
		return nil, errors.New("server misbehaving")
	}

	res := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if res.Permissive {
		t.Errorf("Permissive = true, want false")
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("expected WARN log; got: %s", out)
	}
	if !strings.Contains(out, "transient or resolver issue") {
		t.Errorf("transient error should be logged distinctly from strict-wildcard; got: %s", out)
	}
	if strings.Contains(out, "strict-wildcard") {
		t.Errorf("transient error should NOT be classified as strict-wildcard; got: %s", out)
	}
}

func TestProbeWildcard_EmptyResultButNoError_LogsWarn(t *testing.T) {
	// nil error + empty addrs is rare but possible (some custom resolvers
	// return that for a synthetic NXDOMAIN). Treat as strict-equivalent.
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)

	lookup := func(_ context.Context, _ string) ([]string, error) {
		return []string{}, nil
	}

	res := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if res.Permissive {
		t.Errorf("Permissive = true with empty addrs")
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "no addresses") {
		t.Errorf("expected WARN about no addresses; got: %s", out)
	}
}

func TestProbeWildcard_ProbeNameRandomised(t *testing.T) {
	// Calling twice in a row should produce different probe names.
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)
	lookup := func(_ context.Context, _ string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}

	r1 := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	r2 := ProbeWildcard(context.Background(), "example.com", lookup, logger)
	if r1.Probe == r2.Probe {
		t.Errorf("probe name should be randomised; got %q twice", r1.Probe)
	}
	for _, p := range []string{r1.Probe, r2.Probe} {
		if !strings.HasSuffix(p, ".probe.example.com") {
			t.Errorf("probe %q should end in .probe.example.com", p)
		}
		labels := strings.Split(p, ".")
		// {hex}.probe.example.com → 4 labels
		if len(labels) != 4 {
			t.Errorf("probe %q has %d labels, want 4", p, len(labels))
		}
	}
}

func TestProbeWildcard_NilLookup_UsesDefault(t *testing.T) {
	// Passing nil for lookup should fall back to DefaultLookup. We don't
	// want to depend on real DNS in tests, so just confirm the call
	// doesn't panic and returns *some* result. A real-resolver call will
	// either succeed or NXDOMAIN; both are fine here — we're testing the
	// default-injection, not the network.
	var buf bytes.Buffer
	logger := captureLogger(&buf, slog.LevelInfo)
	res := ProbeWildcard(context.Background(), "example.invalid", nil, logger)
	if res.Probe == "" {
		t.Error("Probe should be set even with nil lookup")
	}
	// .invalid is reserved (RFC 2606) and must not resolve. Either we get
	// IsNotFound (most resolvers) or some transient error (CI quirks). In
	// neither case should we record Permissive=true.
	if res.Permissive {
		t.Errorf("example.invalid resolved permissively?? probe=%q addrs unexpected", res.Probe)
	}
}
