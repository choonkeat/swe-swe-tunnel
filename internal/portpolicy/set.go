package portpolicy

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// Set is a hot-swappable wrapper around a *PortPolicy. Permits is
// lock-free (a single atomic.Pointer load), so reads from the request
// path do not contend with reload. Reload re-reads the configured
// source (file path) and atomically swaps the live policy on success;
// on parse error the previous policy is preserved so a fat-fingered
// edit doesn't reduce the allowlist mid-flight.
//
// Source distinguishes how the policy got loaded — emitted in boot
// logs and SIGHUP-reload logs so an operator can tell at a glance
// which knob is in effect:
//
//	source=default   (compiled-in DefaultSpec, no flag/env/file)
//	source=flag      (--allowed-ports=...)
//	source=env       (SWE_TUNNEL_ALLOWED_PORTS)
//	source=file:/p   (--allowed-ports-file=/p; supports SIGHUP reload)
type Set struct {
	policy atomic.Pointer[PortPolicy]
	source string
	spec   atomic.Pointer[string]

	// file is non-empty iff this Set was loaded from a file. Reload
	// is a no-op for the other sources (inline values can't change
	// without a restart).
	file string
}

// LoadInline builds a Set from an inline spec (flag value, env var,
// or compiled-in default). Reload on the result is a no-op, since
// flag/env values are fixed at process start.
func LoadInline(spec, source string) (*Set, error) {
	p, err := Parse(spec)
	if err != nil {
		return nil, err
	}
	s := &Set{source: source}
	s.policy.Store(p)
	stored := strings.TrimSpace(spec)
	s.spec.Store(&stored)
	return s, nil
}

// LoadFile builds a Set by reading path. SIGHUP reload re-reads the
// same path and swaps the live policy if parsing succeeds.
func LoadFile(path string) (*Set, error) {
	spec, err := readFileSpec(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s := &Set{file: path, source: "file:" + path}
	s.policy.Store(p)
	s.spec.Store(&spec)
	return s, nil
}

// Permits reports whether port may be forwarded under the currently
// loaded policy. Lock-free.
func (s *Set) Permits(port int) bool {
	if s == nil {
		return false
	}
	return s.policy.Load().Permits(port)
}

// Spec returns the spec string currently in effect (the same one a
// SIGHUP reload would compare against).
func (s *Set) Spec() string {
	if s == nil {
		return ""
	}
	if p := s.spec.Load(); p != nil {
		return *p
	}
	return ""
}

// Source returns the human-readable origin label set at construction.
func (s *Set) Source() string {
	if s == nil {
		return ""
	}
	return s.source
}

// File returns the configured file path, or "" if this Set is
// inline-sourced.
func (s *Set) File() string {
	if s == nil {
		return ""
	}
	return s.file
}

// Reload re-reads the source (if file-backed) and atomically swaps
// the live policy on success. On parse error the previous policy is
// preserved and the error is returned for the caller to log.
//
// Returns changed=true iff the new spec differs from the prior one.
// For inline-sourced sets, Reload is a no-op (returns changed=false,
// nil).
func (s *Set) Reload() (changed bool, err error) {
	if s == nil {
		return false, nil
	}
	if s.file == "" {
		return false, nil
	}
	spec, err := readFileSpec(s.file)
	if err != nil {
		return false, err
	}
	p, err := Parse(spec)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", s.file, err)
	}
	prevSpec := s.Spec()
	s.policy.Store(p)
	s.spec.Store(&spec)
	return spec != prevSpec, nil
}

func readFileSpec(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	// Tolerate either a single-line spec or a multi-line file with
	// blank lines and `#` comments. Strip both, join with commas.
	var parts []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, ","), nil
}
