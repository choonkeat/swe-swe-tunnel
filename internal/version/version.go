// Package version exposes a single String() that the binaries print in
// their --help/--version output. The default path uses VCS info embedded
// by `go build`/`go install` (Go 1.18+), so a freshly-built binary
// reports the commit date + short SHA without any -ldflags plumbing. A
// tagged-release path remains available via -ldflags injection of
// `version` for the (eventual) day we cut versioned releases.
package version

import (
	"runtime/debug"
	"strings"
)

// version is overridable at build time:
//
//	go build -ldflags="-X github.com/choonkeat/swe-swe-tunnel/internal/version.version=v1.2.3"
//
// Left unset for development builds, in which case we fall back to the
// VCS info that the toolchain stamps into the binary automatically.
var version = ""

// String returns a human-readable build identifier for the running binary.
//
// Priority:
//  1. -ldflags-injected `version` (for tagged releases)
//  2. VCS info from debug.ReadBuildInfo: "<yyyy-mm-dd> <sha7>"
//  3. "unknown"
func String() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var (
		rev      string
		modified bool
		when     string
	)
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		case "vcs.time":
			// vcs.time is RFC3339 (e.g. "2026-05-03T07:38:34Z"); we
			// only want the calendar date for the human-facing label.
			if len(s.Value) >= 10 {
				when = s.Value[:10]
			}
		}
	}
	if rev == "" {
		return "unknown"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	out := rev
	if when != "" {
		out = when + " " + rev
	}
	if modified {
		out += "-dirty"
	}
	return out
}
