package version

import (
	"strings"
	"testing"
)

// TestString_NonEmpty covers the failure-mode contract: String() must
// never return the empty string. Either a real build identifier or the
// "unknown" sentinel — never "".
func TestString_NonEmpty(t *testing.T) {
	if String() == "" {
		t.Fatal("version.String() returned empty; expected real build info or 'unknown'")
	}
}

// TestString_LdflagInjection asserts that an -ldflags-set value wins
// over the VCS-derived path. Manipulating the package var directly
// from the test is the same operation -ldflags performs at link time.
func TestString_LdflagInjection(t *testing.T) {
	prev := version
	t.Cleanup(func() { version = prev })

	version = "v9.9.9"
	got := String()
	if got != "v9.9.9" {
		t.Errorf("String() = %q, want %q (ldflag override should win over VCS info)", got, "v9.9.9")
	}
}

// TestString_TrimsLdflagWhitespace covers a foot-gun: -ldflags often
// carries trailing whitespace from shell quoting. We don't want
// "  v1.2.3 " to differ from "v1.2.3".
func TestString_TrimsLdflagWhitespace(t *testing.T) {
	prev := version
	t.Cleanup(func() { version = prev })

	version = "  v1.2.3 \n"
	got := String()
	if got != "v1.2.3" {
		t.Errorf("String() = %q, want %q (whitespace must be trimmed)", got, "v1.2.3")
	}
}

// TestString_VCSPath sanity-checks the development-build path: when
// no ldflag is set, String() should produce something that *looks*
// like our VCS format. We can't pin exact bytes (the SHA changes per
// commit), but we can assert shape: contains a dash from yyyy-mm-dd
// or is the "unknown" sentinel (e.g. when running outside a git
// checkout, like some CI sandboxes).
func TestString_VCSPath(t *testing.T) {
	prev := version
	t.Cleanup(func() { version = prev })

	version = ""
	got := String()
	if got == "" {
		t.Fatal("empty version with no ldflag")
	}
	if got == "unknown" {
		t.Skip("running outside a git checkout (or VCS info stripped); shape check skipped")
	}
	if !strings.Contains(got, "-") && len(got) < 7 {
		t.Errorf("String() = %q, want a date-prefixed SHA (e.g. '2026-05-03 2ada7f0') or short SHA", got)
	}
}
