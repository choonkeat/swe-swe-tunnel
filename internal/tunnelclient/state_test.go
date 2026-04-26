package tunnelclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeSession builds a Session with just the fields WriteState reads.
// The yamux/conn fields stay nil — WriteState must not touch them.
func fakeSession(hostname, unique string, registered time.Time) *Session {
	return &Session{
		hostname:     hostname,
		unique:       unique,
		registeredAt: registered,
	}
}

func TestWriteState_HappyPath_ShapeAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel-state.json")
	registered := time.Date(2026, 4, 27, 10, 30, 0, 0, time.UTC)

	if err := WriteState(path, fakeSession("alpha-tunnel.example.com", "alpha", registered)); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("file mode = %o, want 0600", mode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Decode generically so we can verify the *exact* JSON keys, not just
	// that something parses into our struct (a typo'd json tag would still
	// round-trip via the typed struct).
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantKeys := map[string]string{
		"hostname":      "alpha-tunnel.example.com",
		"unique":        "alpha",
		"registered_at": "2026-04-27T10:30:00Z",
	}
	if len(generic) != len(wantKeys) {
		t.Errorf("keys = %v, want exactly %v", keysOf(generic), keysOf(wantKeys))
	}
	for k, want := range wantKeys {
		got, ok := generic[k]
		if !ok {
			t.Errorf("missing key %q (got keys: %v)", k, keysOf(generic))
			continue
		}
		if got != want {
			t.Errorf("%s = %v, want %q", k, got, want)
		}
	}
}

func TestWriteState_RFC3339_NoNanoseconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// Sub-second precision must be dropped (RFC3339, not RFC3339Nano).
	registered := time.Date(2026, 4, 27, 10, 30, 0, 123456789, time.UTC)

	if err := WriteState(path, fakeSession("h", "u", registered)); err != nil {
		t.Fatal(err)
	}
	var got State
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	rfc3339 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$`)
	if !rfc3339.MatchString(got.RegisteredAt) {
		t.Errorf("registered_at = %q, want RFC3339 with no fractional seconds", got.RegisteredAt)
	}
	// Parse back and check it round-trips to the second.
	parsed, err := time.Parse(time.RFC3339, got.RegisteredAt)
	if err != nil {
		t.Fatalf("RFC3339 parse: %v", err)
	}
	if !parsed.Equal(registered.Truncate(time.Second)) {
		t.Errorf("round-trip: got %v, want %v", parsed, registered.Truncate(time.Second))
	}
}

func TestWriteState_LocalTime_ConvertedToUTC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// Non-UTC zone — must be converted to UTC and serialised with `Z`.
	tz := time.FixedZone("UTC+8", 8*3600)
	registered := time.Date(2026, 4, 27, 18, 30, 0, 0, tz)

	if err := WriteState(path, fakeSession("h", "u", registered)); err != nil {
		t.Fatal(err)
	}
	var got State
	raw, _ := os.ReadFile(path)
	_ = json.Unmarshal(raw, &got)
	if !strings.HasSuffix(got.RegisteredAt, "Z") {
		t.Errorf("registered_at = %q, want UTC suffix Z", got.RegisteredAt)
	}
	if got.RegisteredAt != "2026-04-27T10:30:00Z" {
		t.Errorf("registered_at = %q, want %q", got.RegisteredAt, "2026-04-27T10:30:00Z")
	}
}

func TestWriteState_CreatesParentDir(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "two", "three", "tunnel-state.json")

	if err := WriteState(path, fakeSession("h", "u", time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
	// Parent should exist with restrictive mode.
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("parent dir stat: %v", err)
	}
	if !parent.IsDir() {
		t.Errorf("parent should be a directory")
	}
}

func TestWriteState_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := WriteState(path, fakeSession("first-tunnel", "first", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(path, fakeSession("second-tunnel", "second", time.Now())); err != nil {
		t.Fatal(err)
	}
	var got State
	raw, _ := os.ReadFile(path)
	_ = json.Unmarshal(raw, &got)
	if got.Hostname != "second-tunnel" || got.Unique != "second" {
		t.Errorf("after overwrite: got %+v, want hostname=second-tunnel, unique=second", got)
	}
}

func TestWriteState_NoTempfileLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	for i := 0; i < 5; i++ {
		if err := WriteState(path, fakeSession("h", "u", time.Now())); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(path) {
			continue
		}
		t.Errorf("unexpected file in state dir after writes: %q (tempfile leak?)", e.Name())
	}
}

func TestWriteState_AtomicRename_VisiblePathHoldsCompleteJSON(t *testing.T) {
	// This guards against a regression where a half-written tempfile gets
	// renamed (or where we accidentally truncate-and-write in place). After
	// each WriteState call the visible path must contain a fully-formed,
	// parseable JSON document with all three required keys.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	for i := 0; i < 10; i++ {
		if err := WriteState(path, fakeSession("h", "u", time.Now())); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("decode %d (%q): %v", i, string(raw), err)
		}
		for _, k := range []string{"hostname", "unique", "registered_at"} {
			if _, ok := got[k]; !ok {
				t.Errorf("write %d: missing key %q", i, k)
			}
		}
	}
}

func TestWriteState_NilSession(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	err := WriteState(path, nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("file should not exist after nil-session write, stat err = %v", statErr)
	}
}

func TestWriteState_EmptyPath(t *testing.T) {
	if err := WriteState("", fakeSession("h", "u", time.Now())); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestWriteState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	registered := time.Date(2026, 4, 27, 10, 30, 0, 0, time.UTC)

	if err := WriteState(path, fakeSession("alpha-tunnel.example.com", "alpha", registered)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got State
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := State{
		Hostname:     "alpha-tunnel.example.com",
		Unique:       "alpha",
		RegisteredAt: "2026-04-27T10:30:00Z",
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
