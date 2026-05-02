package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
	"github.com/choonkeat/swe-swe-tunnel/internal/portpolicy"
)

// TestMain disables the LE-issuance grace window by default for the whole
// package. The grace exists in production to give a human-typo'd unique
// time to be Ctrl-C'd before consuming an LE issuance slot, but it would
// add 5s of dead time to every Connect-based test that exercises a fresh
// unique. Tests that specifically exercise the grace-bail path opt back
// in by setting issuanceGrace to a non-zero duration (with a Cleanup to
// restore).
func TestMain(m *testing.M) {
	issuanceGrace = 0
	os.Exit(m.Run())
}

func writeKeyFile(t *testing.T, dir, name string, pub ed25519.PublicKey) {
	t.Helper()
	b64 := base64.RawStdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b64+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReloadAllowlistAndRevoke_HappyPathRevokesRemoved confirms a
// successful Reload drops live sessions whose pubkey was removed from the
// directory, and emits the expected log line.
func TestReloadAllowlistAndRevoke_HappyPathRevokesRemoved(t *testing.T) {
	dir := t.TempDir()
	pubKept, _, _ := ed25519.GenerateKey(rand.Reader)
	pubRevoked, _, _ := ed25519.GenerateKey(rand.Reader)
	writeKeyFile(t, dir, "kept.pub", pubKept)
	writeKeyFile(t, dir, "revoked.pub", pubRevoked)

	set, err := allowlist.Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	reg := newRegistry()
	tsKept := makeSession(t)
	tsRevoked := makeSession(t)
	if err := reg.add("kept-tunnel", pubKept, tsKept); err != nil {
		t.Fatal(err)
	}
	if err := reg.add("revoked-tunnel", pubRevoked, tsRevoked); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(dir, "revoked.pub")); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadAllowlistAndRevoke(set, reg, logger)

	if !waitClosed(tsRevoked, 100*time.Millisecond) {
		t.Error("revoked session was not closed after reload")
	}
	if isClosed(tsKept) {
		t.Error("kept session was closed but should have stayed live")
	}
	logs := buf.String()
	if !strings.Contains(logs, "allowlist reloaded") {
		t.Errorf("expected 'allowlist reloaded' log; got: %s", logs)
	}
	if !strings.Contains(logs, "removed=1") {
		t.Errorf("expected 'removed=1' in log; got: %s", logs)
	}
}

// TestReloadAllowlistAndRevoke_ParseErrorPreservesAndSkipsRevoke confirms
// the spec invariant: a malformed file at SIGHUP time keeps the prior
// in-memory set AND does NOT call RevokeMissing (policy didn't change →
// no revoke warranted).
func TestReloadAllowlistAndRevoke_ParseErrorPreservesAndSkipsRevoke(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	writeKeyFile(t, dir, "alice.pub", pub)

	set, err := allowlist.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	priorLen := set.Len()

	reg := newRegistry()
	ts := makeSession(t)
	if err := reg.add("alice-tunnel", pub, ts); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "broken.pub"),
		[]byte("not-base64!!!\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadAllowlistAndRevoke(set, reg, logger)

	time.Sleep(20 * time.Millisecond)
	if isClosed(ts) {
		t.Error("session was revoked despite reload error — policy should be unchanged")
	}
	if got := set.Len(); got != priorLen {
		t.Errorf("Set.Len = %d after failed reload, want preserved %d", got, priorLen)
	}
	logs := buf.String()
	if !strings.Contains(logs, "allowlist reload failed") {
		t.Errorf("expected 'allowlist reload failed' log; got: %s", logs)
	}
	if !strings.Contains(logs, "keeping_previous=true") {
		t.Errorf("expected 'keeping_previous=true' log; got: %s", logs)
	}
	if strings.Contains(logs, "session terminated: revoked") {
		t.Errorf("RevokeMissing log appeared after a failed reload; got: %s", logs)
	}
}

// TestReloadPortPolicy_FilePicksUpEdits drives the SIGHUP-handler
// helper for the port allowlist: edit the file, fire reloadPortPolicy,
// and assert (a) Permits flips on the new port and (b) the log line
// reports the change.
func TestReloadPortPolicy_FilePicksUpEdits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977"), 0o644); err != nil {
		t.Fatal(err)
	}
	ports, err := portpolicy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ports.Permits(8080) {
		t.Fatal("baseline: 8080 must not be permitted")
	}

	if err := os.WriteFile(path, []byte("1977,8080"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadPortPolicy(ports, logger)

	if !ports.Permits(8080) {
		t.Error("reloadPortPolicy: 8080 should be permitted after file edit")
	}
	logs := buf.String()
	if !strings.Contains(logs, "port allowlist reloaded") {
		t.Errorf("expected 'port allowlist reloaded' log; got: %s", logs)
	}
	if !strings.Contains(logs, "changed=true") {
		t.Errorf("expected 'changed=true' in log; got: %s", logs)
	}
}

// TestReloadPortPolicy_ParseErrorPreservesAndLogs verifies the spec
// invariant: a malformed file at SIGHUP keeps the prior policy live
// and logs keeping_previous=true. An operator who fat-fingers the
// file does not lose all their port routes mid-flight.
func TestReloadPortPolicy_ParseErrorPreservesAndLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977,8080"), 0o644); err != nil {
		t.Fatal(err)
	}
	ports, err := portpolicy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("garbage-not-a-port"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadPortPolicy(ports, logger)

	if !ports.Permits(1977) || !ports.Permits(8080) {
		t.Error("prior policy should be preserved after parse error")
	}
	logs := buf.String()
	if !strings.Contains(logs, "port allowlist reload failed") {
		t.Errorf("expected 'port allowlist reload failed' log; got: %s", logs)
	}
	if !strings.Contains(logs, "keeping_previous=true") {
		t.Errorf("expected 'keeping_previous=true' log; got: %s", logs)
	}
}

// TestReloadPortPolicy_InlineSourceIsSilent confirms reloadPortPolicy
// is a quiet no-op for the inline (flag/env/default) source — it
// neither logs nor errors. This avoids a spam log every SIGHUP for
// the common operator setup.
func TestReloadPortPolicy_InlineSourceIsSilent(t *testing.T) {
	ports, err := portpolicy.LoadInline("1977", "flag")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reloadPortPolicy(ports, logger)
	if buf.Len() != 0 {
		t.Errorf("inline reload should be silent; got log: %s", buf.String())
	}
}

// TestReloadPortPolicy_NilSafe: a nil *portpolicy.Set must not panic.
func TestReloadPortPolicy_NilSafe(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	reloadPortPolicy(nil, logger) // must not panic
}

// TestLoadPortPolicy_EmptyEnvIsNotSetSource: regression for a
// production miss where docker-compose's ${VAR:-} indirection sets
// SWE_TUNNEL_ALLOWED_PORTS to empty string when the operator hasn't
// configured anything. Empty spec parses to deny-all, which would
// silently break every tunnel after a deploy. We must treat empty
// env as "not set" -> default source is "default", and the spec is
// the compiled-in DefaultSpec (not "").
func TestLoadPortPolicy_EmptyEnvIsNotSetSource(t *testing.T) {
	t.Setenv("SWE_TUNNEL_ALLOWED_PORTS", "")
	ports, err := loadPortPolicy(portpolicy.DefaultSpec, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ports.Source(); got != "default" {
		t.Errorf("Source() = %q, want default (empty env should not count as 'set')", got)
	}
	if got := ports.Spec(); got != portpolicy.DefaultSpec {
		t.Errorf("Spec() = %q, want %q", got, portpolicy.DefaultSpec)
	}
	if !ports.Permits(9898) {
		t.Errorf("default policy must permit 9898 (the bug-triggering deny-all check)")
	}
}

// TestLoadPortPolicy_EnvWithValueIsRespected: the corollary --
// when env IS set to a real spec, source should be "env" and the
// inline value should be honored.
func TestLoadPortPolicy_EnvWithValueIsRespected(t *testing.T) {
	t.Setenv("SWE_TUNNEL_ALLOWED_PORTS", "9999")
	// Caller of loadPortPolicy is responsible for assigning env into
	// inline before calling, so simulate that by passing the env
	// value here.
	ports, err := loadPortPolicy("9999", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ports.Source(); got != "env" {
		t.Errorf("Source() = %q, want env", got)
	}
	if !ports.Permits(9999) || ports.Permits(9898) {
		t.Errorf("Spec=%q should permit 9999 and reject 9898", ports.Spec())
	}
}
