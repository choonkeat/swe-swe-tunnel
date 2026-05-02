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
)

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
