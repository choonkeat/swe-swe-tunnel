package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
)

// makeSession returns a real *tunnelSession whose underlying yamux.Session
// is server-side of a net.Pipe pair. The client end is closed via
// t.Cleanup so the goroutine yamux spawns doesn't leak.
func makeSession(t *testing.T) *tunnelSession {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	// Yamux client is needed only so the server side completes its
	// handshake. We don't actually use the client object after.
	cli, err := yamux.Client(a, nil)
	if err != nil {
		t.Fatalf("yamux client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	srv, err := yamux.Server(b, nil)
	if err != nil {
		t.Fatalf("yamux server: %v", err)
	}
	return &tunnelSession{sess: srv}
}

// allowlistDirWith writes one file per pubkey into a fresh temp dir and
// returns a loaded *allowlist.Set rooted there.
func allowlistDirWith(t *testing.T, pubs ...ed25519.PublicKey) *allowlist.Set {
	t.Helper()
	dir := t.TempDir()
	for i, pub := range pubs {
		b64 := base64.RawStdEncoding.EncodeToString(pub)
		name := filepath.Join(dir, "k"+string(rune('a'+i))+".pub")
		if err := os.WriteFile(name, []byte(b64+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := allowlist.Load(dir)
	if err != nil {
		t.Fatalf("allowlist.Load: %v", err)
	}
	return set
}

func TestRegistry_AddRemovePubkeyIndex(t *testing.T) {
	reg := newRegistry()
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)

	tsA1 := makeSession(t)
	tsA2 := makeSession(t)
	tsB := makeSession(t)

	if err := reg.add("a1-tunnel", pubA, tsA1); err != nil {
		t.Fatalf("add a1: %v", err)
	}
	if err := reg.add("a2-tunnel", pubA, tsA2); err != nil {
		t.Fatalf("add a2: %v", err)
	}
	if err := reg.add("b-tunnel", pubB, tsB); err != nil {
		t.Fatalf("add b: %v", err)
	}

	// Same label twice → conflict.
	if err := reg.add("a1-tunnel", pubA, tsA1); err == nil {
		t.Error("re-add same label: expected error, got nil")
	}

	// byPubkey indexes both labels under pubA, one under pubB.
	reg.mu.RLock()
	gotA := len(reg.byPubkey[arrayKey(pubA)])
	gotB := len(reg.byPubkey[arrayKey(pubB)])
	reg.mu.RUnlock()
	if gotA != 2 {
		t.Errorf("byPubkey[A] = %d, want 2", gotA)
	}
	if gotB != 1 {
		t.Errorf("byPubkey[B] = %d, want 1", gotB)
	}

	// Remove one of pubA's labels — pubA still has the other.
	reg.remove("a1-tunnel", pubA, tsA1)
	reg.mu.RLock()
	gotA = len(reg.byPubkey[arrayKey(pubA)])
	reg.mu.RUnlock()
	if gotA != 1 {
		t.Errorf("after remove a1: byPubkey[A] = %d, want 1", gotA)
	}

	// Remove the last pubA label — entry should be gone (no empty
	// inner-map left dangling).
	reg.remove("a2-tunnel", pubA, tsA2)
	reg.mu.RLock()
	_, hasA := reg.byPubkey[arrayKey(pubA)]
	reg.mu.RUnlock()
	if hasA {
		t.Error("byPubkey[A] still present after removing last label")
	}

	// pubB untouched.
	reg.mu.RLock()
	gotB = len(reg.byPubkey[arrayKey(pubB)])
	reg.mu.RUnlock()
	if gotB != 1 {
		t.Errorf("byPubkey[B] = %d after pubA cleanup, want 1", gotB)
	}
}

func TestRegistry_RevokeMissing_DropsRemoved(t *testing.T) {
	reg := newRegistry()
	pubKept, _, _ := ed25519.GenerateKey(rand.Reader)
	pubRevoked, _, _ := ed25519.GenerateKey(rand.Reader)

	tsKept := makeSession(t)
	tsRevoked := makeSession(t)

	if err := reg.add("kept-tunnel", pubKept, tsKept); err != nil {
		t.Fatal(err)
	}
	if err := reg.add("revoked-tunnel", pubRevoked, tsRevoked); err != nil {
		t.Fatal(err)
	}

	// allowlist contains only pubKept.
	allow := allowlistDirWith(t, pubKept)
	reg.RevokeMissing(allow, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if !waitClosed(tsRevoked, 100*time.Millisecond) {
		t.Error("revoked session was not closed within 100ms")
	}
	if isClosed(tsKept) {
		t.Error("kept session was closed but should not have been")
	}
}

func TestRegistry_RevokeMissing_NoopWhenAllAllowed(t *testing.T) {
	reg := newRegistry()
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	tsA := makeSession(t)
	tsB := makeSession(t)
	if err := reg.add("a-tunnel", pubA, tsA); err != nil {
		t.Fatal(err)
	}
	if err := reg.add("b-tunnel", pubB, tsB); err != nil {
		t.Fatal(err)
	}

	allow := allowlistDirWith(t, pubA, pubB)
	reg.RevokeMissing(allow, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Brief settle window — RevokeMissing closes outside the lock, but if
	// it were going to close anything spuriously we'd see it inside this
	// bound.
	time.Sleep(20 * time.Millisecond)
	if isClosed(tsA) || isClosed(tsB) {
		t.Error("RevokeMissing closed an allowed session")
	}
}

func TestRegistry_RevokeMissing_NilAllow(t *testing.T) {
	reg := newRegistry()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts := makeSession(t)
	if err := reg.add("a-tunnel", pub, ts); err != nil {
		t.Fatal(err)
	}

	// Passing nil = gate disabled. Must not close anything.
	reg.RevokeMissing(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	time.Sleep(20 * time.Millisecond)
	if isClosed(ts) {
		t.Error("RevokeMissing(nil) closed a session")
	}
}

func TestRegistry_RevokeMissing_RevokesAllLabelsOfOnePubkey(t *testing.T) {
	reg := newRegistry()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ts1 := makeSession(t)
	ts2 := makeSession(t)
	if err := reg.add("one-tunnel", pub, ts1); err != nil {
		t.Fatal(err)
	}
	if err := reg.add("two-tunnel", pub, ts2); err != nil {
		t.Fatal(err)
	}

	allow := allowlistDirWith(t /* nothing — deny everyone */)
	reg.RevokeMissing(allow, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if !waitClosed(ts1, 100*time.Millisecond) {
		t.Error("session 1 not closed")
	}
	if !waitClosed(ts2, 100*time.Millisecond) {
		t.Error("session 2 not closed")
	}
}

// arrayKey converts a pubkey slice to the [32]byte map key the registry
// uses internally. Test-only helper.
func arrayKey(pub []byte) [32]byte {
	var k [32]byte
	copy(k[:], pub)
	return k
}

// waitClosed reports whether the session's Close channel fires within d.
func waitClosed(ts *tunnelSession, d time.Duration) bool {
	select {
	case <-ts.sess.CloseChan():
		return true
	case <-time.After(d):
		return false
	}
}

// isClosed is a non-blocking poll of the CloseChan.
func isClosed(ts *tunnelSession) bool {
	select {
	case <-ts.sess.CloseChan():
		return true
	default:
		return false
	}
}
