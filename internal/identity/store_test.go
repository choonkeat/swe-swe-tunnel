package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_CRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ids.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1714137600, 0)

	if _, err := s.Get(ctx, "abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}

	if err := s.Put(ctx, "abc", pub1, now); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Pubkey, pub1) {
		t.Errorf("pubkey mismatch")
	}
	if got.CreatedAt.Unix() != now.Unix() || got.LastSeenAt.Unix() != now.Unix() {
		t.Errorf("timestamps: created=%v lastSeen=%v want %v", got.CreatedAt, got.LastSeenAt, now)
	}

	// Re-Put should fail (PK conflict).
	if err := s.Put(ctx, "abc", pub2, now); err == nil {
		t.Error("Put on existing should error")
	}

	// Touch updates last_seen.
	later := now.Add(time.Hour)
	if err := s.Touch(ctx, "abc", later); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, _ = s.Get(ctx, "abc")
	if got.LastSeenAt.Unix() != later.Unix() {
		t.Errorf("LastSeen not updated: %v want %v", got.LastSeenAt, later)
	}
	if got.CreatedAt.Unix() != now.Unix() {
		t.Errorf("CreatedAt should not change after touch")
	}

	// Rotate replaces pubkey.
	if err := s.Rotate(ctx, "abc", pub2, later); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	got, _ = s.Get(ctx, "abc")
	if !bytes.Equal(got.Pubkey, pub2) {
		t.Errorf("Rotate didn't update pubkey")
	}

	// Delete removes the row.
	if err := s.Delete(ctx, "abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete, Get = %v, want ErrNotFound", err)
	}
}
