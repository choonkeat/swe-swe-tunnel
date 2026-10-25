package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
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

	// Re-Put should fail with the typed sentinel (PK conflict).
	if err := s.Put(ctx, "abc", pub2, now); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("Put on existing: err = %v, want wrapped ErrAlreadyExists", err)
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

// TestStore_Put_ConcurrentRaceReturnsErrAlreadyExists drives the actual
// race condition that motivates ErrAlreadyExists: N goroutines all
// trying to Put the same unique. Exactly one should succeed; every
// loser should surface the typed sentinel (not a wrapped sqlite-driver
// error string), so the caller can distinguish "row pre-exists, do
// idempotent fallback" from "store is broken".
func TestStore_Put_ConcurrentRaceReturnsErrAlreadyExists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "race.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1714137600, 0)

	const N = 8
	var wg sync.WaitGroup
	errs := make(chan error, N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.Put(context.Background(), "raced", pub, now)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	winners, exists, other := 0, 0, 0
	for err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrAlreadyExists):
			exists++
		default:
			other++
			t.Errorf("unexpected Put error %v (want nil or ErrAlreadyExists)", err)
		}
	}
	if winners != 1 {
		t.Errorf("winners = %d, want exactly 1", winners)
	}
	if exists != N-1 {
		t.Errorf("ErrAlreadyExists count = %d, want %d", exists, N-1)
	}
	if other != 0 {
		t.Errorf("other-error count = %d, want 0", other)
	}
}

func TestStore_List(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	got, err := s.List(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("List(empty) = %v, %v; want empty, nil", got, err)
	}

	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	t0 := time.Unix(1714137600, 0)
	// Insert out of order to prove List sorts by unique.
	if err := s.Put(ctx, "zed", pubB, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "abc", pubA, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err = s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Unique != "abc" || got[1].Unique != "zed" {
		t.Fatalf("List order = %+v; want abc, zed", got)
	}
	if !bytes.Equal(got[0].Pubkey, pubA) || !got[0].CreatedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("abc row = %+v", got[0])
	}

	if err := s.Delete(ctx, "abc"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.List(ctx)
	if len(got) != 1 || got[0].Unique != "zed" {
		t.Errorf("after Delete, List = %+v; want only zed", got)
	}
}
