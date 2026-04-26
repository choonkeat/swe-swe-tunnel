// Package identity persists (unique → Ed25519 pubkey) ownership records.
//
// One row per registered `unique`. Reclaim flow: a connecting client whose
// pubkey doesn't match the stored one must produce a Proof signed with the
// stored private key — only the legitimate owner has it.
//
// Backed by SQLite via modernc.org/sqlite (pure Go, no CGo).
package identity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is a row from the identities table.
type Entry struct {
	Unique     string
	Pubkey     ed25519.PublicKey
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// ErrNotFound is returned by Get when no row matches.
var ErrNotFound = errors.New("identity not found")

// Store wraps the underlying database connection.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the SQLite file at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open identity db %q: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS identities (
    unique_name  TEXT PRIMARY KEY,
    pubkey       BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pubkey ON identities(pubkey);
`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Get returns the stored entry for unique, or ErrNotFound.
func (s *Store) Get(ctx context.Context, unique string) (Entry, error) {
	var (
		pubkey   []byte
		created  int64
		lastSeen int64
	)
	err := s.db.QueryRowContext(ctx,
		"SELECT pubkey, created_at, last_seen_at FROM identities WHERE unique_name = ?",
		unique,
	).Scan(&pubkey, &created, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("get %q: %w", unique, err)
	}
	return Entry{
		Unique:     unique,
		Pubkey:     ed25519.PublicKey(pubkey),
		CreatedAt:  time.Unix(created, 0).UTC(),
		LastSeenAt: time.Unix(lastSeen, 0).UTC(),
	}, nil
}

// Put inserts a fresh ownership record. Returns an error if the unique already
// exists (UNIQUE constraint on PRIMARY KEY).
func (s *Store) Put(ctx context.Context, unique string, pubkey ed25519.PublicKey, now time.Time) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("put: pubkey wrong size %d", len(pubkey))
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO identities (unique_name, pubkey, created_at, last_seen_at) VALUES (?, ?, ?, ?)",
		unique, []byte(pubkey), now.Unix(), now.Unix(),
	)
	if err != nil {
		return fmt.Errorf("put %q: %w", unique, err)
	}
	return nil
}

// Touch updates last_seen_at without changing the pubkey.
func (s *Store) Touch(ctx context.Context, unique string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE identities SET last_seen_at = ? WHERE unique_name = ?",
		now.Unix(), unique,
	)
	if err != nil {
		return fmt.Errorf("touch %q: %w", unique, err)
	}
	return nil
}

// Rotate replaces the stored pubkey for an existing unique. Used after a
// successful Challenge/Proof reclaim flow.
func (s *Store) Rotate(ctx context.Context, unique string, newPubkey ed25519.PublicKey, now time.Time) error {
	if len(newPubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("rotate: pubkey wrong size %d", len(newPubkey))
	}
	_, err := s.db.ExecContext(ctx,
		"UPDATE identities SET pubkey = ?, last_seen_at = ? WHERE unique_name = ?",
		[]byte(newPubkey), now.Unix(), unique,
	)
	if err != nil {
		return fmt.Errorf("rotate %q: %w", unique, err)
	}
	return nil
}

// Delete removes an ownership record.
func (s *Store) Delete(ctx context.Context, unique string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM identities WHERE unique_name = ?",
		unique,
	)
	if err != nil {
		return fmt.Errorf("delete %q: %w", unique, err)
	}
	return nil
}
