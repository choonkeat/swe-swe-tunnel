// Package allowlist holds the set of Ed25519 public keys tunneld is willing
// to accept Register from.
//
// The set is loaded from a directory of files at boot and refreshed on
// SIGHUP. Each regular file in the directory contributes zero or more keys,
// one base64-RawStd Ed25519 pubkey per line; '#' starts a comment, blank
// lines are ignored. Dotfiles and subdirectories are skipped (matches
// sshd's authorized_keys.d convention); symlinks are followed.
//
// Reads (Contains) are lock-free and safe under concurrent Reload via an
// atomic.Pointer swap of the underlying map.
package allowlist

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
)

// Set is a snapshot of authorized pubkeys, swappable atomically by Reload.
// The zero value is not usable; obtain one via Load.
type Set struct {
	keys  atomic.Pointer[map[[32]byte]struct{}]
	files atomic.Int64
	dir   string
}

// Load reads dir, parses every regular file it finds, and returns a fresh
// Set. Returns an error if the directory cannot be read or any file
// contains a malformed line — the caller decides whether that's fatal
// (boot) or recoverable (SIGHUP reload).
func Load(dir string) (*Set, error) {
	keys, files, err := parseDir(dir)
	if err != nil {
		return nil, err
	}
	s := &Set{dir: dir}
	s.keys.Store(&keys)
	s.files.Store(int64(files))
	return s, nil
}

// Reload re-reads the configured directory. On parse error, the in-memory
// set is unchanged (so policy doesn't change mid-flight when an operator
// mistypes a key) and the error is returned for the caller to log.
func (s *Set) Reload() (added, removed, files int, err error) {
	next, files, err := parseDir(s.dir)
	if err != nil {
		return 0, 0, 0, err
	}
	prev := *s.keys.Load()
	for k := range next {
		if _, ok := prev[k]; !ok {
			added++
		}
	}
	for k := range prev {
		if _, ok := next[k]; !ok {
			removed++
		}
	}
	s.keys.Store(&next)
	s.files.Store(int64(files))
	return added, removed, files, nil
}

// Contains reports whether pub is in the current allowlist.
func (s *Set) Contains(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	var k [32]byte
	copy(k[:], pub)
	m := *s.keys.Load()
	_, ok := m[k]
	return ok
}

// Len returns the number of distinct pubkeys currently authorized.
func (s *Set) Len() int { return len(*s.keys.Load()) }

// Files returns the number of regular files contributing to the current
// set, as observed by the most recent successful Load or Reload.
func (s *Set) Files() int { return int(s.files.Load()) }

// Dir returns the directory path the set was loaded from.
func (s *Set) Dir() string { return s.dir }

func parseDir(dir string) (map[[32]byte]struct{}, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("read allowlist dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	out := make(map[[32]byte]struct{})
	files := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		full := filepath.Join(dir, name)
		// Stat through symlinks so we follow links to regular files.
		info, err := os.Stat(full)
		if err != nil {
			return nil, 0, fmt.Errorf("stat %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := parseInto(full, name, out); err != nil {
			return nil, 0, err
		}
		files++
	}
	return out, files, nil
}

func parseInto(path, displayName string, out map[[32]byte]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", displayName, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		b, err := base64.RawStdEncoding.DecodeString(line)
		if err != nil {
			return fmt.Errorf("%s line %d: bad base64: %w", displayName, lineNo, err)
		}
		if len(b) != ed25519.PublicKeySize {
			return fmt.Errorf("%s line %d: pubkey is %d bytes, want %d",
				displayName, lineNo, len(b), ed25519.PublicKeySize)
		}
		var k [32]byte
		copy(k[:], b)
		out[k] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", displayName, err)
	}
	return nil
}
