package allowlist

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// genKey returns a random Ed25519 pubkey and its base64 RawStd encoding.
func genKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, base64.RawStdEncoding.EncodeToString(pub)
}

// writeFile writes content to path under dir; t.Fatal on error.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestLoad_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pub1, b64_1 := genKey(t)
	pub2, b64_2 := genKey(t)
	pub3, b64_3 := genKey(t)

	writeFile(t, dir, "alice.pub", "# alice@laptop\n"+b64_1+"\n")
	writeFile(t, dir, "bob.pub",
		"\n# header comment\n"+
			b64_2+"   # bob@laptop trailing comment\n"+
			"\n"+
			b64_3+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Contains(pub1) || !s.Contains(pub2) || !s.Contains(pub3) {
		t.Fatalf("Contains missed a key")
	}
	if got, want := s.Len(), 3; got != want {
		t.Errorf("Len = %d, want %d", got, want)
	}
	if got, want := s.Files(), 2; got != want {
		t.Errorf("Files = %d, want %d", got, want)
	}
	if s.Dir() != dir {
		t.Errorf("Dir = %q, want %q", s.Dir(), dir)
	}
}

func TestLoad_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := Load(missing)
	if err == nil {
		t.Fatal("Load(missing) returned nil error")
	}
	if !strings.Contains(err.Error(), "read allowlist dir") {
		t.Errorf("error = %q, want it to mention 'read allowlist dir'", err.Error())
	}
}

func TestLoad_EmptyDirIsDenyAll(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0 (deny-all)", s.Len())
	}
	if s.Files() != 0 {
		t.Errorf("Files = %d, want 0", s.Files())
	}
	pub, _ := genKey(t)
	if s.Contains(pub) {
		t.Error("Contains returned true for arbitrary key against empty allowlist")
	}
}

func TestLoad_BadBase64NamesFileAndLine(t *testing.T) {
	dir := t.TempDir()
	_, b64 := genKey(t)
	writeFile(t, dir, "good.pub", b64+"\n")
	writeFile(t, dir, "bad.pub", "# header\nnot-valid-base64!!!\n")

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load with bad base64: nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "bad.pub") || !strings.Contains(msg, "line 2") {
		t.Errorf("error = %q, want it to mention 'bad.pub' and 'line 2'", msg)
	}
}

func TestLoad_WrongKeyLength(t *testing.T) {
	dir := t.TempDir()
	short := base64.RawStdEncoding.EncodeToString([]byte("only-thirty-bytes-not-a-real-key!!"))
	writeFile(t, dir, "short.pub", short+"\n")

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load with wrong-length key: nil error")
	}
	if !strings.Contains(err.Error(), "short.pub") || !strings.Contains(err.Error(), "want 32") {
		t.Errorf("error = %q, want it to mention 'short.pub' and 'want 32'", err.Error())
	}
}

func TestLoad_SkipsDotfiles(t *testing.T) {
	dir := t.TempDir()
	pub, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")
	// These should be silently ignored even though they'd fail to parse as keys.
	writeFile(t, dir, ".gitkeep", "")
	writeFile(t, dir, ".DS_Store", "garbage-not-a-pubkey")
	writeFile(t, dir, ".alice.pub.swp", "more-garbage")

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Contains(pub) {
		t.Error("alice.pub key not in set")
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len = %d, want 1 (only alice.pub counted)", got)
	}
	if got := s.Files(); got != 1 {
		t.Errorf("Files = %d, want 1", got)
	}
}

func TestLoad_SkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()
	pub, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")
	if err := os.Mkdir(filepath.Join(dir, "archive"), 0o755); err != nil {
		t.Fatal(err)
	}
	// File inside the subdirectory must NOT be parsed.
	_, b64Old := genKey(t)
	writeFile(t, filepath.Join(dir, "archive"), "old.pub", b64Old+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Contains(pub) {
		t.Error("alice.pub key not in set")
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len = %d, want 1 (subdir contents ignored)", got)
	}
}

func TestLoad_FollowsSymlinks(t *testing.T) {
	tmp := t.TempDir()
	linkTarget := filepath.Join(tmp, "real-keys")
	if err := os.Mkdir(linkTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, b64 := genKey(t)
	if err := os.WriteFile(filepath.Join(linkTarget, "alice.pub"), []byte(b64+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(tmp, "allowlist")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(linkTarget, "alice.pub"),
		filepath.Join(dir, "alice.pub")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Contains(pub) {
		t.Error("symlinked alice.pub key not in set")
	}
	if got := s.Files(); got != 1 {
		t.Errorf("Files = %d, want 1 (symlink counted as file)", got)
	}
}

func TestLoad_DuplicateKeyAcrossFilesIsUnioned(t *testing.T) {
	dir := t.TempDir()
	pub, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")
	writeFile(t, dir, "alice-copy.pub", b64+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.Contains(pub) {
		t.Error("Contains returned false for duplicated key")
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len = %d, want 1 (duplicate unioned)", got)
	}
	if got := s.Files(); got != 2 {
		t.Errorf("Files = %d, want 2", got)
	}
}

func TestReload_AddFile(t *testing.T) {
	dir := t.TempDir()
	pub1, b64_1 := genKey(t)
	writeFile(t, dir, "alice.pub", b64_1+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	pub2, b64_2 := genKey(t)
	writeFile(t, dir, "bob.pub", b64_2+"\n")

	added, removed, files, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if added != 1 || removed != 0 || files != 2 {
		t.Errorf("Reload diff = (added=%d removed=%d files=%d), want (1,0,2)",
			added, removed, files)
	}
	if !s.Contains(pub1) || !s.Contains(pub2) {
		t.Error("Contains missed a key after reload")
	}
}

func TestReload_RemoveFile(t *testing.T) {
	dir := t.TempDir()
	pub1, b64_1 := genKey(t)
	pub2, b64_2 := genKey(t)
	writeFile(t, dir, "alice.pub", b64_1+"\n")
	writeFile(t, dir, "bob.pub", b64_2+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(dir, "bob.pub")); err != nil {
		t.Fatal(err)
	}

	added, removed, files, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if added != 0 || removed != 1 || files != 1 {
		t.Errorf("Reload diff = (added=%d removed=%d files=%d), want (0,1,1)",
			added, removed, files)
	}
	if !s.Contains(pub1) {
		t.Error("alice still expected after bob removed")
	}
	if s.Contains(pub2) {
		t.Error("bob expected denied after removal")
	}
}

func TestReload_RenameFileSameKeyIsNoop(t *testing.T) {
	dir := t.TempDir()
	pub, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(filepath.Join(dir, "alice.pub"),
		filepath.Join(dir, "alice-renamed.pub")); err != nil {
		t.Fatal(err)
	}

	added, removed, files, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if added != 0 || removed != 0 {
		t.Errorf("Reload diff = (added=%d removed=%d), want (0,0) — set is keyed by pubkey",
			added, removed)
	}
	if files != 1 {
		t.Errorf("Files = %d, want 1", files)
	}
	if !s.Contains(pub) {
		t.Error("Contains lost key across rename")
	}
}

func TestReload_ParseErrorPreservesPriorSet(t *testing.T) {
	dir := t.TempDir()
	pub, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	priorLen := s.Len()
	priorFiles := s.Files()

	// Introduce a malformed file alongside the good one.
	writeFile(t, dir, "bad.pub", "not-base64!!!\n")

	added, removed, files, err := s.Reload()
	if err == nil {
		t.Fatal("Reload with bad file: nil error")
	}
	if added != 0 || removed != 0 || files != 0 {
		t.Errorf("Reload diff on error = (%d,%d,%d), want (0,0,0)", added, removed, files)
	}
	if got := s.Len(); got != priorLen {
		t.Errorf("Len = %d, want preserved %d after failed reload", got, priorLen)
	}
	if got := s.Files(); got != priorFiles {
		t.Errorf("Files = %d, want preserved %d after failed reload", got, priorFiles)
	}
	if !s.Contains(pub) {
		t.Error("alice expected to remain authorized after failed reload")
	}
}

func TestContains_WrongLengthPubkey(t *testing.T) {
	dir := t.TempDir()
	_, b64 := genKey(t)
	writeFile(t, dir, "alice.pub", b64+"\n")
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Contains(ed25519.PublicKey([]byte{1, 2, 3})) {
		t.Error("Contains accepted a 3-byte 'pubkey'")
	}
	if s.Contains(nil) {
		t.Error("Contains accepted a nil pubkey")
	}
}

// TestConcurrentReloadAndContains runs Reload and Contains concurrently to
// catch races under -race. Without the atomic.Pointer swap, this would flag
// the race detector.
func TestConcurrentReloadAndContains(t *testing.T) {
	dir := t.TempDir()
	keys := make([]ed25519.PublicKey, 0, 8)
	for i := 0; i < 8; i++ {
		pub, b64 := genKey(t)
		keys = append(keys, pub)
		writeFile(t, dir, "k"+string(rune('a'+i))+".pub", b64+"\n")
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	var stop atomic.Bool
	var wg sync.WaitGroup

	// Reloader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if _, _, _, err := s.Reload(); err != nil {
				t.Errorf("Reload: %v", err)
				return
			}
		}
	}()

	// Multiple readers.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				for _, k := range keys {
					if !s.Contains(k) {
						t.Errorf("Contains returned false for known key during concurrent reload")
						return
					}
				}
			}
		}()
	}

	time.Sleep(time.Until(deadline))
	stop.Store(true)
	wg.Wait()
}
