package portpolicy

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLoadInline_HappyPath(t *testing.T) {
	s, err := LoadInline("1977,3000-3099", "flag")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Permits(1977) || !s.Permits(3050) {
		t.Error("expected permits in-spec ports")
	}
	if s.Permits(22) {
		t.Error("port 22 should not be permitted")
	}
	if s.Source() != "flag" {
		t.Errorf("Source() = %q, want flag", s.Source())
	}
	if s.File() != "" {
		t.Errorf("File() = %q, want empty for inline", s.File())
	}
}

func TestLoadInline_BadSpec(t *testing.T) {
	if _, err := LoadInline("garbage-not-a-port", "flag"); err == nil {
		t.Error("expected error for malformed spec")
	}
}

func TestLoadFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977,3000-3099,8080\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Permits(1977) || !s.Permits(3050) || !s.Permits(8080) {
		t.Error("expected permits for in-spec ports")
	}
	if s.Permits(22) {
		t.Error("port 22 should not be permitted")
	}
	if s.File() != path {
		t.Errorf("File() = %q, want %q", s.File(), path)
	}
	if s.Source() != "file:"+path {
		t.Errorf("Source() = %q, want file:%s", s.Source(), path)
	}
}

func TestLoadFile_MultilineWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	content := `# operator notes
1977       # swe-swe primary
3000-3099  # dev range

# blank lines OK
8080
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	for _, port := range []int{1977, 3050, 8080} {
		if !s.Permits(port) {
			t.Errorf("port %d should be permitted (spec=%q)", port, s.Spec())
		}
	}
	if s.Permits(22) {
		t.Error("port 22 should not be permitted")
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	if _, err := LoadFile("/no/such/path/swe-swe"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReload_InlineIsNoOp(t *testing.T) {
	s, err := LoadInline("1977", "flag")
	if err != nil {
		t.Fatal(err)
	}
	changed, err := s.Reload()
	if err != nil {
		t.Errorf("inline Reload err = %v", err)
	}
	if changed {
		t.Error("inline Reload should never report changed=true")
	}
}

func TestReload_FilePicksUpEdits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Permits(8080) {
		t.Fatal("baseline: port 8080 should not be permitted")
	}

	if err := os.WriteFile(path, []byte("1977,8080"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !changed {
		t.Error("Reload should report changed=true after file edit")
	}
	if !s.Permits(8080) {
		t.Error("after Reload, port 8080 should be permitted")
	}
}

func TestReload_NoChangeReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977,8080"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := s.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if changed {
		t.Error("Reload with unchanged content should report changed=false")
	}
}

// TestReload_ParseErrorPreservesPriorPolicy: a bad edit must not
// reduce the live allowlist. Operator can fix the file and HUP
// again; meanwhile the prior policy stays live.
func TestReload_ParseErrorPreservesPriorPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977,8080"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("garbage-not-a-port"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reload(); err == nil {
		t.Error("Reload should error on garbage spec")
	}
	if !s.Permits(1977) || !s.Permits(8080) {
		t.Error("prior policy must be preserved on parse error")
	}
}

// TestReload_ConcurrentPermits exercises the atomic-pointer claim:
// hammering Permits from multiple goroutines while Reload swaps the
// underlying policy must not race. Run under -race.
func TestReload_ConcurrentPermits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ports")
	if err := os.WriteFile(path, []byte("1977"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = s.Permits(1977)
				_ = s.Permits(8080)
			}
		}()
	}
	specs := []string{"1977", "1977,8080", "8080,3000-3099", "1977,8080,3000-3099"}
	for _, spec := range specs {
		if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
}

// TestSet_NilSafe ensures a nil *Set never panics — defensive for any
// startup path that fails to wire the pointer.
func TestSet_NilSafe(t *testing.T) {
	var s *Set
	if s.Permits(1977) {
		t.Error("nil Set.Permits should be false")
	}
	if s.Spec() != "" || s.Source() != "" || s.File() != "" {
		t.Error("nil Set accessors should return empty strings")
	}
	if changed, err := s.Reload(); changed || err != nil {
		t.Errorf("nil Set.Reload = (%v, %v), want (false, nil)", changed, err)
	}
}
