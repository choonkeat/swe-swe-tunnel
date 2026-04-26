package tunnelclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is the persisted, on-disk view of a registered tunnel session.
// Other tools on the same host (notably swe-swe) read this file as a
// fallback to discover the public hostname when it isn't supplied via
// env/flag.
type State struct {
	Hostname     string `json:"hostname"`
	Unique       string `json:"unique"`
	RegisteredAt string `json:"registered_at"` // RFC3339, UTC
}

// WriteState atomically writes a JSON state file describing sess.
//
// Behavior:
//   - Parent directories are created with mode 0700 if missing.
//   - File mode is 0600 (private to the running user).
//   - Write is atomic: data is written to a sibling tempfile, fsynced, then
//     renamed onto path. A concurrent reader sees either the previous
//     contents (or ENOENT) or the new contents — never a partial write.
//   - Timestamp is RFC3339 in UTC (no nanoseconds), matching the documented
//     wire shape.
func WriteState(path string, sess *Session) error {
	if sess == nil {
		return fmt.Errorf("tunnelclient.WriteState: nil session")
	}
	if path == "" {
		return fmt.Errorf("tunnelclient.WriteState: empty path")
	}

	s := State{
		Hostname:     sess.hostname,
		Unique:       sess.unique,
		RegisteredAt: sess.registeredAt.UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we bail before rename. Rename consumes the
	// tempfile on success, making this a no-op.
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
