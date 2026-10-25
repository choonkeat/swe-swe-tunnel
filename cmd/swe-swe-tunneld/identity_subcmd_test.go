package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
)

func TestValidateRegistrationGate(t *testing.T) {
	cases := []struct {
		name    string
		dir     string
		open    bool
		wantErr string
	}{
		{"neither refuses", "", false, "refusing to start"},
		{"both refuses", "/etc/allow", true, "mutually exclusive"},
		{"allowlist only ok", "/etc/allow", false, ""},
		{"open only ok", "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRegistrationGate(tc.dir, tc.open)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// seedIdentities writes rows into {stateDir}/identities.db, the same
// file the daemon uses.
func seedIdentities(t *testing.T, stateDir string, uniques ...string) map[string]ed25519.PublicKey {
	t.Helper()
	s, err := identity.Open(identityDBPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	keys := map[string]ed25519.PublicKey{}
	for _, u := range uniques {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err := s.Put(context.Background(), u, pub, time.Unix(1714137600, 0)); err != nil {
			t.Fatal(err)
		}
		keys[u] = pub
	}
	return keys
}

func TestIdentityList_PrintsRows(t *testing.T) {
	stateDir := t.TempDir()
	keys := seedIdentities(t, stateDir, "alice", "bob")

	var out bytes.Buffer
	if code := runIdentityList(nil, stateDir, &out, quietLogger()); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	s := out.String()
	for u, k := range keys {
		if !strings.Contains(s, u) || !strings.Contains(s, base64.RawStdEncoding.EncodeToString(k)) {
			t.Errorf("output missing %s or its key:\n%s", u, s)
		}
	}
	if !strings.HasPrefix(s, "UNIQUE") {
		t.Errorf("missing header:\n%s", s)
	}
}

func TestIdentityDelete_ReleasesName(t *testing.T) {
	stateDir := t.TempDir()
	seedIdentities(t, stateDir, "alice", "bob")

	var out bytes.Buffer
	if code := runIdentityDelete([]string{"alice"}, stateDir, &out, quietLogger()); code != 0 {
		t.Fatalf("exit = %d, out=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "released alice") {
		t.Errorf("out = %q", out.String())
	}

	s, err := identity.Open(identityDBPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Get(context.Background(), "alice"); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("alice still present: %v", err)
	}
	if _, err := s.Get(context.Background(), "bob"); err != nil {
		t.Errorf("bob was removed too: %v", err)
	}
}

func TestIdentityDelete_PurgeCert(t *testing.T) {
	stateDir := t.TempDir()
	seedIdentities(t, stateDir, "alice", "bob")
	certDir := filepath.Join(stateDir, "lego", "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"_.alice-tunnel.example.com.crt", "_.alice-tunnel.example.com.key",
		"_.bob-tunnel.example.com.crt", "_.bob-tunnel.example.com.key",
	} {
		if err := os.WriteFile(filepath.Join(certDir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	code := runIdentityDelete([]string{"--purge-cert", "--apex", "example.com", "alice"}, stateDir, &out, quietLogger())
	if code != 0 {
		t.Fatalf("exit = %d, out=%q", code, out.String())
	}
	for _, f := range []string{"_.alice-tunnel.example.com.crt", "_.alice-tunnel.example.com.key"} {
		if _, err := os.Stat(filepath.Join(certDir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists", f)
		}
	}
	for _, f := range []string{"_.bob-tunnel.example.com.crt", "_.bob-tunnel.example.com.key"} {
		if _, err := os.Stat(filepath.Join(certDir, f)); err != nil {
			t.Errorf("%s was removed: %v", f, err)
		}
	}
}

func TestIdentityDelete_Errors(t *testing.T) {
	stateDir := t.TempDir()
	seedIdentities(t, stateDir, "alice")
	t.Setenv("SWE_TUNNEL_APEX", "")

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arg", nil, 2},
		{"two args", []string{"alice", "bob"}, 2},
		{"bad shape (path escape)", []string{"../etc"}, 2},
		{"purge without apex", []string{"--purge-cert", "alice"}, 2},
		{"unknown name", []string{"nobody"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := runIdentityDelete(tc.args, stateDir, &bytes.Buffer{}, quietLogger()); code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestRunSubcommand_DispatchIdentity(t *testing.T) {
	stateDir := t.TempDir()
	seedIdentities(t, stateDir, "alice")
	var out bytes.Buffer
	code, handled := runSubcommand([]string{"swe-swe-tunneld", "identity-list"}, stateDir, &out, quietLogger())
	if !handled || code != 0 || !strings.Contains(out.String(), "alice") {
		t.Errorf("identity-list: handled=%v code=%d out=%q", handled, code, out.String())
	}
	code, handled = runSubcommand([]string{"swe-swe-tunneld", "identity-delete", "alice"}, stateDir, &out, quietLogger())
	if !handled || code != 0 {
		t.Errorf("identity-delete: handled=%v code=%d", handled, code)
	}
}

// buildDaemon compiles the real binary so boot-time checks are tested
// end to end, exactly as an operator would hit them.
func buildDaemon(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary; skipped in -short")
	}
	bin := filepath.Join(t.TempDir(), "swe-swe-tunneld")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runDaemon starts the binary with a clean environment plus env, and
// returns its exit code and combined output. --no-acme with an empty
// state dir means a booted daemon would only bind a port; the test
// uses a short timeout to tell "refused to boot" from "booted".
func runDaemon(t *testing.T, bin string, env []string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"--no-acme", "--apex-domain", "example.com", "--listen", "127.0.0.1:0", "--state-dir", t.TempDir()}, args...)...)
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return -1, string(out) // still running: it booted
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return 0, string(out)
}

func TestE2E_Boot_RefusesWithoutRegistrationGate(t *testing.T) {
	bin := buildDaemon(t)
	allowDir := t.TempDir()

	code, out := runDaemon(t, bin, nil)
	if code != 2 || !strings.Contains(out, "refusing to start without a registration gate") {
		t.Errorf("no gate: code=%d, want 2\n%s", code, out)
	}

	code, out = runDaemon(t, bin, []string{"SWE_TUNNEL_ALLOWLIST_DIR=" + allowDir, "SWE_TUNNEL_OPEN_REGISTRATION=1"})
	if code != 2 || !strings.Contains(out, "mutually exclusive") {
		t.Errorf("both: code=%d, want 2\n%s", code, out)
	}

	// Compose sets unset vars to "". Empty must count as unset, not as a gate.
	code, out = runDaemon(t, bin, []string{"SWE_TUNNEL_ALLOWLIST_DIR=", "SWE_TUNNEL_OPEN_REGISTRATION="})
	if code != 2 {
		t.Errorf("empty env: code=%d, want 2\n%s", code, out)
	}
}

func TestE2E_Boot_StartsWithAGate(t *testing.T) {
	bin := buildDaemon(t)

	code, out := runDaemon(t, bin, []string{"SWE_TUNNEL_ALLOWLIST_DIR=" + t.TempDir()})
	if code != -1 || !strings.Contains(out, "allowlist loaded") {
		t.Errorf("allowlist: code=%d, want still running\n%s", code, out)
	}

	code, out = runDaemon(t, bin, nil, "--open-registration")
	if code != -1 || !strings.Contains(out, "OPEN REGISTRATION") {
		t.Errorf("open flag: code=%d, want still running with warning\n%s", code, out)
	}
}
