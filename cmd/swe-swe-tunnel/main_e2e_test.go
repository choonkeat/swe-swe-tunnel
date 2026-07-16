package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/choonkeat/swe-swe-tunnel/internal/tunneldfake"
)

// provisionKey writes a fresh Ed25519 identity key (PKCS8 PEM) to path so
// the binary reuses it instead of generating one. Lifecycle tests that
// exercise connect/register need a key already on disk: a missing key now
// triggers the first-boot generate-and-exit path (see
// TestBinary_FreshKey_GeneratesAndExits).
// scrubIdentityEnv returns environ with the identity-related vars removed
// so tests are not affected by an ambient SWE_TUNNEL_IDENTITY_KEY /
// SWE_TUNNEL_KEY exported by the surrounding dev container.
func scrubIdentityEnv(environ []string) []string {
	out := environ[:0:0]
	for _, kv := range environ {
		if strings.HasPrefix(kv, "SWE_TUNNEL_IDENTITY_KEY=") ||
			strings.HasPrefix(kv, "SWE_TUNNEL_KEY=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func provisionKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildTunnelBinary compiles cmd/swe-swe-tunnel into a temp directory
// and returns the absolute path. The binary is reused across subtests
// (built once per package test run via sync.Once).
var (
	binPathOnce sync.Once
	binPath     string
	binBuildErr error
)

func binaryPath(t *testing.T) string {
	t.Helper()
	binPathOnce.Do(func() {
		dir, err := os.MkdirTemp("", "swe-swe-tunnel-bin-*")
		if err != nil {
			binBuildErr = err
			return
		}
		out := filepath.Join(dir, "swe-swe-tunnel")
		// `go build` runs in the same module as this test, so we can
		// just point it at the cmd path.
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			binBuildErr = err
			return
		}
		binPath = out
	})
	if binBuildErr != nil {
		t.Fatalf("build binary: %v", binBuildErr)
	}
	return binPath
}

// runBinary launches the binary with the given args, captures stdout
// and stderr separately, sends SIGTERM after the predicate fires (or
// the deadline elapses), and returns captured streams + exit error.
func runBinary(t *testing.T, args []string, env []string, untilStdout func(seen string) bool, untilStderr func(seen string) bool, deadline time.Duration) (stdoutBuf, stderrBuf []byte, exitErr error) {
	t.Helper()

	cmd := exec.Command(binaryPath(t), args...)
	// Scrub any ambient identity env so tests control identity solely via
	// --identity-key or the explicit env param. Dev containers may export
	// SWE_TUNNEL_IDENTITY_KEY, which would otherwise override the on-disk
	// key and make the generate/reuse behavior non-deterministic.
	cmd.Env = append(scrubIdentityEnv(os.Environ()), env...)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
		mu     sync.Mutex
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	signaled := make(chan struct{})
	signalOnce := sync.Once{}
	signalNow := func() {
		signalOnce.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			close(signaled)
		})
	}

	// Spawn readers for stdout and stderr that append to buffers and
	// fire the predicate (if any) on each line.
	pumpDone := make(chan struct{}, 2)
	go pumpReader(stdoutPipe, &stdout, &mu, untilStdout, signalNow, pumpDone)
	go pumpReader(stderrPipe, &stderr, &mu, untilStderr, signalNow, pumpDone)

	// Hard deadline backstop: if neither predicate fired in time, signal
	// anyway so the test doesn't hang.
	go func() {
		select {
		case <-signaled:
		case <-time.After(deadline):
			signalNow()
		}
	}()

	exitErr = cmd.Wait()
	// Drain pumps. They exit when their pipes close (which happens when
	// the child exits), so this is fast.
	<-pumpDone
	<-pumpDone

	mu.Lock()
	stdoutBuf = append([]byte(nil), stdout.Bytes()...)
	stderrBuf = append([]byte(nil), stderr.Bytes()...)
	mu.Unlock()
	return stdoutBuf, stderrBuf, exitErr
}

func pumpReader(r io.ReadCloser, dst *bytes.Buffer, mu *sync.Mutex, until func(string) bool, signal func(), done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		mu.Lock()
		dst.WriteString(line)
		dst.WriteByte('\n')
		mu.Unlock()
		if until != nil && until(line) {
			signal()
		}
	}
	_ = r.Close()
}

func startFake(t *testing.T) *tunneldfake.Server {
	t.Helper()
	f, err := tunneldfake.Start(tunneldfake.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

// TestBinary_DefaultFormat_StdoutEmpty covers acceptance #1: running
// cmd/swe-swe-tunnel with no new flags produces zero bytes on stdout
// across a full happy-path lifecycle. The supervisor channel must stay
// silent unless the operator opts in via --report-format=jsonl.
func TestBinary_DefaultFormat_StdoutEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short: builds the binary")
	}
	f := startFake(t)
	keyDir := t.TempDir()
	provisionKey(t, filepath.Join(keyDir, "id.key"))

	stdout, stderr, exitErr := runBinary(t,
		[]string{
			"--server", f.URL(),
			"--unique", "alpha",
			"--insecure",
			"--identity-key", filepath.Join(keyDir, "id.key"),
		},
		nil,
		// stdout predicate: should never fire — but if it does, return
		// false to keep waiting (the deadline backstop will signal).
		func(string) bool { return false },
		// stderr: signal as soon as we see "registered" (stderr log
		// line from tunnelclient.Connect).
		func(s string) bool { return strings.Contains(s, "registered") },
		15*time.Second,
	)

	if len(stdout) != 0 {
		t.Errorf("default stdout must be empty, got %d bytes:\n%s", len(stdout), stdout)
	}
	// stderr still has slog output; that's expected.
	if !bytes.Contains(stderr, []byte("registered")) {
		t.Errorf("expected stderr to log 'registered', got:\n%s", stderr)
	}
	// Graceful SIGTERM path: Run drives Deregister, returns nil, and
	// main exits 0. A non-zero exit here would mean the signal arrived
	// before register or that something else failed.
	if exitErr != nil {
		var ee *exec.ExitError
		if errors.As(exitErr, &ee) {
			t.Errorf("binary exited %d on graceful SIGTERM; want 0\nstderr:\n%s", ee.ExitCode(), stderr)
		} else {
			t.Errorf("unexpected error type: %T %v", exitErr, exitErr)
		}
	}
}

// TestBinary_JSONLFormat_StdoutHasLifecycle covers acceptance #2 at the
// binary level: --report-format=jsonl emits the documented event
// sequence (starting, connecting, register_ok, deregister_ok) on
// stdout, one JSON object per line, with the v=1 envelope.
func TestBinary_JSONLFormat_StdoutHasLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short: builds the binary")
	}
	f := startFake(t)
	keyDir := t.TempDir()
	provisionKey(t, filepath.Join(keyDir, "id.key"))

	stdout, stderr, _ := runBinary(t,
		[]string{
			"--server", f.URL(),
			"--unique", "alpha",
			"--insecure",
			"--identity-key", filepath.Join(keyDir, "id.key"),
			"--report-format", "jsonl",
		},
		nil,
		// signal as soon as register_ok lands on stdout
		func(line string) bool {
			return strings.Contains(line, `"kind":"register_ok"`)
		},
		nil,
		15*time.Second,
	)

	if len(stdout) == 0 {
		t.Fatalf("jsonl stdout empty; stderr:\n%s", stderr)
	}
	kinds := parseKinds(t, stdout)

	// starting must be first.
	if len(kinds) == 0 || kinds[0] != "starting" {
		t.Errorf("first kind: got %v, want starting", kinds)
	}
	// must contain connecting and register_ok.
	if !contains(kinds, "connecting") {
		t.Errorf("missing connecting in %v", kinds)
	}
	if !contains(kinds, "register_ok") {
		t.Errorf("missing register_ok in %v", kinds)
	}
	// last must be deregister_ok (graceful) — the test signaled
	// SIGTERM after register_ok, so Run's graceful path runs.
	if got := kinds[len(kinds)-1]; got != "deregister_ok" {
		t.Errorf("last kind: got %q, want deregister_ok. Full sequence: %v", got, kinds)
	}
	// each line is a v=1 envelope.
	for _, line := range bytes.Split(bytes.TrimSpace(stdout), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev struct {
			V    int    `json:"v"`
			TS   string `json:"ts"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Errorf("invalid jsonl line %q: %v", line, err)
			continue
		}
		if ev.V != 1 {
			t.Errorf("v: want 1, got %d on line %q", ev.V, line)
		}
		if ev.Kind == "" {
			t.Errorf("missing kind: %q", line)
		}
		if ev.TS == "" {
			t.Errorf("missing ts: %q", line)
		}
	}
}

// TestBinary_JSONLFormat_EnvVar covers the env equivalent of the flag.
func TestBinary_JSONLFormat_EnvVar(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short: builds the binary")
	}
	f := startFake(t)
	keyDir := t.TempDir()
	provisionKey(t, filepath.Join(keyDir, "id.key"))

	stdout, _, _ := runBinary(t,
		[]string{
			"--server", f.URL(),
			"--unique", "alpha",
			"--insecure",
			"--identity-key", filepath.Join(keyDir, "id.key"),
		},
		[]string{"SWE_TUNNEL_REPORT_FORMAT=jsonl"},
		func(line string) bool { return strings.Contains(line, `"kind":"register_ok"`) },
		nil,
		15*time.Second,
	)

	if !bytes.Contains(stdout, []byte(`"kind":"starting"`)) {
		t.Errorf("env-var jsonl mode should emit starting; got:\n%s", stdout)
	}
}

// TestBinary_BadReportFormat_ExitsNonZero covers operator error
// surfacing: an unknown --report-format value rejects at startup.
func TestBinary_BadReportFormat_ExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short: builds the binary")
	}
	cmd := exec.Command(binaryPath(t),
		"--server", "https://127.0.0.1:1",
		"--unique", "alpha",
		"--insecure",
		"--report-format", "yaml",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit; combined output:\n%s", out)
	}
	if !bytes.Contains(out, []byte("invalid --report-format")) {
		t.Errorf("expected 'invalid --report-format' in stderr, got:\n%s", out)
	}
}

// TestBinary_FreshKey_GeneratesAndExits covers the first-boot bootstrap:
// with no identity key on disk, the binary generates one, prints the
// pubkey + path to stderr, emits a fatal(identity_generated) event, and
// exits non-zero WITHOUT connecting — so it never burns a registration
// attempt against an un-allowlisted pubkey.
func TestBinary_FreshKey_GeneratesAndExits(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in -short: builds the binary")
	}
	// No fake server needed: the binary must exit before dialing. Point
	// --server at an unroutable address to prove no connection is made.
	keyPath := filepath.Join(t.TempDir(), "id.key")

	stdout, stderr, exitErr := runBinary(t,
		[]string{
			"--server", "https://127.0.0.1:1",
			"--unique", "alpha",
			"--insecure",
			"--identity-key", keyPath,
			"--report-format", "jsonl",
		},
		nil,
		// Signal as soon as the fatal event lands so we don't wait out
		// the deadline.
		func(line string) bool { return strings.Contains(line, `"kind":"fatal"`) },
		nil,
		15*time.Second,
	)

	// Non-zero exit.
	var ee *exec.ExitError
	if !errors.As(exitErr, &ee) {
		t.Fatalf("expected non-zero exit, got err=%v\nstderr:\n%s", exitErr, stderr)
	}
	if ee.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1\nstderr:\n%s", ee.ExitCode(), stderr)
	}

	// stderr: human-facing pubkey + path + instruction.
	if !bytes.Contains(stderr, []byte("Generated a new tunnel identity key")) {
		t.Errorf("stderr missing generate notice:\n%s", stderr)
	}
	if !bytes.Contains(stderr, []byte(keyPath)) {
		t.Errorf("stderr missing key path %q:\n%s", keyPath, stderr)
	}
	if !bytes.Contains(stderr, []byte("pubkey:")) {
		t.Errorf("stderr missing pubkey line:\n%s", stderr)
	}

	// stdout jsonl: exactly the fatal(identity_generated) event, and NO
	// connect/register lifecycle events (we never touched the network).
	kinds := parseKinds(t, stdout)
	if !contains(kinds, "fatal") {
		t.Errorf("stdout missing fatal event; kinds=%v", kinds)
	}
	for _, forbidden := range []string{"connecting", "register_ok", "registered"} {
		if contains(kinds, forbidden) {
			t.Errorf("stdout contains %q — binary connected despite fresh key; kinds=%v", forbidden, kinds)
		}
	}
	if !bytes.Contains(stdout, []byte(`"reason":"identity_generated"`)) {
		t.Errorf("stdout fatal event missing reason=identity_generated:\n%s", stdout)
	}

	// The key was persisted, so the NEXT boot reuses it (generated=false).
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not persisted: %v", err)
	}
}

func parseKinds(t *testing.T, raw []byte) []string {
	t.Helper()
	var kinds []string
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid jsonl: %q (%v)", line, err)
		}
		kinds = append(kinds, ev.Kind)
	}
	return kinds
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
