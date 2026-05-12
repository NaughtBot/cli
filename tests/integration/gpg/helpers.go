//go:build integration

// Package gpg — helpers for the GPG signing e2e suite. Mirrors the shape of
// the age/ssh suite helpers: anything that is not the happy-path test body
// lives here.
package gpg

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/naughtbot/cli/tests/integration/shared"
)

// repoRoot resolves the monorepo root. Honours REPO_ROOT for callers that run
// the tests from a non-canonical cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("REPO_ROOT"); v != "" {
		return v
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("repoRoot: getwd: %v", err)
	}
	// tests/integration/gpg -> tests/integration -> tests -> repo root
	return filepath.Clean(filepath.Join(cwd, "..", "..", ".."))
}

// cliEnv is the env every CLI subprocess inherits. Same shape as the age
// suite's helper: acceptance flag is required because the simulator approver
// returns software-only attestation.
func cliEnv(env *shared.TestEnv) []string {
	e := os.Environ()
	e = append(e,
		"NB_CONFIG_DIR="+env.ConfigDir,
		"TEST_LOGIN_URL="+env.LoginURL,
		"TEST_RELAY_URL="+env.RelayURL,
		"TEST_BLOB_URL="+env.BlobURL,
		"SKIP_VERIFY_ATTESTATION=true",
		"NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1",
	)
	return e
}

// gpgEnv is the env for the stock `gpg` binary — a copy of cliEnv plus an
// isolated GNUPGHOME so we never pollute the developer's real keyring and the
// test has a clean starting state.
func gpgEnv(gnupgHome string) []string {
	e := os.Environ()
	e = append(e,
		"GNUPGHOME="+gnupgHome,
		// Keep gpg silent on TTY-absent CI runs.
		"GPG_TTY=",
	)
	return e
}

// lockedBuffer mirrors the age suite helper: mutex-guarded bytes.Buffer safe
// for concurrent writes from exec.Cmd's stdout/stderr drain goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *lockedBuffer) Snapshot() *bytes.Buffer {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := bytes.NewBuffer(make([]byte, 0, b.buf.Len()))
	out.Write(b.buf.Bytes())
	return out
}

// removeIfExists is a tiny convenience for cleanup paths that should not fail
// when the file is already gone.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// fingerprintRe matches a 40-hex-char OpenPGP V4 fingerprint. The CLI prints
// it after `nb gpg --generate-key` in the style GnuPG uses, typically as
// "Fingerprint: <40 hex>" or bare on its own line.
var fingerprintRe = regexp.MustCompile(`[0-9A-Fa-f]{40}`)

// parseFingerprint extracts the 40-hex-char V4 fingerprint from CLI output.
// The newest (last) match wins — generate-key prints exactly one, but sync
// banners in future CLI versions might add more.
func parseFingerprint(stdout string) (string, error) {
	matches := fingerprintRe.FindAllString(stdout, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no GPG fingerprint found in CLI stdout")
	}
	return strings.ToUpper(matches[len(matches)-1]), nil
}

// checkGPGInstalled verifies the stock `gpg` binary is on PATH. Fails the
// test if not — the harness's setup.sh is expected to have installed it
// (macOS runners typically already have GnuPG via Homebrew; Linux CI
// installs it in setup.sh).
func checkGPGInstalled(t *testing.T) {
	t.Helper()
	cmd := exec.Command("gpg", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gpg CLI not installed or not on PATH: %v\n%s", err, string(out))
	}
}

// dumpFailureContext is the suite's mirror of the age/ssh failure dumpers.
func dumpFailureContext(t *testing.T, env *shared.TestEnv, cliBuf *lockedBuffer) {
	t.Helper()
	t.Log("[E2E] ─── failure context ────────────────────────────────────")
	if env != nil {
		t.Logf("[E2E] env: cli=%s config=%s sim=%s data=%s",
			env.CLIPath, env.ConfigDir, env.SimulatorID, env.DataDir)
	}
	shared.DumpCoordinationDir(t)
	if cliBuf != nil && cliBuf.Len() > 0 {
		snap := cliBuf.Snapshot()
		t.Logf("[E2E] CLI buffer (%d bytes):", snap.Len())
		shared.LogE2ELines(t, "nb", snap)
	}
	logPath := os.Getenv("SIM_LOG_FILE")
	if logPath == "" {
		logPath = "/tmp/nb-gpg-sim-log"
	}
	if data, err := os.ReadFile(logPath); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		start := len(lines) - 200
		if start < 0 {
			start = 0
		}
		t.Logf("[E2E] device log %s (last %d lines):", logPath, len(lines)-start)
		for _, line := range lines[start:] {
			t.Logf("[E2E][sim] %s", line)
		}
	} else {
		t.Logf("[E2E] device log %s unavailable: %v", logPath, err)
	}
	t.Log("[E2E] ─── end failure context ────────────────────────────────")
}
