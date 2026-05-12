//go:build integration

// Package age — helpers for the age encryption e2e suite. Mirrors the shape
// of the ssh suite helpers: anything that is not the happy-path test body
// lives here.
package age

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

// repoRoot resolves the monorepo root by walking up from the suite directory.
// Honours REPO_ROOT for callers that run the tests from a non-canonical cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("REPO_ROOT"); v != "" {
		return v
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("repoRoot: getwd: %v", err)
	}
	// tests/integration/age -> tests/integration -> tests -> repo root
	return filepath.Clean(filepath.Join(cwd, "..", "..", ".."))
}

// cliEnv is the env every CLI subprocess inherits — same shape as the ssh
// suite's cliEnv. NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1 is required because
// the simulator approver returns software-only attestation, and several CLI
// entry points transparently re-sync device metadata before proceeding.
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

// ageEnv is the env for the stock `age` binary when it spawns
// age-plugin-nb. We point PATH at the harness-provided plugin directory
// first so age-plugin-nb resolves to the freshly-built binary, and
// propagate NB_CONFIG_DIR so the plugin reads the CLI config that this
// test's enrollment populated.
func ageEnv(env *shared.TestEnv) []string {
	out := cliEnv(env)
	if env.AgePlugin != "" {
		pluginDir := filepath.Dir(env.AgePlugin)
		out = prependPath(out, pluginDir)
	}
	return out
}

// prependPath returns a copy of env with `dir` prepended to the PATH entry.
// If PATH is absent, it is inserted. Order is important — age walks PATH in
// order when resolving plugins.
func prependPath(env []string, dir string) []string {
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			out = append(out, "PATH="+dir+string(os.PathListSeparator)+strings.TrimPrefix(kv, "PATH="))
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, "PATH="+dir)
	}
	return out
}

// lockedBuffer mirrors the ssh suite helper: a mutex-guarded bytes.Buffer
// safe for concurrent writes from exec.Cmd's stdout/stderr drain goroutines.
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

// removeIfExists is a tiny convenience for cleanup paths that should not
// fail when the file is already gone.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// recipientRe matches the NaughtBot age recipient string on stdout. The CLI
// prints the recipient on stdout after `nb age keygen` succeeds; the
// informational banner lands on stderr so the recipient is the sole non-blank
// stdout line in the happy path. The regex is permissive to tolerate that
// future CLI versions may wrap or prefix the line.
var recipientRe = regexp.MustCompile(`age1nb[a-z0-9]+`)

// parseRecipient extracts the age recipient string ("age1nb…") from the
// CLI stdout produced by `nb age keygen`. When multiple recipients are
// present (e.g. previously enrolled keys echoed in a future banner), the
// newest — last — match wins, since keygen prints exactly one.
func parseRecipient(stdout string) (string, error) {
	matches := recipientRe.FindAllString(stdout, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no age recipient found in CLI stdout")
	}
	return matches[len(matches)-1], nil
}

// identityRe matches an NaughtBot age identity string ("AGE-PLUGIN-NB-…").
// Identities are emitted by `nb age identity` on stdout in uppercase.
var identityRe = regexp.MustCompile(`AGE-PLUGIN-NB-[A-Z0-9]+`)

// parseIdentity extracts an identity string from the CLI stdout produced by
// `nb age identity`. Same tie-breaking rule as parseRecipient.
func parseIdentity(stdout string) (string, error) {
	matches := identityRe.FindAllString(stdout, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no age identity found in CLI stdout")
	}
	return matches[len(matches)-1], nil
}

// checkAgeInstalled verifies the stock `age` binary is on PATH. Fails the
// test if not — the harness's setup.sh is expected to have installed it.
func checkAgeInstalled(t *testing.T) {
	t.Helper()
	cmd := exec.Command("age", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("age CLI not installed or not on PATH: %v\n%s", err, string(out))
	}
}

// ensureAgePluginBinary makes sure age-plugin-nb is discoverable by the
// stock age binary. setup.sh publishes AGE_PLUGIN pointing at the built
// binary; we verify existence so a stale env.sh fails fast.
func ensureAgePluginBinary(t *testing.T, env *shared.TestEnv) string {
	t.Helper()
	if env.AgePlugin == "" {
		// Fall back to the canonical build output so a manual run without
		// AGE_PLUGIN still works.
		fallback := filepath.Join(repoRoot(t), "age-plugin-nb")
		if _, err := os.Stat(fallback); err != nil {
			t.Fatalf("age-plugin-nb not found: AGE_PLUGIN empty and fallback %s missing (%v)", fallback, err)
		}
		return fallback
	}
	if _, err := os.Stat(env.AgePlugin); err != nil {
		t.Fatalf("AGE_PLUGIN=%s: %v", env.AgePlugin, err)
	}
	return env.AgePlugin
}

// dumpFailureContext is the suite's mirror of the ssh failure dumper.
func dumpFailureContext(t *testing.T, env *shared.TestEnv, cliBuf *lockedBuffer) {
	t.Helper()
	t.Log("[E2E] ─── failure context ────────────────────────────────────")
	if env != nil {
		t.Logf("[E2E] env: cli=%s config=%s sim=%s data=%s age-plugin=%s",
			env.CLIPath, env.ConfigDir, env.SimulatorID, env.DataDir, env.AgePlugin)
	}
	shared.DumpCoordinationDir(t)
	if cliBuf != nil && cliBuf.Len() > 0 {
		snap := cliBuf.Snapshot()
		t.Logf("[E2E] CLI buffer (%d bytes):", snap.Len())
		shared.LogE2ELines(t, "nb", snap)
	}
	logPath := os.Getenv("SIM_LOG_FILE")
	if logPath == "" {
		logPath = "/tmp/nb-age-sim-log"
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
