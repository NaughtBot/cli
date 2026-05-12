//go:build integration

// Package ssh — helpers shared by the ECDSA + Ed25519 SSH e2e tests.
//
// These helpers exist so the per-algorithm tests stay short and read like a
// step list. Anything that involves the build system, docker, the sk-provider
// dylib, or failure-context dumping lives here.
package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
	// tests/integration/ssh -> tests/integration -> tests -> repo root
	return filepath.Clean(filepath.Join(cwd, "..", "..", ".."))
}

// ensureSKProviderDylib makes sure libnb-sk.dylib exists on disk and
// returns its absolute path. We honour SK_DYLIB if setup.sh published one,
// then fall back to the canonical sk-provider dir at the cli repo root,
// and finally to building it via `make build DEV=1` from there.
//
// macOS caches dylibs by absolute path within a process, which has bitten
// every previous incarnation of this suite. The caller is expected to copy
// the returned path into a per-test tempdir before passing it to ssh.
func ensureSKProviderDylib(t *testing.T) string {
	t.Helper()

	// Preferred: setup.sh published SK_DYLIB.
	if v := os.Getenv("SK_DYLIB"); v != "" {
		if _, err := os.Stat(v); err == nil {
			shared.LogStep(t, 0, "ensureSKProviderDylib: using SK_DYLIB=%s", v)
			return v
		}
		t.Logf("[E2E] SK_DYLIB=%s not on disk, falling back to canonical path", v)
	}

	root := repoRoot(t)
	canonical := filepath.Join(root, "sk-provider", "libnb-sk.dylib")
	if _, err := os.Stat(canonical); err == nil {
		shared.LogStep(t, 0, "ensureSKProviderDylib: found canonical %s", canonical)
		return canonical
	}

	shared.LogStep(t, 0, "ensureSKProviderDylib: dylib missing, building via `make build DEV=1`")
	cmd := exec.Command("make", "-C", root, "build", "DEV=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ensureSKProviderDylib: build failed: %v\n%s", err, string(out))
	}
	if _, err := os.Stat(canonical); err != nil {
		t.Fatalf("ensureSKProviderDylib: build succeeded but %s still missing: %v\n%s", canonical, err, string(out))
	}
	return canonical
}

// copyDylibToTempdir copies src to <tempdir>/libnb-sk.dylib. The point
// is to avoid macOS's per-path dylib cache: ssh keeps re-resolving the same
// absolute SecurityKeyProvider, and after a rebuild the cached image inside
// ssh's address space goes stale. A fresh per-test path side-steps it.
func copyDylibToTempdir(t *testing.T, src, dstDir string) string {
	t.Helper()
	dst := filepath.Join(dstDir, "libnb-sk.dylib")
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("copyDylibToTempdir: open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("copyDylibToTempdir: create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copyDylibToTempdir: copy: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("copyDylibToTempdir: close: %v", err)
	}
	shared.LogStep(t, 0, "copyDylibToTempdir: %s -> %s", src, dst)
	return dst
}

// resolveSSHContainer returns the docker container name (or id) for the
// nb-ssh-server service. Honours NB_SSH_CONTAINER, then queries
// `docker compose ps -q`. Failing both, the test is marked failed via
// t.Fatalf; we never silently fall back to a hardcoded name.
//
// The compose stack is owned by the sibling `core/` checkout (see
// `setup.sh`/`teardown.sh` and `nb_workspace_root` in lib/common.sh); we
// resolve it via WORKSPACE_ROOT, falling back to `<cli>/..` for the
// canonical workspace layout. Pointing at the cli repo would let Docker
// Compose search the cli dir and its parents, which is fragile and depends
// on the host's `compose.yaml` discovery order.
func resolveSSHContainer(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("NB_SSH_CONTAINER"); v != "" {
		return v
	}
	composeDir := os.Getenv("WORKSPACE_ROOT")
	if composeDir == "" {
		composeDir = filepath.Join(repoRoot(t), "..")
	}
	composeDir = filepath.Join(composeDir, "core")
	cmd := exec.Command("docker", "compose",
		"--profile", "nb-e2e-testing",
		"ps", "-q", "nb-ssh-server")
	cmd.Dir = composeDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("resolveSSHContainer: docker compose ps failed (cwd=%s): %v", composeDir, err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		t.Fatalf("resolveSSHContainer: no container id for nb-ssh-server (is the docker stack up at %s?)", composeDir)
	}
	return id
}

// installAuthorizedKey appends pubKey to the testuser authorized_keys file
// inside the running ssh-server container. The linuxserver/openssh-server
// image places testuser's home at /config/, so authorized_keys lives at
// /config/.ssh/authorized_keys. We chmod/chown to be safe even though the
// image creates them with the right ownership at startup.
func installAuthorizedKey(t *testing.T, container, pubKey string) {
	t.Helper()
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		t.Fatalf("installAuthorizedKey: empty pubKey")
	}
	// Use heredoc-via-stdin so we don't need to escape the key contents
	// for the shell. Print the key with `cat`, append via a single sh -c.
	script := `set -e
mkdir -p /config/.ssh
cat >> /config/.ssh/authorized_keys
chown -R testuser:users /config/.ssh
chmod 700 /config/.ssh
chmod 600 /config/.ssh/authorized_keys
`
	cmd := exec.Command("docker", "exec", "-i", container, "sh", "-c", script)
	cmd.Stdin = strings.NewReader(pubKey + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installAuthorizedKey: %v\n%s", err, string(out))
	}
	shared.LogStep(t, 0, "installAuthorizedKey: appended pubkey to %s:/config/.ssh/authorized_keys", container)
}

// cliEnv is the env every CLI subprocess inherits — same shape as login's
// cliEnv, kept private to the suite so additions don't leak.
//
// We export NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1 because the simulator
// approver returns software-only attestation, and a bare `nb ssh
// --generate-key` invocation transparently calls keys --sync to refresh the
// device list before enrollment. Without acceptance the sync rejects the
// device and wipes profile.user_account.devices, leaving the next CLI step
// staring at "not logged in".
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

// lockedBuffer mirrors login/login_e2e_test.go's helper: a mutex-guarded
// bytes.Buffer safe for concurrent writes from exec.Cmd's stdout/stderr
// drain goroutines, with a Snapshot() that the dump path can read without
// racing live writes.
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

// dumpFailureContext is the suite's mirror of login's failure dumper. It
// emits enough state to debug a failure without re-running:
//   - env summary,
//   - coordination dir contents,
//   - full CLI buffer (from the long-running enrollment / signing CLI),
//   - last 200 lines of the simulator log file.
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
		logPath = "/tmp/nb-ssh-sim-log"
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

// keyTypeMatch reports whether the given pubkey line starts with the
// OpenSSH sk- type prefix that corresponds to the requested algorithm. We
// keep this defensive check in helpers because it's used by both tests and
// the spec is the source of truth: ecdsa => sk-ecdsa-sha2-nistp256, ed25519
// => sk-ssh-ed25519.
func keyTypeMatch(pubKeyLine, algorithm string) error {
	want := ""
	switch algorithm {
	case "ecdsa":
		want = "sk-ecdsa-sha2-nistp256@openssh.com"
	case "ed25519":
		want = "sk-ssh-ed25519@openssh.com"
	default:
		return fmt.Errorf("keyTypeMatch: unknown algorithm %q", algorithm)
	}
	if !strings.HasPrefix(strings.TrimSpace(pubKeyLine), want) {
		return fmt.Errorf("expected %s prefix, got: %s", want, firstLine(pubKeyLine))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
