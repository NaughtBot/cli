//go:build integration

// Package ssh — end-to-end tests for NaughtBot's SSH security key flow.
//
// Per-test sequence:
//
//	Step 1: dump environment.
//	Step 2: ensure CLI is logged in (re-uses prior login state).
//	Step 3: ensure libnb-sk.dylib exists, copy to per-test tempdir.
//	Step 4: launch goroutine driving ApproveRequest("ssh_enrollment").
//	Step 5: run `nb ssh --generate-key -t <type>` and assert success.
//	Step 6: read the generated pubkey file.
//	Step 7: append pubkey to docker nb-ssh-server authorized_keys.
//	Step 8: launch goroutine driving ApproveRequest("ssh_sign").
//	Step 9: run `ssh -I <dylib> -i <priv> -p 2222 testuser@127.0.0.1 whoami`,
//	         assert stdout == "testuser\n".
//	Step 10: best-effort cleanup of the generated key on disk.
//
// Both tests share the same skeleton and only differ in --type and the
// expected sk- pubkey prefix.
package ssh

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/naughtbot/cli/tests/integration/shared"
)

// runSSHFlow is the shared body of the per-algorithm tests. Splitting on
// algorithm + label inside one helper keeps the test bodies readable and
// guarantees the two tests can never drift apart by accident.
func runSSHFlow(t *testing.T, algorithm string) {
	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping ssh E2E: RUN_NB_E2E != 1")
	}

	env := shared.SetupTestEnv(t)

	// Whole-test deadline. The flow runs two iOS approvals back to back,
	// each of which can take 30-60s on a slow simulator, plus an
	// end-to-end ssh handshake. 8 minutes is the same shape as login.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// ── Step 1 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 1, "dump environment")
	shared.LogEnvDump(t)
	t.Logf("[E2E]   E2E data dir: %s", env.DataDir)
	t.Logf("[E2E]   Config dir:   %s", env.ConfigDir)
	t.Logf("[E2E]   Simulator:    %s", env.SimulatorID)
	t.Logf("[E2E]   CLI path:     %s", env.CLIPath)
	t.Logf("[E2E]   SSH host/port: %s:%s", env.SSHHost, env.SSHPort)

	// Fresh test → wipe stale approval breadcrumbs but keep relay/login
	// URL files (they are required by the iOS approver).
	for _, f := range []string{
		"approval_complete.txt",
		"approval_error.txt",
		"approval_request.txt",
		"approval_auto_approved.txt",
		"sekey_debug.txt",
		"callback_debug.txt",
	} {
		if err := shared.ClearE2EFile(f); err != nil {
			t.Fatalf("ClearE2EFile(%s): %v", f, err)
		}
	}

	// ── Step 2 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 2, "ensure CLI is logged in (RunLoginFlowIfNeeded)")
	env.RunLoginFlowIfNeeded(t)

	// Step 2.5: re-sync devices. The login suite's terminal `keys --sync`
	// runs without NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1, so under
	// software-only attestation it leaves profile.user_account.devices ==
	// nil and downstream commands trip cfg.IsLoggedIn() == false. Run the
	// sync again with our env (which DOES set acceptance) so the device
	// list is repopulated. This is idempotent — running it when devices
	// is already populated is a no-op modulo log lines.
	shared.LogStep(t, 2, "re-sync devices with NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1")
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	syncCmd := exec.CommandContext(ctx, env.CLIPath, "keys", "--sync")
	syncCmd.Env = cliEnv(env)
	syncOut, syncErr := syncCmd.CombinedOutput()
	t.Logf("[E2E] keys --sync output:\n%s", strings.TrimSpace(string(syncOut)))
	if syncErr != nil {
		t.Fatalf("keys --sync failed: %v", syncErr)
	}

	// ── Step 3 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 3, "ensure libnb-sk.dylib exists + copy to tempdir")
	canonical := ensureSKProviderDylib(t)
	dylibDir := t.TempDir()
	dylibPath := copyDylibToTempdir(t, canonical, dylibDir)
	if st, err := os.Stat(dylibPath); err != nil {
		t.Fatalf("dylib copy missing post-copy: %v", err)
	} else {
		t.Logf("[E2E] dylib ready: %s (%d bytes)", dylibPath, st.Size())
	}

	// Per-test key paths — keep them in their own dir so we can delete the
	// whole tree at the end without hitting unrelated files.
	keyDir := t.TempDir()
	keyLabel := fmt.Sprintf("ssh-e2e-%s-%d", algorithm, time.Now().UnixNano())
	keyPath := filepath.Join(keyDir, "id_nb")
	pubKeyPath := keyPath + ".pub"

	// Resolve the docker container that hosts sshd. We do this early so
	// the test fails fast with a clear "no container" error rather than
	// after the slow iOS enrollment.
	container := resolveSSHContainer(t)
	t.Logf("[E2E] ssh-server container: %s", container)

	// ── Step 4 + 5 ─────────────────────────────────────────────────────
	shared.LogStep(t, 4, "launch ApproveRequest(ssh_enrollment) goroutine")
	shared.LogStep(t, 5, "run `nb ssh --generate-key -t %s -n %s -o %s`", algorithm, keyLabel, keyPath)

	enrollOut, enrollErr := runEnrollWithApproval(ctx, t, env, algorithm, keyLabel, keyPath)
	if enrollErr != nil {
		dumpFailureContext(t, env, enrollOut)
		t.Fatalf("enrollment failed: %v", enrollErr)
	}

	// Belt-and-braces — runEnrollWithApproval already covers the happy
	// path, but verify both files actually landed.
	if _, err := os.Stat(keyPath); err != nil {
		dumpFailureContext(t, env, enrollOut)
		t.Fatalf("private key missing after enrollment: %v", err)
	}
	if _, err := os.Stat(pubKeyPath); err != nil {
		dumpFailureContext(t, env, enrollOut)
		t.Fatalf("public key missing after enrollment: %v", err)
	}

	// ── Step 6 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 6, "read generated pubkey from %s", pubKeyPath)
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		dumpFailureContext(t, env, enrollOut)
		t.Fatalf("read pubkey: %v", err)
	}
	pubKeyLine := strings.TrimSpace(string(pubKeyBytes))
	t.Logf("[E2E] pubkey: %s", firstLine(pubKeyLine))
	if err := keyTypeMatch(pubKeyLine, algorithm); err != nil {
		dumpFailureContext(t, env, enrollOut)
		t.Fatalf("pubkey type mismatch: %v", err)
	}

	// ── Step 7 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 7, "install pubkey on docker ssh-server")
	installAuthorizedKey(t, container, pubKeyLine)

	// ── Step 8 + 9 ─────────────────────────────────────────────────────
	shared.LogStep(t, 8, "launch ApproveRequest(ssh_sign) goroutine")
	shared.LogStep(t, 9, "run `ssh -I %s -i %s -p %s testuser@%s whoami`", dylibPath, keyPath, env.SSHPort, env.SSHHost)

	sshOut, sshErr := runSSHWithApproval(ctx, t, env, dylibPath, keyPath)
	if sshErr != nil {
		dumpFailureContext(t, env, sshOut)
		t.Fatalf("ssh failed: %v", sshErr)
	}
	got := strings.TrimSpace(sshOut.String())
	// `ssh ... whoami` may emit warnings (e.g. host key, banner). Look at
	// the last non-empty line for the actual command output.
	last := lastNonEmptyLine(got)
	if last != "testuser" {
		dumpFailureContext(t, env, sshOut)
		t.Fatalf("ssh whoami output mismatch: want %q, got last line %q (full output: %q)", "testuser", last, got)
	}
	t.Logf("[E2E] ssh whoami = %q", last)

	// ── Step 10 ────────────────────────────────────────────────────────
	shared.LogStep(t, 10, "cleanup: remove on-disk key files (%s, %s)", keyPath, pubKeyPath)
	// Cleanup is best-effort — we never fail the test for cleanup issues
	// (per the task brief). The on-iOS key remains in the NaughtBot config;
	// the CLI does not currently expose `ssh --delete-key`, so removal of
	// the iOS-side key is a no-op until that subcommand exists.
	if err := removeIfExists(keyPath); err != nil {
		t.Logf("[E2E] cleanup: remove %s: %v", keyPath, err)
	}
	if err := removeIfExists(pubKeyPath); err != nil {
		t.Logf("[E2E] cleanup: remove %s: %v", pubKeyPath, err)
	}

	// ── Success banner ─────────────────────────────────────────────────
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║                  SSH E2E PASSED (%-8s)                  ║", algorithm)
	t.Log("║  enroll → install on sshd → ssh whoami round-trip OK         ║")
	t.Log("╚══════════════════════════════════════════════════════════════╝")
}

// TestNBSSHEcdsa exercises the ECDSA-P256 flow.
func TestNBSSHEcdsa(t *testing.T) {
	runSSHFlow(t, "ecdsa")
}

// TestNBSSHEd25519 exercises the Ed25519 flow.
func TestNBSSHEd25519(t *testing.T) {
	runSSHFlow(t, "ed25519")
}

// runEnrollWithApproval spawns `nb ssh --generate-key` and, in parallel,
// drives the iOS approver via ApproveRequest. The CLI blocks on iOS approval;
// when the goroutine completes, the CLI returns and we observe its exit. We
// own waiting for both sides so neither one can leak past the test.
func runEnrollWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	algorithm, keyLabel, keyPath string,
) (*lockedBuffer, error) {
	t.Helper()

	args := []string{
		"ssh",
		"--generate-key",
		"-n", keyLabel,
		"-t", algorithm,
		"-o", keyPath,
	}
	cliBuf := &lockedBuffer{}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, args...)
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb", nil))
	cmd.Stderr = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s %s", env.CLIPath, strings.Join(args, " "))

	if err := cmd.Start(); err != nil {
		return cliBuf, fmt.Errorf("start `nb ssh --generate-key`: %w", err)
	}
	t.Logf("[E2E] enroll CLI pid=%d", cmd.Process.Pid)

	// Make sure we never leak the child if anything throws.
	cliDone := make(chan error, 1)
	go func() { cliDone <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// Drive the iOS approver in parallel. ApproveRequest blocks until the
	// XCUITest exits (which itself happens after the in-app auto-approve
	// writes approval_complete.txt). Run it concurrently and wait for both
	// completion signals before returning.
	approvalCtx, approvalCancel := context.WithCancel(ctx)
	defer approvalCancel()
	var (
		approvalErr error
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, "ssh_enrollment")
	}()

	// Wait for the CLI; if it dies before approval completes, fail. The
	// CLI completes only after the iOS approver returns success, so the
	// expected order is: approver writes approval_complete.txt → CLI
	// receives the response → CLI exits 0 → wg drains as the XCUITest
	// process exits.
	select {
	case err := <-cliDone:
		// CLI exited. Wait for the approval goroutine to drain too so its
		// xcodebuild process is fully reaped.
		wg.Wait()
		if err != nil {
			return cliBuf, fmt.Errorf("CLI exited with error: %w (approval err: %v)", err, approvalErr)
		}
		if approvalErr != nil {
			// The CLI may exit 0 because the approver already wrote success
			// before the XCUITest process formally returned, but if the
			// approver itself errored, we want to see it.
			t.Logf("[E2E] enroll CLI exited 0 but approver returned: %v", approvalErr)
		}
		return cliBuf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return cliBuf, fmt.Errorf("ctx done while waiting for enroll CLI: %w", ctx.Err())
	}
}

// runSSHWithApproval drives `ssh -I <dylib> -i <priv> -p <port> user@host whoami`
// alongside an iOS ssh_sign approval. Mirrors runEnrollWithApproval; kept as
// its own function because the args + env shape is meaningfully different.
func runSSHWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	dylibPath, keyPath string,
) (*lockedBuffer, error) {
	t.Helper()

	args := []string{
		"-i", keyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "SecurityKeyProvider=" + dylibPath,
		"-o", "BatchMode=yes",
		"-p", env.SSHPort,
		"testuser@" + env.SSHHost,
		"whoami",
	}
	sshBuf := &lockedBuffer{}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	// Pass NB_CONFIG_DIR explicitly so the sk-provider dylib (which
	// runs inside ssh's address space) reads the same CLI config that the
	// enrollment wrote into.
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(sshBuf, shared.TeeToLog(t, "ssh", nil))
	cmd.Stderr = io.MultiWriter(sshBuf, shared.TeeToLog(t, "ssh:err", nil))
	t.Logf("[E2E] launching: ssh %s", strings.Join(args, " "))

	if err := cmd.Start(); err != nil {
		return sshBuf, fmt.Errorf("start ssh: %w", err)
	}
	t.Logf("[E2E] ssh pid=%d", cmd.Process.Pid)

	sshDone := make(chan error, 1)
	go func() { sshDone <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	approvalCtx, approvalCancel := context.WithCancel(ctx)
	defer approvalCancel()
	var (
		approvalErr error
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, "ssh_sign")
	}()

	select {
	case err := <-sshDone:
		wg.Wait()
		if err != nil {
			return sshBuf, fmt.Errorf("ssh exited with error: %w (approval err: %v)", err, approvalErr)
		}
		if approvalErr != nil {
			t.Logf("[E2E] ssh exited 0 but approver returned: %v", approvalErr)
		}
		return sshBuf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return sshBuf, fmt.Errorf("ctx done while waiting for ssh: %w", ctx.Err())
	}
}

// lastNonEmptyLine returns the last line of s that is not blank after
// trimming. We use it to skip over ssh's stderr-noise prefix (banner,
// host-key warnings) and look at the actual command output.
func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}
