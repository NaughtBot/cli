//go:build integration

// Package age — end-to-end test for NaughtBot's age encryption flow.
//
// Per-test sequence (single TestNBAge):
//
//	Step 1: dump environment.
//	Step 2: ensure CLI is logged in (re-uses prior login state).
//	Step 3: run `nb age keygen --label <unique>` with concurrent
//	        ApproveRequest(enroll); parse `age1nb1…` recipient.
//	Step 4: run `nb age identity` (no approval); write identity file.
//	Step 5: write plaintext file; run stock `age -r <recipient> -o
//	        hello.txt.age hello.txt` (no approval — public-key encryption).
//	Step 6: run `age -d -i identity.txt -o decrypted.txt hello.txt.age`
//	        with concurrent ApproveRequest(age_unwrap); age spawns
//	        age-plugin-nb, which issues the iOS unwrap request.
//	Step 7: assert decrypted plaintext matches the original.
//
// Unlike the ssh suite there is no docker dependency — age is all
// file-in/file-out. The test therefore finishes substantially faster than ssh.
package age

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

// TestNBAge exercises the full age encryption/decryption round-trip.
func TestNBAge(t *testing.T) {
	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping age E2E: RUN_NB_E2E != 1")
	}

	env := shared.SetupTestEnv(t)

	// Whole-test deadline. Two iOS approvals back to back (enroll +
	// age_unwrap) plus a stock-age round-trip. 6 minutes leaves headroom
	// on a slow simulator without dragging if something is wedged.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// ── Step 1 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 1, "dump environment")
	shared.LogEnvDump(t)
	t.Logf("[E2E]   E2E data dir: %s", env.DataDir)
	t.Logf("[E2E]   Config dir:   %s", env.ConfigDir)
	t.Logf("[E2E]   Simulator:    %s", env.SimulatorID)
	t.Logf("[E2E]   CLI path:     %s", env.CLIPath)
	t.Logf("[E2E]   age plugin:   %s", env.AgePlugin)

	// Fresh test → wipe stale approval breadcrumbs but keep relay/login
	// URL files (required by the iOS approver).
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

	// Sanity-check that the stock age binary and age-plugin-nb are
	// present before we spend minutes driving the iOS approver.
	checkAgeInstalled(t)
	pluginPath := ensureAgePluginBinary(t, env)
	t.Logf("[E2E] age-plugin-nb: %s", pluginPath)

	// ── Step 2 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 2, "ensure CLI is logged in (RunLoginFlowIfNeeded)")
	env.RunLoginFlowIfNeeded(t)

	// Re-sync devices with NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1 for the
	// same reason the ssh suite does — the login suite's post-login sync
	// runs without acceptance and can leave the device list empty.
	shared.LogStep(t, 2, "re-sync devices with NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1")
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	syncCmd := exec.CommandContext(ctx, env.CLIPath, "keys", "--sync")
	syncCmd.Env = cliEnv(env)
	syncOut, syncErr := syncCmd.CombinedOutput()
	t.Logf("[E2E] keys --sync output:\n%s", strings.TrimSpace(string(syncOut)))
	if syncErr != nil {
		t.Fatalf("keys --sync failed: %v", syncErr)
	}

	// Per-test working directory for the plaintext / ciphertext / identity.
	workDir := t.TempDir()
	plaintextPath := filepath.Join(workDir, "hello.txt")
	ciphertextPath := filepath.Join(workDir, "hello.txt.age")
	decryptedPath := filepath.Join(workDir, "decrypted.txt")
	identityPath := filepath.Join(workDir, "identity.txt")
	plaintext := fmt.Sprintf("hello from the nb age e2e at %s\n", time.Now().Format(time.RFC3339Nano))

	// ── Step 3 ─────────────────────────────────────────────────────────
	keyLabel := fmt.Sprintf("age-e2e-%d", time.Now().UnixNano())
	shared.LogStep(t, 3, "run `nb age keygen --label %s`", keyLabel)
	recipient, keygenOut, keygenErr := runKeygenWithApproval(ctx, t, env, keyLabel)
	if keygenErr != nil {
		dumpFailureContext(t, env, keygenOut)
		t.Fatalf("age keygen failed: %v", keygenErr)
	}
	t.Logf("[E2E] age recipient: %s", recipient)
	if !strings.HasPrefix(recipient, "age1nb") {
		dumpFailureContext(t, env, keygenOut)
		t.Fatalf("unexpected recipient prefix: %q", recipient)
	}

	// ── Step 4 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 4, "run `nb age identity` and write identity file")
	identityStr, idCLIOut, idErr := runAgeIdentity(ctx, t, env)
	if idErr != nil {
		dumpFailureContext(t, env, idCLIOut)
		t.Fatalf("age identity failed: %v", idErr)
	}
	if !strings.HasPrefix(identityStr, "AGE-PLUGIN-NB-") {
		dumpFailureContext(t, env, idCLIOut)
		t.Fatalf("unexpected identity prefix: %q", identityStr)
	}
	if err := os.WriteFile(identityPath, []byte(identityStr+"\n"), 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	t.Logf("[E2E] identity file: %s", identityPath)

	// ── Step 5 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 5, "encrypt plaintext with stock `age -r <recipient>`")
	if err := os.WriteFile(plaintextPath, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	// Public-key encryption — no iOS approval needed. Age derives an
	// ephemeral X25519 key on the fly and writes the stanza.
	encryptCmd := exec.CommandContext(ctx, "age", "-r", recipient, "-o", ciphertextPath, plaintextPath)
	encryptCmd.Env = ageEnv(env)
	encryptOut, err := encryptCmd.CombinedOutput()
	if err != nil {
		t.Logf("[E2E] age encrypt output:\n%s", string(encryptOut))
		// Mirror the other failure paths: surface simulator + host state
		// so a post-mortem has the same context as approval-side failures.
		encryptBuf := &lockedBuffer{}
		_, _ = encryptBuf.Write(encryptOut)
		dumpFailureContext(t, env, encryptBuf)
		t.Fatalf("age encrypt failed: %v", err)
	}
	if st, err := os.Stat(ciphertextPath); err != nil {
		encryptBuf := &lockedBuffer{}
		_, _ = encryptBuf.Write(encryptOut)
		dumpFailureContext(t, env, encryptBuf)
		t.Fatalf("ciphertext missing post-encrypt: %v", err)
	} else if st.Size() == 0 {
		encryptBuf := &lockedBuffer{}
		_, _ = encryptBuf.Write(encryptOut)
		dumpFailureContext(t, env, encryptBuf)
		t.Fatalf("ciphertext %s is empty", ciphertextPath)
	}

	// ── Step 6 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 6, "decrypt with `age -d -i %s` + ApproveRequest(age_unwrap)", identityPath)
	decryptBuf, decryptErr := runDecryptWithApproval(ctx, t, env, identityPath, ciphertextPath, decryptedPath)
	if decryptErr != nil {
		dumpFailureContext(t, env, decryptBuf)
		t.Fatalf("age decrypt failed: %v", decryptErr)
	}

	// ── Step 7 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 7, "assert decrypted plaintext matches original")
	got, err := os.ReadFile(decryptedPath)
	if err != nil {
		dumpFailureContext(t, env, decryptBuf)
		t.Fatalf("read decrypted file: %v", err)
	}
	if string(got) != plaintext {
		dumpFailureContext(t, env, decryptBuf)
		t.Fatalf("decrypted content mismatch\n want: %q\n got:  %q", plaintext, string(got))
	}

	// ── Cleanup ────────────────────────────────────────────────────────
	// Best-effort, per the spec. The iOS-side key remains enrolled.
	for _, p := range []string{plaintextPath, ciphertextPath, decryptedPath, identityPath} {
		if err := removeIfExists(p); err != nil {
			t.Logf("[E2E] cleanup: remove %s: %v", p, err)
		}
	}

	// ── Success banner ─────────────────────────────────────────────────
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════╗")
	t.Log("║                     AGE E2E PASSED                           ║")
	t.Log("║  keygen → encrypt → decrypt → plaintext round-trip OK        ║")
	t.Log("╚══════════════════════════════════════════════════════════════╝")
}

// runKeygenWithApproval spawns `nb age keygen` and in parallel drives
// ApproveRequest("enroll"). Mirrors ssh's runEnrollWithApproval.
func runKeygenWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	label string,
) (recipient string, cliBuf *lockedBuffer, err error) {
	t.Helper()

	args := []string{"age", "keygen", "--label", label}
	cliBuf = &lockedBuffer{}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, args...)
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb", nil))
	cmd.Stderr = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s %s", env.CLIPath, strings.Join(args, " "))

	if startErr := cmd.Start(); startErr != nil {
		return "", cliBuf, fmt.Errorf("start `nb age keygen`: %w", startErr)
	}
	t.Logf("[E2E] keygen CLI pid=%d", cmd.Process.Pid)

	cliDone := make(chan error, 1)
	go func() { cliDone <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// Drive the iOS approver in parallel. Keygen is an enrollment flow;
	// the iOS side surfaces it as signingType="enroll" (same identifier
	// the ssh enrollment uses). The UI test does not key off the string,
	// but we pass "enroll" to keep log correlation honest.
	approvalCtx, approvalCancel := context.WithCancel(ctx)
	defer approvalCancel()
	var (
		approvalErr error
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, "enroll")
	}()

	select {
	case waitErr := <-cliDone:
		wg.Wait()
		if waitErr != nil {
			return "", cliBuf, fmt.Errorf("CLI exited with error: %w (approval err: %v)", waitErr, approvalErr)
		}
		if approvalErr != nil {
			t.Logf("[E2E] keygen CLI exited 0 but approver returned: %v", approvalErr)
		}
		rec, parseErr := parseRecipient(cliBuf.String())
		if parseErr != nil {
			return "", cliBuf, fmt.Errorf("parse recipient: %w", parseErr)
		}
		return rec, cliBuf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return "", cliBuf, fmt.Errorf("ctx done while waiting for keygen CLI: %w", ctx.Err())
	}
}

// runAgeIdentity runs `nb age identity` (no iOS approval needed — the
// CLI only reads local config to print the identity string).
func runAgeIdentity(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
) (identity string, cliBuf *lockedBuffer, err error) {
	t.Helper()
	cliBuf = &lockedBuffer{}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, "age", "identity")
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb", nil))
	cmd.Stderr = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s age identity", env.CLIPath)
	if runErr := cmd.Run(); runErr != nil {
		return "", cliBuf, fmt.Errorf("nb age identity: %w", runErr)
	}
	id, parseErr := parseIdentity(cliBuf.String())
	if parseErr != nil {
		return "", cliBuf, fmt.Errorf("parse identity: %w", parseErr)
	}
	return id, cliBuf, nil
}

// runDecryptWithApproval drives `age -d -i identity ciphertext > decrypted`
// alongside ApproveRequest("age_unwrap"). Mirrors ssh's runSSHWithApproval.
func runDecryptWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	identityPath, ciphertextPath, decryptedPath string,
) (*lockedBuffer, error) {
	t.Helper()
	args := []string{"-d", "-i", identityPath, "-o", decryptedPath, ciphertextPath}
	buf := &lockedBuffer{}
	cmd := exec.CommandContext(ctx, "age", args...)
	cmd.Env = ageEnv(env)
	cmd.Stdout = io.MultiWriter(buf, shared.TeeToLog(t, "age", nil))
	cmd.Stderr = io.MultiWriter(buf, shared.TeeToLog(t, "age:err", nil))
	t.Logf("[E2E] launching: age %s", strings.Join(args, " "))
	if err := cmd.Start(); err != nil {
		return buf, fmt.Errorf("start age -d: %w", err)
	}
	t.Logf("[E2E] age pid=%d", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
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
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, "age_unwrap")
	}()

	select {
	case err := <-done:
		wg.Wait()
		if err != nil {
			return buf, fmt.Errorf("age -d exited with error: %w (approval err: %v)", err, approvalErr)
		}
		if approvalErr != nil {
			t.Logf("[E2E] age exited 0 but approver returned: %v", approvalErr)
		}
		return buf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return buf, fmt.Errorf("ctx done while waiting for age -d: %w", ctx.Err())
	}
}
