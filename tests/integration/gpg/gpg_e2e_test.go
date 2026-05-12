//go:build integration

// Package gpg — end-to-end test for NaughtBot's GPG signing flow.
//
// Per-subtest sequence (one subtest per algorithm: ecdsa, ed25519):
//
//	Step 1: dump environment.
//	Step 2: ensure CLI is logged in; re-sync devices with acceptance flag.
//	Step 3: run `nb gpg --generate-key --name <n> --email <e>
//	        --type <alg>` with concurrent ApproveRequest(enroll); parse 40-hex
//	        fingerprint from stdout.
//	Step 4: run `nb gpg --export --armor -u <fingerprint>` (no approval —
//	        export is local config read) into an isolated GNUPGHOME via
//	        `gpg --import`.
//	Step 5: write plaintext; run `nb gpg -bsau <fp>` (reads stdin, writes
//	        detached ASCII armor signature on stdout) with concurrent
//	        ApproveRequest(gpg_sign).
//	Step 6: run stock `gpg --verify <sig> <plaintext>` and assert success.
//
// Unlike age this flow exercises *signing*, not decryption — the second iOS
// approval is signingType="gpg_sign" and the preimage is the plaintext file
// contents (exactly the shape git uses to sign commit objects).
package gpg

import (
	"bytes"
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

// TestNBGPG exercises the full GPG enrollment + detached-sign + stock
// `gpg --verify` round-trip on both algorithm variants.
func TestNBGPG(t *testing.T) {
	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping gpg E2E: RUN_NB_E2E != 1")
	}

	env := shared.SetupTestEnv(t)

	checkGPGInstalled(t)

	for _, alg := range []string{"ecdsa", "ed25519"} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			runGPGE2E(t, env, alg)
		})
	}
}

func runGPGE2E(t *testing.T, env *shared.TestEnv, algorithm string) {
	// Whole-subtest deadline. Two back-to-back iOS approvals (enroll +
	// gpg_sign) plus import/verify through stock gpg. 6 minutes matches the
	// age suite — comfortable on a slow simulator.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// ── Step 1 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 1, "dump environment (algorithm=%s)", algorithm)
	shared.LogEnvDump(t)
	t.Logf("[E2E]   E2E data dir: %s", env.DataDir)
	t.Logf("[E2E]   Config dir:   %s", env.ConfigDir)
	t.Logf("[E2E]   Simulator:    %s", env.SimulatorID)
	t.Logf("[E2E]   CLI path:     %s", env.CLIPath)

	// Fresh subtest → wipe stale approval breadcrumbs but keep relay/login
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

	// ── Step 2 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 2, "ensure CLI is logged in (RunLoginFlowIfNeeded)")
	env.RunLoginFlowIfNeeded(t)

	// Re-sync devices with NB_ACCEPT_SOFTWARE_APPROVER_KEYS=1 for the
	// same reason the age/ssh suites do: the login suite's post-login sync
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

	// Per-subtest working directory + isolated GNUPGHOME so stock gpg
	// doesn't touch the developer's real keyring.
	workDir := t.TempDir()
	gnupgHome := filepath.Join(workDir, "gnupg")
	if err := os.MkdirAll(gnupgHome, 0o700); err != nil {
		t.Fatalf("mkdir GNUPGHOME: %v", err)
	}
	plaintextPath := filepath.Join(workDir, "hello.txt")
	signaturePath := filepath.Join(workDir, "hello.txt.asc")
	pubkeyPath := filepath.Join(workDir, "pubkey.asc")
	plaintext := fmt.Sprintf("hello from the nb gpg e2e (%s) at %s\n",
		algorithm, time.Now().Format(time.RFC3339Nano))

	// ── Step 3 ─────────────────────────────────────────────────────────
	keyName := fmt.Sprintf("gpg-e2e-%s", algorithm)
	keyEmail := fmt.Sprintf("gpg-e2e-%s-%d@nb.test", algorithm, time.Now().UnixNano())
	shared.LogStep(t, 3, "run `nb gpg --generate-key --type %s`", algorithm)
	fingerprint, genOut, genErr := runGenerateKeyWithApproval(ctx, t, env, algorithm, keyName, keyEmail)
	if genErr != nil {
		dumpFailureContext(t, env, genOut)
		t.Fatalf("gpg --generate-key failed: %v", genErr)
	}
	t.Logf("[E2E] gpg fingerprint: %s", fingerprint)

	// ── Step 4 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 4, "export public key and import into isolated GNUPGHOME=%s", gnupgHome)
	armoredPub, exportBuf, exportErr := runExportKey(ctx, t, env, fingerprint)
	if exportErr != nil {
		dumpFailureContext(t, env, exportBuf)
		t.Fatalf("gpg --export failed: %v", exportErr)
	}
	if !strings.Contains(armoredPub, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		dumpFailureContext(t, env, exportBuf)
		t.Fatalf("exported key is not ASCII-armored public key:\n%s", armoredPub)
	}
	if err := os.WriteFile(pubkeyPath, []byte(armoredPub), 0o600); err != nil {
		t.Fatalf("write pubkey file: %v", err)
	}

	// --no-autostart keeps gpg from trying to spawn a shared gpg-agent in this
	// sandboxed test session. Without it gpg exits 2 (connection to agent
	// failed) even though the keybox import itself succeeded.
	importCmd := exec.CommandContext(ctx, "gpg", "--no-autostart", "--import", pubkeyPath)
	importCmd.Env = gpgEnv(gnupgHome)
	if importOut, err := importCmd.CombinedOutput(); err != nil {
		t.Logf("[E2E] gpg --import output:\n%s", string(importOut))
		// Surface stock-gpg's own output alongside simulator state so a
		// post-mortem sees both sides (iOS logs + the importer stderr).
		importBuf := &lockedBuffer{}
		_, _ = importBuf.Write(importOut)
		dumpFailureContext(t, env, importBuf)
		t.Fatalf("gpg --import failed: %v", err)
	} else {
		t.Logf("[E2E] gpg --import output:\n%s", strings.TrimSpace(string(importOut)))
	}

	// ── Step 5 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 5, "sign plaintext with `nb gpg -bsau %s`", fingerprint)
	if err := os.WriteFile(plaintextPath, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	signature, signBuf, signErr := runSignWithApproval(ctx, t, env, fingerprint, []byte(plaintext))
	if signErr != nil {
		dumpFailureContext(t, env, signBuf)
		t.Fatalf("gpg sign failed: %v", signErr)
	}
	if !strings.Contains(signature, "-----BEGIN PGP SIGNATURE-----") {
		dumpFailureContext(t, env, signBuf)
		t.Fatalf("signature output is not ASCII-armored:\n%s", signature)
	}
	if err := os.WriteFile(signaturePath, []byte(signature), 0o600); err != nil {
		t.Fatalf("write signature file: %v", err)
	}

	// ── Step 6 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 6, "verify detached signature with stock `gpg --verify`")
	verifyCmd := exec.CommandContext(ctx, "gpg", "--no-autostart", "--verify", signaturePath, plaintextPath)
	verifyCmd.Env = gpgEnv(gnupgHome)
	verifyOut, verifyErr := verifyCmd.CombinedOutput()
	t.Logf("[E2E] gpg --verify output:\n%s", strings.TrimSpace(string(verifyOut)))
	if verifyErr != nil {
		dumpFailureContext(t, env, signBuf)
		t.Fatalf("gpg --verify failed: %v\n%s", verifyErr, string(verifyOut))
	}
	// gpg writes "Good signature from …" on stderr; CombinedOutput merges it.
	if !strings.Contains(string(verifyOut), "Good signature") {
		dumpFailureContext(t, env, signBuf)
		t.Fatalf("gpg --verify did not report a good signature:\n%s", string(verifyOut))
	}

	// ── Cleanup ────────────────────────────────────────────────────────
	// Best-effort. The iOS-side key remains enrolled for this run.
	for _, p := range []string{plaintextPath, signaturePath, pubkeyPath} {
		if err := removeIfExists(p); err != nil {
			t.Logf("[E2E] cleanup: remove %s: %v", p, err)
		}
	}

	// ── Success banner ─────────────────────────────────────────────────
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║               GPG E2E PASSED (%s)%s║", algorithm, strings.Repeat(" ", 29-len(algorithm)))
	t.Log("║  generate → export → import → sign → stock-gpg verify OK     ║")
	t.Log("╚══════════════════════════════════════════════════════════════╝")
}

// runGenerateKeyWithApproval spawns `nb gpg --generate-key` and drives
// ApproveRequest("enroll") in parallel. Mirrors the age suite's keygen helper.
func runGenerateKeyWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	algorithm, name, email string,
) (fingerprint string, cliBuf *lockedBuffer, err error) {
	t.Helper()

	args := []string{
		"gpg",
		"--generate-key",
		"--type", algorithm,
		"--name", name,
		"--email", email,
	}
	cliBuf = &lockedBuffer{}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, args...)
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb", nil))
	cmd.Stderr = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s %s", env.CLIPath, strings.Join(args, " "))

	if startErr := cmd.Start(); startErr != nil {
		return "", cliBuf, fmt.Errorf("start `nb gpg --generate-key`: %w", startErr)
	}
	t.Logf("[E2E] gpg --generate-key CLI pid=%d", cmd.Process.Pid)

	cliDone := make(chan error, 1)
	go func() { cliDone <- cmd.Wait() }()
	defer func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// Approve the enroll transaction in parallel. The iOS side surfaces
	// GPG enrollment as signingType="enroll" — the same string age/ssh use.
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
			t.Logf("[E2E] generate-key CLI exited 0 but approver returned: %v", approvalErr)
		}
		fp, parseErr := parseFingerprint(cliBuf.String())
		if parseErr != nil {
			return "", cliBuf, fmt.Errorf("parse fingerprint: %w", parseErr)
		}
		return fp, cliBuf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return "", cliBuf, fmt.Errorf("ctx done while waiting for generate-key CLI: %w", ctx.Err())
	}
}

// runExportKey runs `nb gpg --export --armor -u <fingerprint>` and
// returns the armored public key from stdout. No iOS approval — export is a
// local config read.
func runExportKey(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	fingerprint string,
) (armored string, cliBuf *lockedBuffer, err error) {
	t.Helper()
	cliBuf = &lockedBuffer{}
	args := []string{"gpg", "--export", "--armor", "-u", fingerprint}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, args...)
	cmd.Env = cliEnv(env)
	cmd.Stdout = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb", nil))
	cmd.Stderr = io.MultiWriter(cliBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s %s", env.CLIPath, strings.Join(args, " "))
	if runErr := cmd.Run(); runErr != nil {
		return "", cliBuf, fmt.Errorf("nb gpg --export: %w", runErr)
	}
	return cliBuf.String(), cliBuf, nil
}

// runSignWithApproval pipes `plaintext` into `nb gpg -bsau <fingerprint>`
// and drives ApproveRequest("gpg_sign") in parallel. Returns the armored
// detached signature (stdout).
func runSignWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	fingerprint string,
	plaintext []byte,
) (signature string, cliBuf *lockedBuffer, err error) {
	t.Helper()

	args := []string{"gpg", "-bsau", fingerprint}
	cliBuf = &lockedBuffer{}
	errBuf := &lockedBuffer{}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command — env.CLIPath is harness-provisioned by setup.sh, not user input.
	cmd := exec.CommandContext(ctx, env.CLIPath, args...)
	cmd.Env = cliEnv(env)
	// Feed plaintext via a bytes.Reader on cmd.Stdin — simpler than a pipe
	// and avoids a goroutine race between Write and Wait.
	cmd.Stdin = bytes.NewReader(plaintext)
	// Keep stdout clean for the armored signature; tee stderr for debugging.
	cmd.Stdout = cliBuf
	cmd.Stderr = io.MultiWriter(errBuf, shared.TeeToLog(t, "nb:err", nil))
	t.Logf("[E2E] launching: %s %s (stdin=%d bytes)", env.CLIPath, strings.Join(args, " "), len(plaintext))
	if startErr := cmd.Start(); startErr != nil {
		return "", cliBuf, fmt.Errorf("start `nb gpg -bsau`: %w", startErr)
	}
	t.Logf("[E2E] gpg sign CLI pid=%d", cmd.Process.Pid)

	cliDone := make(chan error, 1)
	go func() { cliDone <- cmd.Wait() }()
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
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, "gpg_sign")
	}()

	select {
	case waitErr := <-cliDone:
		wg.Wait()
		if waitErr != nil {
			return "", cliBuf, fmt.Errorf("CLI exited with error: %w (approval err: %v, stderr: %s)",
				waitErr, approvalErr, errBuf.String())
		}
		if approvalErr != nil {
			t.Logf("[E2E] gpg sign CLI exited 0 but approver returned: %v", approvalErr)
		}
		return cliBuf.String(), cliBuf, nil
	case <-ctx.Done():
		approvalCancel()
		_ = cmd.Process.Kill()
		wg.Wait()
		return "", cliBuf, fmt.Errorf("ctx done while waiting for gpg sign CLI: %w", ctx.Err())
	}
}
