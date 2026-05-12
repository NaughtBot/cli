//go:build integration

package shared

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// SimctlOpenURL delivers a URL to the installed app on the simulator via
// `xcrun simctl openurl`. Used by suites that need to invoke the universal
// link handler without going through Safari.
func SimctlOpenURL(t *testing.T, simulatorID, url string) error {
	t.Helper()
	cmd := exec.Command("xcrun", "simctl", "openurl", simulatorID, url)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("simctl openurl failed: %v\n%s", err, out.String())
	}
	return nil
}

// PreApproveURLScheme writes a LaunchServices scheme-approval default on the
// simulator so iOS 26's "Open in <App>?" prompt does not appear when
// `xcrun simctl openurl` delivers a URL with the given scheme. Without this
// pre-approval, the confirmation alert is presented by SpringBoard and the
// URL never reaches the app's `.onOpenURL` / AppDelegate handler — which
// silently breaks every URL-based E2E hook (login deep links, test URLs).
//
// The approval key is namespaced by the process that requests the open, which
// for `simctl openurl` is `com.apple.CoreSimulator.CoreSimulatorBridge`.
func PreApproveURLScheme(t *testing.T, simulatorID, scheme, bundleID string) error {
	t.Helper()
	key := "com.apple.CoreSimulator.CoreSimulatorBridge-->" + scheme
	cmd := exec.Command("xcrun", "simctl", "spawn", simulatorID,
		"defaults", "write", "com.apple.launchservices.schemeapproval", key, "-string", bundleID)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pre-approve scheme %s failed: %v\n%s", scheme, err, out.String())
	}
	return nil
}

// SimctlTerminate terminates the NaughtBot app on the simulator if running.
// Missing-app is not an error — this is called opportunistically before a
// relaunch.
func SimctlTerminate(simulatorID, bundleID string) {
	cmd := exec.Command("xcrun", "simctl", "terminate", simulatorID, bundleID)
	_ = cmd.Run()
}

// RunFullE2ELogin invokes the NaughtBot XCUITest scheme's
// testFullE2EFlow against the named simulator. It is safe to call this
// concurrently with `nb login --localdev` running in another
// goroutine — the XCUITest reads qr_url.txt from E2EDataDir.
//
// The function blocks until xcodebuild exits. stdout/stderr are mirrored to
// the test log via TeeToLog.
func RunFullE2ELogin(ctx context.Context, t *testing.T, env *TestEnv) error {
	t.Helper()
	return runXCUITest(ctx, t, env, "NaughtBotUITests/E2EFullFlowUITests/testFullE2EFlow")
}

// RunApprovalUITest invokes the XCUITest scheme's testApproveRequest.
// Non-login suites call this in a goroutine so the iOS approver auto-taps
// as soon as the CLI surfaces a pending signing request.
//
// requestType is written to approval_request.txt as a breadcrumb so the
// XCUITest can log which flow it is approving.
func RunApprovalUITest(ctx context.Context, t *testing.T, env *TestEnv, requestType string) error {
	t.Helper()
	if err := WriteE2EFile("approval_request.txt", requestType); err != nil {
		return fmt.Errorf("WriteE2EFile(approval_request.txt): %w", err)
	}
	return runXCUITest(ctx, t, env, "NaughtBotUITests/E2EApprovalUITests/testApproveRequest")
}

// ApproveRequest is the canonical entry point used by non-login suites to
// dispatch the iOS approver. It is a thin alias over RunApprovalUITest kept
// to match the spec's per-suite vocabulary ("await ssh_enrollment approval
// via ApproveRequest"). Each call reuses the XCUITest harness, which clears
// approval_complete.txt and writes a fresh approval_request.txt before
// launching the approver.
//
// Callers typically invoke this in a goroutine alongside a CLI invocation
// that is blocking on iOS approval. The function blocks until xcodebuild
// exits.
func ApproveRequest(ctx context.Context, t *testing.T, env *TestEnv, requestType string) error {
	t.Helper()
	// Clear any prior approval breadcrumbs so the next CLI request sees a
	// fresh signal — without this, a stale approval_complete.txt from a
	// previous step would short-circuit WaitForApprovalComplete.
	for _, f := range []string{
		"approval_complete.txt",
		"approval_error.txt",
		"approval_auto_approved.txt",
	} {
		if err := ClearE2EFile(f); err != nil {
			return fmt.Errorf("ApproveRequest: clear %s: %w", f, err)
		}
	}
	return RunApprovalUITest(ctx, t, env, requestType)
}

// ServeOpenURLRequests polls E2EDataDir for `open_url_request.txt` and
// delivers each request by invoking `xcrun simctl openurl <simulatorID> <url>`
// on the host. On success the request file is removed and
// `open_url_delivered.txt` is written with "ok"; on failure
// `approval_error.txt` is populated AND the test is marked failed via
// `t.Errorf` so a fatal serve error (port-bind failure, simctl missing, …)
// can never be silently swallowed by the rest of the suite.
//
// Callers launch this before starting the XCUITest runner and call the
// returned `wait` function (typically via defer) once they cancel the
// context, so the goroutine has a chance to drain before the test exits.
// `wait` blocks until the goroutine has fully returned.
func ServeOpenURLRequests(ctx context.Context, t *testing.T, simulatorID string) (wait func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			url, err := ReadE2EFile("open_url_request.txt")
			if err != nil || url == "" {
				time.Sleep(150 * time.Millisecond)
				continue
			}
			LogStep(t, 0, "ServeOpenURLRequests: delivering %s", url)
			if err := SimctlOpenURL(t, simulatorID, url); err != nil {
				msg := fmt.Sprintf("simctl openurl failed: %v", err)
				_ = WriteE2EFile("approval_error.txt", msg)
				t.Errorf("ServeOpenURLRequests: %s", msg)
				return
			}
			if err := ClearE2EFile("open_url_request.txt"); err != nil {
				t.Errorf("ServeOpenURLRequests: clear open_url_request.txt: %v", err)
				return
			}
			if err := WriteE2EFile("open_url_delivered.txt", "ok"); err != nil {
				t.Errorf("ServeOpenURLRequests: write open_url_delivered.txt: %v", err)
				return
			}
		}
	}()
	return func() { <-done }
}

// WaitForApprovalComplete blocks until the XCUITest side writes either
// approval_complete.txt ("success") or approval_error.txt. On failure the
// error includes the error text.
func WaitForApprovalComplete(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if v, _ := ReadE2EFile("approval_complete.txt"); v == "success" {
			return nil
		}
		if v, _ := ReadE2EFile("approval_error.txt"); v != "" {
			return fmt.Errorf("approval failed: %s", v)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for approval_complete.txt / approval_error.txt after %s", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// runXCUITest is the common xcodebuild invocation used by RunFullE2ELogin
// and RunApprovalUITest.
func runXCUITest(ctx context.Context, t *testing.T, env *TestEnv, onlyTesting string) error {
	t.Helper()

	if env.DerivedData == "" {
		return fmt.Errorf("runXCUITest: env.DerivedData is empty; setup.sh should have populated DERIVED_DATA_PATH")
	}

	// workspaceRoot points at the NaughtBot workspace root (the parent of
	// the cli/, mobile/, core/, ... sibling checkouts). The cli/ repo lives
	// at <workspace>/cli/, and the iOS app the harness installs lives at
	// <workspace>/mobile/ios/apps/NaughtBot/. Callers can override via the
	// WORKSPACE_ROOT env var when running from a non-canonical layout (e.g.
	// a lane worktree generated by `make lane-create`).
	workspaceRoot := os.Getenv("WORKSPACE_ROOT")
	if workspaceRoot == "" {
		// The shared module lives at <cli>/tests/integration/shared. Walk
		// up four levels: shared -> integration -> tests -> cli -> workspace.
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("os.Getwd: %w", err)
		}
		workspaceRoot = cwd + "/../../../.."
	}

	// Reinstall the built apps from DerivedData before each test run. Without
	// this, `xcodebuild test-without-building` reuses the Runner.app installed
	// on the simulator by a previous invocation, which can be stale relative
	// to the code in DerivedData after an incremental rebuild. The symptom is
	// silent: tests "run" but execute old code paths.
	//
	// Reinstalling requires an uninstall first: `simctl install` over an
	// existing installation of the same bundle id does not always replace the
	// binary inside the .app — it appears to skip the copy when it detects a
	// matching codesign signature. Uninstall forces a clean install from
	// DerivedData.
	productsDir := env.DerivedData + "/Build/Products/LocalDev-iphonesimulator"
	// The XCUITest runner app has no persistent state worth preserving and
	// MUST be reinstalled each run so xcodebuild test-without-building
	// picks up code changes (uninstall is required because simctl install
	// over a same-codesign bundle is a no-op, see comment below).
	//
	// NaughtBot.app, however, owns the iOS-side login state (keychain,
	// approver key material, requester membership). Uninstalling it
	// between suites would invalidate the session that the login suite
	// established, leaving every downstream suite (ssh, gpg, age, pkcs11)
	// staring at an empty Requests tab while the CLI hangs waiting for
	// approval. We therefore install NaughtBot.app over the existing copy
	// without uninstalling first, accepting that an incremental rebuild
	// of NaughtBot.app may not always swap in (rare in normal dev — the
	// operator can run setup.sh --build to force a clean reinstall).
	type appSpec struct {
		dir, bundleID string
		preserveData  bool // skip uninstall to keep keychain / app data
	}
	apps := []appSpec{
		{"NaughtBot.app", "com.naughtbot.ios.dev", true},
		{"NaughtBotUITests-Runner.app", "com.naughtbot.ios.uitests.xctrunner", false},
	}
	for _, app := range apps {
		appPath := productsDir + "/" + app.dir
		if _, err := os.Stat(appPath); err != nil {
			LogStep(t, 0, "[shared] skip install (not built): %s", appPath)
			continue
		}
		if !app.preserveData {
			uninstall := exec.Command("xcrun", "simctl", "uninstall", env.SimulatorID, app.bundleID)
			_ = uninstall.Run() // ignore error: may not be installed yet
		}
		install := exec.Command("xcrun", "simctl", "install", env.SimulatorID, appPath)
		if out, ierr := install.CombinedOutput(); ierr != nil {
			return fmt.Errorf("simctl install %s: %v\n%s", app.dir, ierr, string(out))
		}
		mode := "reinstalled"
		if app.preserveData {
			mode = "installed (preserving data)"
		}
		LogStep(t, 0, "[shared] %s %s on simulator", mode, app.dir)
	}

	// TODO(NaughtBot/mobile): the legacy harness used a dedicated
	// `OOBSignE2E` scheme that test-built the `OOBSignUITests` bundle
	// against the `LocalDev` configuration. The NaughtBot iOS app does not
	// yet have an equivalent CLI-approval E2E scheme + XCUITest bundle.
	// Until the approval-UI follow-up lands (tracked alongside WS3.5),
	// these suites build but do not run end-to-end: the `NaughtBot` scheme
	// below is a placeholder and the `-only-testing:` selectors below
	// reference test cases that the mobile repo does not yet expose.
	args := []string{
		"test-without-building",
		"-project", workspaceRoot + "/mobile/ios/apps/NaughtBot/NaughtBot.xcodeproj",
		"-scheme", "NaughtBot",
		"-configuration", "LocalDev",
		"-destination", "platform=iOS Simulator,id=" + env.SimulatorID,
		"-derivedDataPath", env.DerivedData,
		"-only-testing:" + onlyTesting,
		"-parallel-testing-enabled", "NO",
	}

	cmd := exec.CommandContext(ctx, "xcodebuild", args...)
	// Forward coordination env vars into the xcodebuild process so the test
	// runner's launchEnvironment picks them up via TEST_RUNNER_* prefix.
	// SIMCTL_CHILD_* is ALSO set so that if the app is launched by
	// `simctl launch` instead of via xcodebuild, these reach it too.
	cmd.Env = append(os.Environ(),
		"TEST_RUNNER_E2E_DATA_DIR="+env.DataDir,
		"TEST_RUNNER_RUN_INTEGRATION_TESTS=1",
		"TEST_RUNNER_FORCE_SOFTWARE_KEY=1",
		"TEST_RUNNER_FORCE_SOFTWARE_ATTESTATION=1",
		"TEST_RUNNER_SKIP_VERIFY_ATTESTATION=true",
		"SIMCTL_CHILD_E2E_DATA_DIR="+env.DataDir,
		"SIMCTL_CHILD_RUN_INTEGRATION_TESTS=1",
		"SIMCTL_CHILD_FORCE_SOFTWARE_KEY=1",
		"SIMCTL_CHILD_FORCE_SOFTWARE_ATTESTATION=1",
		"SIMCTL_CHILD_SKIP_VERIFY_ATTESTATION=true",
	)

	cmd.Stdout = TeeToLog(t, "xcodebuild", nil)
	cmd.Stderr = TeeToLog(t, "xcodebuild:err", nil)

	LogStep(t, 0, "[shared] xcodebuild test-without-building -only-testing:%s", onlyTesting)
	err := cmd.Run()
	LogStep(t, 0, "[shared] xcodebuild %s exited err=%v", onlyTesting, err)
	return err
}
