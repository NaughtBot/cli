//go:build integration

package shared

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEnv captures the state the harness publishes via setup.sh and the
// per-suite test's derived values. Each suite's TestMain builds one of these
// and passes it around instead of re-reading environment variables.
type TestEnv struct {
	// Directories
	DataDir     string // E2E coordination files (E2E_DATA_DIR)
	ConfigDir   string // NB_CONFIG_DIR — CLI config root
	AppPath     string // built NaughtBot.app on disk (for reinstalls)
	DerivedData string // DerivedData for xcodebuild test-without-building

	// Simulator + binaries
	SimulatorID string
	CLIPath     string // nb binary (canonical path NB_CLI_PATH)
	AgePlugin   string // age-plugin-nb
	SKDylib     string // libnb-sk.dylib
	PKCS11Dylib string // libnb-pkcs11.dylib

	// Profile name to inspect on disk. Mirrors the NaughtBot CLI's
	// `NB_PROFILE` env var; defaults to "default" (which matches
	// `cli/internal/shared/config.DefaultProfileName`).
	ProfileName string

	// Backend URLs
	LoginURL string
	RelayURL string
	BlobURL  string
	SSHHost  string
	SSHPort  string
}

// SetupTestEnv resolves the ambient environment into a TestEnv. It fails the
// test if any required field is missing, so every suite fails fast with a
// clear "missing X" error rather than a cryptic downstream panic.
//
// Call from suite TestMain:
//
//	func TestMain(m *testing.M) {
//	    os.Exit(m.Run())
//	}
//
// and from the top of each test:
//
//	env := shared.SetupTestEnv(t)
//	shared.LogEnvDump(t)
func SetupTestEnv(t *testing.T) *TestEnv {
	t.Helper()

	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping E2E test — RUN_NB_E2E=1 not set (use ./run-test.sh --e2e)")
	}

	env := &TestEnv{
		DataDir:     envOr("E2E_DATA_DIR", "/tmp/nb-e2e"),
		ConfigDir:   os.Getenv("NB_CONFIG_DIR"),
		AppPath:     os.Getenv("NB_APP_PATH"),
		DerivedData: os.Getenv("DERIVED_DATA_PATH"),
		SimulatorID: os.Getenv("SIMULATOR_ID"),
		CLIPath:     firstNonEmpty(os.Getenv("NB_CLI_PATH"), os.Getenv("NB_CLI")),
		AgePlugin:   os.Getenv("AGE_PLUGIN"),
		SKDylib:     os.Getenv("SK_DYLIB"),
		PKCS11Dylib: os.Getenv("PKCS11_DYLIB"),
		ProfileName: envOr("NB_PROFILE", "default"),
		LoginURL:    envOr("TEST_LOGIN_URL", "http://127.0.0.1:4455"),
		RelayURL:    envOr("TEST_RELAY_URL", "http://127.0.0.1:8080"),
		BlobURL:     envOr("TEST_BLOB_URL", "http://127.0.0.1:8082"),
		SSHHost:     envOr("TEST_SSH_HOST", "127.0.0.1"),
		SSHPort:     envOr("TEST_SSH_PORT", "2222"),
	}

	for field, value := range map[string]string{
		"SIMULATOR_ID":  env.SimulatorID,
		"NB_CLI_PATH":   env.CLIPath,
		"NB_CONFIG_DIR": env.ConfigDir,
	} {
		if value == "" {
			t.Fatalf("SetupTestEnv: required environment variable %s is empty (did you run ./setup.sh?)", field)
		}
	}

	if _, err := os.Stat(env.CLIPath); err != nil {
		t.Fatalf("SetupTestEnv: CLI not found at %q: %v", env.CLIPath, err)
	}

	if err := os.MkdirAll(env.ConfigDir, 0o755); err != nil {
		t.Fatalf("SetupTestEnv: cannot create CONFIG_DIR %q: %v", env.ConfigDir, err)
	}
	if _, err := EnsureE2EDataDir(); err != nil {
		t.Fatalf("SetupTestEnv: cannot ensure DATA_DIR: %v", err)
	}

	// Publish relay/login/blob URLs into the coordination dir so XCUITest can
	// read them on launch without reaching into the Go env.
	for name, value := range map[string]string{
		"relay_url.txt": env.RelayURL,
		"login_url.txt": env.LoginURL,
		"blob_url.txt":  env.BlobURL,
	} {
		if err := WriteE2EFile(name, value); err != nil {
			t.Fatalf("SetupTestEnv: WriteE2EFile(%s): %v", name, err)
		}
	}

	// Pre-approve the `naughtbot://` custom scheme so iOS 26's LaunchServices
	// confirmation alert ("Open in NaughtBot?") does not block URL delivery
	// during `xcrun simctl openurl`. Without this the test URL bridge silently
	// fails — see PreApproveURLScheme for the full rationale.
	if err := PreApproveURLScheme(t, env.SimulatorID, "naughtbot", "com.naughtbot.ios.dev"); err != nil {
		t.Fatalf("SetupTestEnv: PreApproveURLScheme: %v", err)
	}

	return env
}

// ProfilePath returns the on-disk path to the CLI's profile JSON for the
// active profile, matching `cli/internal/shared/config.ProfilePath`:
// `<ConfigDir>/profiles/<ProfileName>.json`. Used by IsLoggedIn after a
// login flow completes.
func (e *TestEnv) ProfilePath() string {
	name := e.ProfileName
	if name == "" {
		name = "default"
	}
	return filepath.Join(e.ConfigDir, "profiles", name+".json")
}

// IsLoggedIn reports whether the CLI appears to be logged in, as determined
// by the presence of token references on disk in the active profile file.
func (e *TestEnv) IsLoggedIn() bool {
	data, err := os.ReadFile(e.ProfilePath())
	if err != nil {
		return false
	}
	s := string(data)
	return contains(s, "access_token_ref") && contains(s, "refresh_token_ref")
}

// WaitForQRURL blocks until the CLI writes `qr_url.txt` into DataDir, or
// times out. This is how the Go suite hands off the login URL to XCUITest.
func (e *TestEnv) WaitForQRURL(t *testing.T, timeout time.Duration) string {
	t.Helper()
	url, err := WaitForE2EFile("qr_url.txt", timeout)
	if err != nil {
		t.Fatalf("WaitForQRURL: %v", err)
	}
	return url
}

// RunLoginFlowIfNeeded is a placeholder used by non-login suites: they need
// the CLI to be logged in before exercising their own flow. For now it just
// skips when not logged in and lets the suite signal a setup error; the
// login suite (phase 2) will add the real implementation that spawns
// `nb login --localdev` and drives the iOS E2EFullFlow.
func (e *TestEnv) RunLoginFlowIfNeeded(t *testing.T) {
	t.Helper()
	path := e.ProfilePath()
	LogStep(t, 0, "RunLoginFlowIfNeeded: checking profile %q at %s", e.ProfileName, path)
	if e.IsLoggedIn() {
		LogStep(t, 0, "CLI already logged in (profile present at %s)", path)
		return
	}
	t.Fatalf("RunLoginFlowIfNeeded: CLI not logged in yet (no token refs at %s) and driver not implemented; run the login suite first", path)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return indexOf(haystack, needle) >= 0
}

// indexOf is a minimal substring search; written out rather than pulling
// strings to keep this file dependency-free (the module has no imports).
func indexOf(haystack, needle string) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
