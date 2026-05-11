package main

import (
	"testing"

	"github.com/naughtbot/cli/internal/shared/config"
)

// configTestDir installs a fresh temporary config directory for the duration
// of the test and returns a cleanup function. Lives in an ungated test file
// so it is available in both default and `legacy_api` builds.
func configTestDir(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	return func() {
		config.ResetConfigDir()
	}
}
