//go:build integration

// Package ssh contains the NaughtBot SSH end-to-end suite.
//
// Two tests exercise the full SSH path (enroll → export pubkey → install on
// docker sshd → ssh-with-sk-provider) for both supported key algorithms.
//
// Skipped unless RUN_NB_E2E=1; setup.sh + run-test.sh are the canonical
// entry points.
package ssh

import (
	"os"
	"testing"
)

// TestMain mirrors the login suite — there is no package-level state; each
// test calls shared.SetupTestEnv on its own.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
