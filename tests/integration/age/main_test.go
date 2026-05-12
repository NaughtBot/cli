//go:build integration

// Package age contains the NaughtBot age encryption end-to-end suite.
//
// The single test exercises the full age path:
//  1. ensure the CLI is logged in;
//  2. generate an X25519 age key on iOS via `nb age keygen`
//     (concurrent iOS approval of `enroll`);
//  3. encrypt a file with the stock `age -r <recipient>` binary (no approval,
//     pure public-key encryption);
//  4. decrypt with stock `age -d -i identity.txt` which spawns
//     `age-plugin-nb`; the plugin issues an `age_unwrap` request iOS
//     must approve (concurrent iOS approval of `age_unwrap`);
//  5. assert the decrypted plaintext matches the original.
//
// Skipped unless RUN_NB_E2E=1; setup.sh + run-test.sh are the canonical
// entry points.
package age

import (
	"os"
	"testing"
)

// TestMain mirrors the ssh suite — there is no package-level state; each test
// calls shared.SetupTestEnv on its own.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
