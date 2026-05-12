//go:build integration

// Package gpg contains the NaughtBot GPG signing end-to-end suite.
//
// Each test exercises the full GPG path end-to-end:
//  1. ensure the CLI is logged in;
//  2. generate a GPG key on iOS via `nb gpg --generate-key`
//     (concurrent iOS approval of `enroll`);
//  3. export the resulting public key (`nb gpg --export`) and import it
//     into a fresh GnuPG keyring so stock `gpg --verify` has a trust anchor;
//  4. produce a detached armored signature over a plaintext payload via
//     `nb gpg -bsau <fingerprint>` (concurrent iOS approval of
//     `gpg_sign`);
//  5. verify the signature with stock `gpg --verify` and assert success.
//
// Skipped unless RUN_NB_E2E=1; setup.sh + run-test.sh are the canonical
// entry points.
package gpg

import (
	"os"
	"testing"
)

// TestMain mirrors the age/ssh suites — no package-level state; each test
// calls shared.SetupTestEnv on its own.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
