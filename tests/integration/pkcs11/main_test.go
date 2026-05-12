//go:build integration

// Package pkcs11 contains the NaughtBot PKCS#11 end-to-end suite.
//
// Three tests drive the real PKCS#11 dylib (libnb-pkcs11.dylib) from Go
// via miekg/pkcs11 against a booted iOS simulator:
//
//   - TestNBPKCS11SignECDSA       — CKM_ECDSA sign over a pre-hashed
//     32-byte digest. Verifies signature with the device auth public key.
//   - TestNBPKCS11SignECDSASHA256 — CKM_ECDSA_SHA256 sign over raw
//     data; provider hashes internally. Verifies signature after locally
//     computing SHA-256.
//   - TestNBPKCS11DeriveECDH      — CKM_ECDH1_DERIVE against an
//     ephemeral peer P-256 public key; asserts a non-zero shared secret is
//     returned via DeriveKey.
//
// Each test drives the iOS approver in parallel via shared.ApproveRequest,
// mirroring the ssh suite. Skipped unless RUN_NB_E2E=1.
package pkcs11

import (
	"os"
	"testing"
)

// TestMain mirrors the ssh / login suites — there is no package-level state;
// each test calls shared.SetupTestEnv on its own.
//
// Unlike the other suites, the PKCS#11 dylib is loaded in-process by miekg
// via dlopen. The dylib is a c-shared Go binary with its *own* Go runtime
// that caches the process environment at startup via envp, and neither
// os.Setenv nor C.setenv in this test process propagates into that cached
// table once the dylib is loaded. The environment variable
// “SKIP_VERIFY_ATTESTATION=true“ must therefore be exported into the
// environment of the “go test“ process *before* it runs — see
// “tests/integration/run-test.sh“ which sets it for the pkcs11 suite —
// paired with the DEV=1 build of libnb-pkcs11.dylib that bakes in
// “transport.AllowSkipAttestation="true"“ via ldflags. Both conditions
// are required for “transport.SkipAttestationRequested()“ to return true,
// which is what lets the CLI accept the dev-signed simulator's missing
// BBS+ anonymous attestation on every approval response.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
