//go:build integration

// Package pkcs11 — end-to-end tests for NaughtBot's PKCS#11 flow.
//
// Per-test sequence:
//
//	Step 1: dump environment.
//	Step 2: ensure CLI is logged in (re-uses prior login state, re-syncs
//	         devices so that profile.user_account.devices is populated).
//	Step 3: ensure libnb-pkcs11.dylib exists, copy to per-test tempdir.
//	Step 4: read the device auth public-key hex from the CLI profile — this
//	         is the CKA_ID the provider publishes for device-backed keys.
//	Step 5: Initialize / OpenSession / find the private-key object by
//	         CKA_ID, fetch the matching CKA_EC_POINT public key.
//	Step 6: drive `p.Sign` or `p.DeriveKey` alongside a concurrent
//	         shared.ApproveRequest goroutine.
//	Step 7: cryptographic assertion on the returned bytes.
//
// The provider is a CGo shared library driven over the PKCS#11 C ABI; the
// Go test sees the same wire shape any other PKCS#11 consumer would. There
// is no enrollment step — the CLI's PKCS#11 session loads device signing
// keys straight out of “user_account.devices“ after login.
package pkcs11

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/naughtbot/cli/tests/integration/shared"
)

// approvalTypeSign is the signing-type string the provider emits for the
// PKCS#11 Sign path. It maps to `CustomPayload.type = "custom"` on the
// wire (protocol.CustomPayloadType), and to `NaughtBotCustomType` in the
// iOS SigningTypeRegistry. Kept as a named constant so a wire-format
// change is a single find-and-replace.
const approvalTypeSign = "custom"

// approvalTypeDerive is the signing-type string the provider emits for
// CKM_ECDH1_DERIVE. Maps to `EcdhDerivePayload.type = "ecdh_derive"` and
// the iOS `EcdhDeriveType`.
const approvalTypeDerive = "ecdh_derive"

// TestNBPKCS11SignECDSA exercises CKM_ECDSA over a pre-hashed
// 32-byte digest. The provider forwards the digest to iOS, iOS signs with
// the device auth key, and the 64-byte raw `r||s` signature is verified
// locally against the public key read out of CKA_EC_POINT.
func TestNBPKCS11SignECDSA(t *testing.T) {
	runSignFlow(t, "ckm_ecdsa")
}

// TestNBPKCS11SignECDSASHA256 exercises CKM_ECDSA_SHA256. The
// provider accepts arbitrary-length input, hashes it, and asks iOS to
// sign the digest. We verify with the locally computed SHA-256.
//
// sign.go explicitly whitelists both CKM_ECDSA and CKM_ECDSA_SHA256, so
// the two mechanisms share one flow and only differ in the data handed to
// p.Sign.
func TestNBPKCS11SignECDSASHA256(t *testing.T) {
	runSignFlow(t, "ckm_ecdsa_sha256")
}

// runSignFlow is the shared body of the two sign tests. Splitting on
// mechanism inside one helper keeps the tests readable and prevents them
// from drifting apart.
func runSignFlow(t *testing.T, mechanismLabel string) {
	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping pkcs11 E2E: RUN_NB_E2E != 1")
	}

	env := shared.SetupTestEnv(t)

	// Each PKCS#11 sign involves one iOS approval, which can take 30-60s
	// on a slow simulator, plus the in-band FindObjects bookkeeping.
	// 6 minutes is comfortably more than we need but matches the shape
	// of the other suites.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// ── Step 1 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 1, "dump environment")
	shared.LogEnvDump(t)
	t.Logf("[E2E]   E2E data dir: %s", env.DataDir)
	t.Logf("[E2E]   Config dir:   %s", env.ConfigDir)
	t.Logf("[E2E]   Simulator:    %s", env.SimulatorID)
	t.Logf("[E2E]   CLI path:     %s", env.CLIPath)
	t.Logf("[E2E]   PKCS11 dylib: %s", env.PKCS11Dylib)

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

	// ── Step 3 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 3, "ensure libnb-pkcs11.dylib exists + copy to tempdir")
	canonical := ensurePKCS11Dylib(t)
	dylibDir := t.TempDir()
	dylibPath := copyDylibToTempdir(t, canonical, dylibDir)
	if st, err := os.Stat(dylibPath); err != nil {
		t.Fatalf("dylib copy missing post-copy: %v", err)
	} else {
		t.Logf("[E2E] dylib ready: %s (%d bytes)", dylibPath, st.Size())
	}

	// ── Step 4 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 4, "read device auth pubkey hex from profile")
	authKeyHex, err := getDeviceAuthPublicKeyHex(env)
	if err != nil {
		dumpFailureContext(t, env, nil)
		t.Fatalf("getDeviceAuthPublicKeyHex: %v", err)
	}
	t.Logf("[E2E] device auth public key hex: %s", authKeyHex)

	// ── Step 5 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 5, "Initialize / OpenSession / find key by CKA_ID")
	p := initializePKCS11(t, dylibPath)
	defer func() {
		if err := p.Finalize(); err != nil {
			t.Logf("[E2E] Finalize: %v", err)
		}
		p.Destroy()
	}()
	session := openFirstSession(t, p)
	defer func() {
		if err := p.CloseSession(session); err != nil {
			t.Logf("[E2E] CloseSession: %v", err)
		}
	}()

	keyHandle := findPrivateKeyByCKAID(t, p, session, authKeyHex)
	t.Logf("[E2E] private key handle: %d", keyHandle)

	pubKey := getPublicKeyFromObject(t, p, session, keyHandle)
	t.Logf("[E2E] public key X=%x... Y=%x...", pubKey.X.Bytes()[:8], pubKey.Y.Bytes()[:8])

	// ── Step 6 + 7 ─────────────────────────────────────────────────────
	shared.LogStep(t, 6, "launch ApproveRequest(%s) goroutine + run p.Sign (%s)", approvalTypeSign, mechanismLabel)

	var (
		mechanism []*pkcs11.Mechanism
		dataIn    []byte
		// digest we verify against: for CKM_ECDSA the data IS the digest,
		// for CKM_ECDSA_SHA256 we compute the digest ourselves post-hoc.
		expectedDigest []byte
	)
	rawMessage := []byte("PKCS#11 E2E: verify signature via CKA_EC_POINT (" + mechanismLabel + ")")
	switch mechanismLabel {
	case "ckm_ecdsa":
		sum := sha256.Sum256(rawMessage)
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
		dataIn = sum[:]
		expectedDigest = sum[:]
	case "ckm_ecdsa_sha256":
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}
		dataIn = rawMessage
		sum := sha256.Sum256(rawMessage)
		expectedDigest = sum[:]
	default:
		t.Fatalf("runSignFlow: unknown mechanism %q", mechanismLabel)
	}

	signature, err := runSignWithApproval(ctx, t, env, p, session, keyHandle, mechanism, dataIn)
	if err != nil {
		dumpFailureContext(t, env, nil)
		t.Fatalf("sign with approval failed: %v", err)
	}

	shared.LogStep(t, 7, "verify signature against CKA_EC_POINT pubkey")
	if len(signature) != p256SignatureLen {
		dumpFailureContext(t, env, nil)
		t.Fatalf("unexpected signature length: got %d, want %d", len(signature), p256SignatureLen)
	}
	if !verifyP256RawSignature(pubKey, expectedDigest, signature) {
		dumpFailureContext(t, env, nil)
		t.Fatalf("ECDSA verify failed for mechanism %s", mechanismLabel)
	}
	t.Logf("[E2E] signature verified (%d bytes, mech=%s)", len(signature), mechanismLabel)

	// ── Success banner ─────────────────────────────────────────────────
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║          PKCS#11 SIGN E2E PASSED (%-20s)       ║", mechanismLabel)
	t.Log("║  FindObjects → p.Sign → verify round-trip OK                 ║")
	t.Log("╚══════════════════════════════════════════════════════════════╝")
}

// TestNBPKCS11DeriveECDH exercises CKM_ECDH1_DERIVE. We generate a
// fresh ephemeral P-256 peer keypair, hand its uncompressed public point
// to the provider, and assert that DeriveKey returns a non-error object
// handle — i.e. iOS returned a 32-byte shared secret via the
// ecdh_derive approval path.
//
// The PKCS#11 spec keeps the derived key value inside the token
// (CKA_SENSITIVE), so a strict shared-secret comparison is out of scope
// for this suite. The provider nonetheless fails loudly if iOS returns a
// malformed response (< 32 bytes, error code set, etc.), so a successful
// DeriveKey is a strong existence proof that the full round-trip worked.
func TestNBPKCS11DeriveECDH(t *testing.T) {
	if os.Getenv("RUN_NB_E2E") != "1" {
		t.Skip("skipping pkcs11 E2E: RUN_NB_E2E != 1")
	}

	env := shared.SetupTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// ── Step 1 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 1, "dump environment")
	shared.LogEnvDump(t)

	for _, f := range []string{
		"approval_complete.txt",
		"approval_error.txt",
		"approval_request.txt",
		"approval_auto_approved.txt",
	} {
		if err := shared.ClearE2EFile(f); err != nil {
			t.Fatalf("ClearE2EFile(%s): %v", f, err)
		}
	}

	// ── Step 2 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 2, "ensure CLI is logged in (RunLoginFlowIfNeeded)")
	env.RunLoginFlowIfNeeded(t)

	// ── Step 3 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 3, "ensure libnb-pkcs11.dylib exists + copy to tempdir")
	canonical := ensurePKCS11Dylib(t)
	dylibDir := t.TempDir()
	dylibPath := copyDylibToTempdir(t, canonical, dylibDir)

	// ── Step 4 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 4, "read device auth pubkey hex from profile")
	authKeyHex, err := getDeviceAuthPublicKeyHex(env)
	if err != nil {
		dumpFailureContext(t, env, nil)
		t.Fatalf("getDeviceAuthPublicKeyHex: %v", err)
	}
	t.Logf("[E2E] device auth public key hex: %s", authKeyHex)

	// ── Step 5 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 5, "Initialize / OpenSession / find key by CKA_ID")
	p := initializePKCS11(t, dylibPath)
	defer func() {
		if err := p.Finalize(); err != nil {
			t.Logf("[E2E] Finalize: %v", err)
		}
		p.Destroy()
	}()
	session := openFirstSession(t, p)
	defer func() {
		if err := p.CloseSession(session); err != nil {
			t.Logf("[E2E] CloseSession: %v", err)
		}
	}()
	keyHandle := findPrivateKeyByCKAID(t, p, session, authKeyHex)

	// ── Step 6 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 6, "generate ephemeral peer keypair + launch ApproveRequest(%s)", approvalTypeDerive)
	peer := generateTestKeyPair(t)
	peerPoint := encodeUncompressedPoint(&peer.PublicKey)
	t.Logf("[E2E] peer ephemeral X=%x...", peer.PublicKey.X.Bytes()[:8])

	deriveParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPoint)
	deriveMech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, deriveParams)}
	deriveTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, p256SharedLen),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}

	derivedHandle, err := runDeriveWithApproval(
		ctx, t, env, p, session, keyHandle, deriveMech, deriveTemplate,
	)
	if err != nil {
		dumpFailureContext(t, env, nil)
		t.Fatalf("derive with approval failed: %v", err)
	}

	// ── Step 7 ─────────────────────────────────────────────────────────
	shared.LogStep(t, 7, "assert non-zero derived handle")
	if derivedHandle == 0 {
		dumpFailureContext(t, env, nil)
		t.Fatalf("DeriveKey returned zero handle")
	}
	t.Logf("[E2E] derived key handle: %d", derivedHandle)

	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════╗")
	t.Log("║              PKCS#11 DERIVE E2E PASSED (ECDH1)               ║")
	t.Log("║  CKM_ECDH1_DERIVE round-trip via iOS ecdh_derive OK          ║")
	t.Log("╚══════════════════════════════════════════════════════════════╝")
}

// runSignWithApproval calls SignInit + Sign on the PKCS#11 context and, in
// parallel, drives the iOS approver via shared.ApproveRequest. The
// provider's Sign call blocks inside CGo until iOS returns, so we must
// launch the approver concurrently — exactly the same concurrency shape
// as the archived suite's `approvalDone` chan pattern.
//
// Returns the raw `r||s` signature bytes.
func runSignWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	keyHandle pkcs11.ObjectHandle,
	mechanism []*pkcs11.Mechanism,
	dataIn []byte,
) ([]byte, error) {
	t.Helper()

	if err := p.SignInit(session, mechanism, keyHandle); err != nil {
		return nil, fmt.Errorf("C_SignInit: %w", err)
	}

	approvalCtx, approvalCancel := context.WithCancel(ctx)
	defer approvalCancel()
	var (
		approvalErr error
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, approvalTypeSign)
	}()

	// p.Sign blocks until iOS returns. When it returns, the CLI's
	// performSigning has observed the decrypted signature response.
	signature, signErr := p.Sign(session, dataIn)
	approvalCancel()
	wg.Wait()

	if signErr != nil {
		if approvalErr != nil {
			return nil, fmt.Errorf("C_Sign: %w (approver error: %v)", signErr, approvalErr)
		}
		return nil, fmt.Errorf("C_Sign: %w", signErr)
	}
	if approvalErr != nil && !errors.Is(approvalErr, context.Canceled) {
		t.Logf("[E2E] Sign returned but approver reported: %v", approvalErr)
	}
	return signature, nil
}

// runDeriveWithApproval drives p.DeriveKey + iOS ECDH approval. Same
// concurrency shape as runSignWithApproval.
func runDeriveWithApproval(
	ctx context.Context,
	t *testing.T,
	env *shared.TestEnv,
	p *pkcs11.Ctx,
	session pkcs11.SessionHandle,
	baseKey pkcs11.ObjectHandle,
	mechanism []*pkcs11.Mechanism,
	template []*pkcs11.Attribute,
) (pkcs11.ObjectHandle, error) {
	t.Helper()

	approvalCtx, approvalCancel := context.WithCancel(ctx)
	defer approvalCancel()
	var (
		approvalErr error
		wg          sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalErr = shared.ApproveRequest(approvalCtx, t, env, approvalTypeDerive)
	}()

	derived, deriveErr := p.DeriveKey(session, mechanism, baseKey, template)
	approvalCancel()
	wg.Wait()

	if deriveErr != nil {
		if approvalErr != nil {
			return 0, fmt.Errorf("C_DeriveKey: %w (approver error: %v)", deriveErr, approvalErr)
		}
		return 0, fmt.Errorf("C_DeriveKey: %w", deriveErr)
	}
	if approvalErr != nil && !errors.Is(approvalErr, context.Canceled) {
		t.Logf("[E2E] DeriveKey returned but approver reported: %v", approvalErr)
	}
	return derived, nil
}
