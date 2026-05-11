package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	attestedkeyzk "github.com/naughtbot/attested-key-zk/bindings/go"
)

var (
	testCircuitOnce sync.Once
	testCircuit     []byte
	testCircuitErr  error
)

func TestLongfellowProofVerifier_VerifyApprovalProof(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	if _, err := verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	}); err != nil {
		t.Fatalf("VerifyApprovalProof: %v", err)
	}
}

func TestLongfellowProofVerifier_RejectsAudienceMismatch(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	fixture.proof.Statement.AudienceHashHex = "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	})
	if err == nil {
		t.Fatal("expected audience mismatch")
	}
	if !contains(err.Error(), "audienceHashHex mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestLongfellowProofVerifier_AcceptsUppercaseHexFields is a regression guard
// for commit 93a129af ("fix(approval): compare statement hex fields
// case-insensitively"). Pre-fix, validateStatement compared AudienceHashHex,
// ChallengeNonceHex, ApprovalHashHex and validateAttestationBundle compared
// AppIDHashHex against hex.EncodeToString output — always lowercase — with
// `==`, so an otherwise valid proof that supplied uppercase hex was rejected.
// Uppercasing every affected field on a valid fixture proof must still verify.
func TestLongfellowProofVerifier_AcceptsUppercaseHexFields(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)

	fixture.proof.Statement.AudienceHashHex = strings.ToUpper(fixture.proof.Statement.AudienceHashHex)
	fixture.proof.Statement.ChallengeNonceHex = strings.ToUpper(fixture.proof.Statement.ChallengeNonceHex)
	fixture.proof.Statement.ApprovalHashHex = strings.ToUpper(fixture.proof.Statement.ApprovalHashHex)
	fixture.proof.Statement.AppIDHashHex = strings.ToUpper(fixture.proof.Statement.AppIDHashHex)

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	if _, err := verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	}); err != nil {
		t.Fatalf("VerifyApprovalProof with uppercase hex fields: %v", err)
	}
}

func TestLongfellowProofVerifier_AcceptsAllowedAppIDHashes(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)
	fixture.config.AppID = ""
	fixture.config.AllowedAppIDHashesHex = []string{fixture.proof.Statement.AppIDHashHex}

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	if _, err := verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	}); err != nil {
		t.Fatalf("VerifyApprovalProof: %v", err)
	}
}

func TestLongfellowProofVerifier_RejectsHighSAttestationSignature(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)
	fixture.proof.Attestation.Signature = flipAttestationSignatureToHighS(t, fixture.proof.Attestation.Signature)

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	_, err = verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	})
	if err == nil {
		t.Fatal("expected non-canonical high-S attestation signature rejection")
	}
	if !contains(err.Error(), "non-canonical (high-S)") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifier_WithLongfellowVerifierConfig(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)

	nonceStore := newMockNonceStore()
	verifier := NewVerifier(nil, nonceStore, WithLongfellowVerifierConfig(fixture.config))
	if err := nonceStore.Create(context.Background(), fixture.challenge.Nonce, fixture.challenge.RequestID, "remove_member", "admin-user"); err != nil {
		t.Fatalf("Create nonce: %v", err)
	}

	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  fixture.challenge.Nonce,
	}
	if err := verifier.Verify(context.Background(), fixture.proof, "admin-user", actionFields); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestCanonicalApprovalChallengeJSON_IncludesEveryExportedField is a regression
// guard for https://github.com/ClarifiedLabs/ackagent-monorepo/issues/300.
//
// The SHA-256 over this canonical JSON is committed to the Longfellow approval
// circuit as approvalHash. A future field added to ApprovalChallenge that
// silently dropped out of the canonical encoding would mean the server and the
// prover are signing different things — breaking verification at best, or
// hiding a field from circuit enforcement at worst. Drive the check by
// reflection so the test fails automatically when a field is added without an
// encoder update.
func TestCanonicalApprovalChallengeJSON_IncludesEveryExportedField(t *testing.T) {
	challenge := ApprovalChallenge{
		Version:       ApprovalChallengeVersion,
		Nonce:         "test-nonce",
		RequestID:     "test-request-id",
		PlaintextHash: "sha256:" + strings.Repeat("a", 64),
	}

	got, err := canonicalApprovalChallengeJSON(challenge)
	if err != nil {
		t.Fatalf("canonicalApprovalChallengeJSON: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("canonical JSON is not valid JSON: %v", err)
	}

	// Mirror encoding/json's field-to-key rules: skip unexported fields and
	// skip fields tagged `json:"-"` (deliberately excluded from the wire
	// format). Anything else the struct exposes MUST appear in the canonical
	// JSON, since that's what gets committed to the circuit.
	expectedKeys := map[string]string{}
	typ := reflect.TypeFor[ApprovalChallenge]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		jsonKey := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			name, _, hasOpts := strings.Cut(tag, ",")
			if name == "-" && !hasOpts {
				// `json:"-"` — field is intentionally wire-excluded; it is
				// not expected in the canonical JSON.
				continue
			}
			if name != "" {
				jsonKey = name
			}
		}
		expectedKeys[jsonKey] = field.Name
	}

	for jsonKey, fieldName := range expectedKeys {
		if _, ok := decoded[jsonKey]; !ok {
			t.Errorf(
				"canonical approval challenge JSON is missing field %q (Go field %q); "+
					"every wire-visible ApprovalChallenge field must be bound into approvalHash",
				jsonKey, fieldName,
			)
		}
	}

	if len(decoded) != len(expectedKeys) {
		t.Errorf(
			"canonical approval challenge JSON has %d keys but ApprovalChallenge has %d wire-visible fields; "+
				"extra or missing keys will desync the circuit-bound approvalHash",
			len(decoded), len(expectedKeys),
		)
	}
}

// TestCanonicalApprovalChallengeJSON_MatchesLegacyEncoding locks in the exact
// byte encoding of the canonical approval challenge for the current schema.
// The approvalHash committed to the Longfellow circuit is SHA-256 over these
// bytes; changing the encoding silently would invalidate every already-issued
// approval proof. If this test fails after a legitimate schema change, update
// the expected string intentionally and document the break.
func TestCanonicalApprovalChallengeJSON_MatchesLegacyEncoding(t *testing.T) {
	challenge := ApprovalChallenge{
		Version:       ApprovalChallengeVersion,
		Nonce:         "nonce-123",
		RequestID:     "550e8400-e29b-41d4-a716-446655440000",
		PlaintextHash: "sha256:" + strings.Repeat("0", 64),
	}

	got, err := canonicalApprovalChallengeJSON(challenge)
	if err != nil {
		t.Fatalf("canonicalApprovalChallengeJSON: %v", err)
	}

	want := `{"nonce":"nonce-123","plaintextHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","requestId":"550e8400-e29b-41d4-a716-446655440000","version":"approval-challenge/v1"}`
	if got != want {
		t.Errorf("canonical approval challenge JSON changed\n  got:  %s\n  want: %s", got, want)
	}
}

type longfellowProofFixture struct {
	challenge      ApprovalChallenge
	proof          ApprovalAttestedKeyProof
	config         LongfellowVerifierConfig
	issuerKey      *ecdsa.PrivateKey
	attestationRaw [attestedkeyzk.AttestationLength]byte
}

func makeLongfellowProofFixture(t *testing.T) longfellowProofFixture {
	t.Helper()

	circuit := mustApprovalProofCircuit(t)
	statementNow := int64(1714761600)
	audience := "ackagent.example.com"
	appID := "com.example.ackagent"

	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "nonce-123",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "nonce-123",
		RequestID: "550e8400-e29b-41d4-a716-446655440000",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge: %v", err)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device keygen: %v", err)
	}

	appIDHash := sha256.Sum256([]byte(appID))
	audienceHash := sha256.Sum256([]byte(audience))
	challengeNonce := sha256.Sum256([]byte(challenge.Nonce))
	canonicalChallenge, err := canonicalApprovalChallengeJSON(challenge)
	if err != nil {
		t.Fatalf("canonicalApprovalChallengeJSON: %v", err)
	}
	approvalHash := sha256.Sum256([]byte(canonicalChallenge))

	var statement attestedkeyzk.Statement
	fillFixed32(statement.IssuerPublicKeyX[:], issuerKey.PublicKey.X)
	fillFixed32(statement.IssuerPublicKeyY[:], issuerKey.PublicKey.Y)
	copy(statement.AppIDHash[:], appIDHash[:])
	binary.BigEndian.PutUint32(statement.PolicyVersion[:], 1)
	binary.BigEndian.PutUint64(statement.Now[:], uint64(statementNow))
	copy(statement.ChallengeNonce[:], challengeNonce[:])
	copy(statement.AudienceHash[:], audienceHash[:])
	copy(statement.ApprovalHash[:], approvalHash[:])

	deviceX, deviceY := publicKeyXY(deviceKey)
	attestation := attestedkeyzk.BuildAttestation(
		statement,
		deviceX,
		deviceY,
		attestedkeyzk.Uint64BE(uint64(statementNow-60)),
		attestedkeyzk.Uint64BE(uint64(statementNow+300)),
	)
	attestationSig := rawSignature(t, issuerKey, attestation[:])
	approvalAssertion := attestedkeyzk.BuildApprovalAssertion(
		statement,
		attestedkeyzk.Uint64BE(uint64(statementNow+60)),
	)
	approvalAssertionSig := rawSignature(t, deviceKey, approvalAssertion[:])

	proofBytes, err := attestedkeyzk.Prove(circuit, attestedkeyzk.ProverInput{
		Statement:            statement,
		Attestation:          attestation,
		AttestationSig:       attestationSig,
		ApprovalAssertion:    approvalAssertion,
		ApprovalAssertionSig: approvalAssertionSig,
	})
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	issuerKeyHex := compressedPublicKeyHex(t, &issuerKey.PublicKey)
	var attestationSigBytes [64]byte
	copy(attestationSigBytes[:], attestationSig[:])

	return longfellowProofFixture{
		challenge:      challenge,
		issuerKey:      issuerKey,
		attestationRaw: attestation,
		proof: ApprovalAttestedKeyProof{
			Version:   ApprovalAttestedKeyProofVersion,
			Challenge: challenge,
			Statement: ApprovalProofStatement{
				IssuerPublicKeyHex: issuerKeyHex,
				AppIDHashHex:       hex.EncodeToString(appIDHash[:]),
				PolicyVersion:      1,
				Now:                statementNow,
				ChallengeNonceHex:  hex.EncodeToString(challengeNonce[:]),
				AudienceHashHex:    hex.EncodeToString(audienceHash[:]),
				ApprovalHashHex:    hex.EncodeToString(approvalHash[:]),
			},
			Attestation: ApprovalAttestationV1{
				Version:   ApprovalAttestationVersion,
				Bytes:     base64.StdEncoding.EncodeToString(attestation[:]),
				Signature: base64.StdEncoding.EncodeToString(attestationSigBytes[:]),
			},
			Proof: base64.StdEncoding.EncodeToString(proofBytes),
		},
		config: LongfellowVerifierConfig{
			Audience:             audience,
			AppID:                appID,
			PolicyVersion:        1,
			IssuerPublicKeyHexes: []string{issuerKeyHex},
			Circuit:              circuit,
			Now: func() time.Time {
				return time.Unix(statementNow, 0).UTC()
			},
		},
	}
}

func mustApprovalProofCircuit(t *testing.T) []byte {
	t.Helper()
	testCircuitOnce.Do(func() {
		testCircuit, testCircuitErr = attestedkeyzk.GenerateCircuit()
	})
	if testCircuitErr != nil {
		t.Fatalf("GenerateCircuit: %v", testCircuitErr)
	}
	return append([]byte(nil), testCircuit...)
}

func publicKeyXY(key *ecdsa.PrivateKey) ([attestedkeyzk.P256CoordLength]byte, [attestedkeyzk.P256CoordLength]byte) {
	var x, y [attestedkeyzk.P256CoordLength]byte
	fillFixed32(x[:], key.PublicKey.X)
	fillFixed32(y[:], key.PublicKey.Y)
	return x, y
}

func rawSignature(t *testing.T, key *ecdsa.PrivateKey, msg []byte) [attestedkeyzk.SignatureLength]byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	s = normalizeLowS(s, key.Curve)
	var sig [attestedkeyzk.SignatureLength]byte
	fillFixed32(sig[0:32], r)
	fillFixed32(sig[32:64], s)
	return sig
}

func flipAttestationSignatureToHighS(t *testing.T, signatureBase64 string) string {
	t.Helper()

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		t.Fatalf("decode attestation signature: %v", err)
	}
	if len(signature) != attestedkeyzk.SignatureLength {
		t.Fatalf("unexpected attestation signature length: %d", len(signature))
	}

	s := new(big.Int).SetBytes(signature[32:])
	halfOrder := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		t.Fatal("attestation signature is already high-S")
	}

	highS := new(big.Int).Sub(elliptic.P256().Params().N, s)
	fillFixed32(signature[32:], highS)
	return base64.StdEncoding.EncodeToString(signature)
}

func normalizeLowS(s *big.Int, curve elliptic.Curve) *big.Int {
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		return new(big.Int).Sub(curve.Params().N, s)
	}
	return new(big.Int).Set(s)
}

func compressedPublicKeyHex(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	raw := elliptic.MarshalCompressed(elliptic.P256(), publicKey.X, publicKey.Y)
	if len(raw) != 33 {
		t.Fatalf("unexpected compressed public key length: %d", len(raw))
	}
	return hex.EncodeToString(raw)
}

// mutateAndResignAttestation clones the fixture's raw attestation, applies
// `mutate`, re-signs the result with the fixture's issuer key, and returns the
// base64-encoded bytes and signature. Needed for tests that target specific
// rejection branches inside the 136-byte attestation layout (domain, appID,
// policy version, key class, reserved, time window) — if we mutated without
// re-signing, `validateAttestationBundle` would reject on the signature check
// before reaching the branch under test.
func mutateAndResignAttestation(t *testing.T, f *longfellowProofFixture, mutate func(raw []byte)) (string, string) {
	t.Helper()
	raw := f.attestationRaw
	mutate(raw[:])
	sig := rawSignature(t, f.issuerKey, raw[:])
	return base64.StdEncoding.EncodeToString(raw[:]),
		base64.StdEncoding.EncodeToString(sig[:])
}

// TestLongfellowProofVerifier_RejectsProofMutations exercises every rejection
// branch in VerifyApprovalProof (and the bundle/statement helpers) via
// targeted fixture mutations. Each case should fail if the corresponding
// production check is removed — per issue #313 fidelity guidance.
//
// One baseline fixture is built with attestedkeyzk.Prove (the expensive step)
// and shallow-copied per subtest. Every mutation either reassigns a whole
// field or writes into a value-type sub-struct/array, so shallow copies do
// not leak between cases.
func TestLongfellowProofVerifier_RejectsProofMutations(t *testing.T) {
	baseline := makeLongfellowProofFixture(t)

	cases := []struct {
		name      string
		mutate    func(t *testing.T, f *longfellowProofFixture)
		errSubstr string
	}{
		{
			name: "challenge_mismatch",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Challenge.Nonce = "different-nonce"
			},
			errSubstr: "approval proof challenge mismatch",
		},
		{
			name: "issuer_key_not_allowed",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("other issuer keygen: %v", err)
				}
				f.config.IssuerPublicKeyHexes = []string{compressedPublicKeyHex(t, &otherKey.PublicKey)}
			},
			errSubstr: "issuer public key is not allowed",
		},
		{
			name: "statement_app_id_hash_mismatch",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Statement.AppIDHashHex = strings.Repeat("00", 32)
			},
			errSubstr: "appIdHashHex mismatch",
		},
		{
			name: "statement_policy_version_mismatch",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Statement.PolicyVersion = 999
			},
			errSubstr: "policyVersion mismatch",
		},
		{
			name: "statement_challenge_nonce_mismatch",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Statement.ChallengeNonceHex = strings.Repeat("00", 32)
			},
			errSubstr: "challengeNonceHex mismatch",
		},
		{
			name: "statement_approval_hash_mismatch",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Statement.ApprovalHashHex = strings.Repeat("00", 32)
			},
			errSubstr: "approvalHashHex mismatch",
		},
		{
			name: "statement_clock_skew_out_of_range",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				statementTime := time.Unix(f.proof.Statement.Now, 0).UTC()
				skewed := statementTime.Add(24 * time.Hour)
				f.config.Now = func() time.Time { return skewed }
			},
			errSubstr: "outside the allowed clock skew",
		},
		{
			name: "attestation_bytes_not_base64",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Attestation.Bytes = "!!!not-base64"
			},
			errSubstr: "decode approval attestation bytes",
		},
		{
			name: "attestation_bytes_wrong_length",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Attestation.Bytes = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
			},
			errSubstr: "attestation bytes must be",
		},
		{
			name: "attestation_domain_mismatch",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					raw[0] = 'X'
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "attestation domain mismatch",
		},
		{
			name: "attestation_app_id_hash_mismatch",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					for i := 16; i < 48; i++ {
						raw[i] = 0
					}
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "attestation app ID hash mismatch",
		},
		{
			name: "attestation_policy_version_mismatch",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					binary.BigEndian.PutUint32(raw[48:52], 999)
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "attestation policy version mismatch",
		},
		{
			name: "attestation_key_class_mismatch",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					raw[52] = 0
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "attestation key class mismatch",
		},
		{
			name: "attestation_reserved_bytes_nonzero",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					raw[53] = 1
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "reserved bytes must be zero",
		},
		{
			name: "attestation_not_valid_at_statement_now",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				bytes, sig := mutateAndResignAttestation(t, f, func(raw []byte) {
					// Force notAfter < statementNow so the window check at
					// validateAttestationBundle line ~274 rejects.
					binary.BigEndian.PutUint64(raw[64:72], uint64(f.proof.Statement.Now-1))
				})
				f.proof.Attestation.Bytes = bytes
				f.proof.Attestation.Signature = sig
			},
			errSubstr: "attestation is not valid at statement.now",
		},
		{
			name: "attestation_signature_not_base64",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Attestation.Signature = "!!!not-base64"
			},
			errSubstr: "decode approval attestation signature",
		},
		{
			name: "attestation_signature_wrong_length",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Attestation.Signature = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
			},
			errSubstr: "signature must be",
		},
		{
			name: "attestation_signature_invalid",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				sig, err := base64.StdEncoding.DecodeString(f.proof.Attestation.Signature)
				if err != nil {
					t.Fatalf("decode baseline signature: %v", err)
				}
				sig[0] ^= 0xFF
				f.proof.Attestation.Signature = base64.StdEncoding.EncodeToString(sig)
			},
			errSubstr: "attestation signature is invalid",
		},
		{
			name: "proof_bytes_not_base64",
			mutate: func(_ *testing.T, f *longfellowProofFixture) {
				f.proof.Proof = "!!!not-base64"
			},
			errSubstr: "decode approval proof bytes",
		},
		{
			name: "zkp_verify_rejects_tampered_proof",
			mutate: func(t *testing.T, f *longfellowProofFixture) {
				raw, err := base64.StdEncoding.DecodeString(f.proof.Proof)
				if err != nil {
					t.Fatalf("decode baseline proof: %v", err)
				}
				if len(raw) == 0 {
					t.Fatal("baseline proof unexpectedly empty")
				}
				raw[len(raw)/2] ^= 0xFF
				f.proof.Proof = base64.StdEncoding.EncodeToString(raw)
			},
			errSubstr: "verify longfellow approval proof",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseline
			tc.mutate(t, &f)

			verifier, err := NewLongfellowProofVerifier(f.config)
			if err != nil {
				t.Fatalf("NewLongfellowProofVerifier: %v", err)
			}
			_, err = verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
				Challenge: f.challenge,
				Proof:     f.proof,
			})
			if err == nil {
				t.Fatalf("expected rejection containing %q", tc.errSubstr)
			}
			if !contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

// TestNewLongfellowProofVerifier_AcceptsPinnedCircuitIDWithMatchingBlob is a
// regression guard for ClarifiedLabs/ackagent-monorepo#336. The fix adds a
// fail-fast reject for pinned CircuitIDHex with an empty Circuit blob; this
// test locks in that the happy path — pinned ID plus the matching blob — is
// unaffected.
func TestNewLongfellowProofVerifier_AcceptsPinnedCircuitIDWithMatchingBlob(t *testing.T) {
	fixture := makeLongfellowProofFixture(t)

	circuitID, err := attestedkeyzk.CircuitID(fixture.config.Circuit)
	if err != nil {
		t.Fatalf("CircuitID: %v", err)
	}
	fixture.config.CircuitIDHex = hex.EncodeToString(circuitID[:])

	verifier, err := NewLongfellowProofVerifier(fixture.config)
	if err != nil {
		t.Fatalf("NewLongfellowProofVerifier: %v", err)
	}

	if _, err := verifier.VerifyApprovalProof(context.Background(), ApprovalProofVerificationRequest{
		Challenge: fixture.challenge,
		Proof:     fixture.proof,
	}); err != nil {
		t.Fatalf("VerifyApprovalProof: %v", err)
	}
}

// TestNewLongfellowProofVerifier_RejectsConfigErrors covers every rejection
// branch in the constructor. Each case fails if the corresponding production
// check is removed.
func TestNewLongfellowProofVerifier_RejectsConfigErrors(t *testing.T) {
	circuit := mustApprovalProofCircuit(t)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	baseline := LongfellowVerifierConfig{
		Audience:             "audience.example.com",
		AppID:                "com.example.app",
		PolicyVersion:        1,
		IssuerPublicKeyHexes: []string{compressedPublicKeyHex(t, &issuerKey.PublicKey)},
		Circuit:              circuit,
	}

	cases := []struct {
		name      string
		mutate    func(c *LongfellowVerifierConfig)
		errSubstr string
	}{
		{
			name:      "missing_audience",
			mutate:    func(c *LongfellowVerifierConfig) { c.Audience = "   " },
			errSubstr: "audience is required",
		},
		{
			name:      "missing_policy_version",
			mutate:    func(c *LongfellowVerifierConfig) { c.PolicyVersion = 0 },
			errSubstr: "policy version is required",
		},
		{
			name:      "missing_issuer_keys",
			mutate:    func(c *LongfellowVerifierConfig) { c.IssuerPublicKeyHexes = nil },
			errSubstr: "issuer public keys are required",
		},
		{
			name:      "invalid_issuer_key_hex",
			mutate:    func(c *LongfellowVerifierConfig) { c.IssuerPublicKeyHexes = []string{"not-hex"} },
			errSubstr: "invalid longfellow issuer public key",
		},
		{
			name: "missing_app_id_and_allowlist",
			mutate: func(c *LongfellowVerifierConfig) {
				c.AppID = ""
				c.AllowedAppIDHashesHex = nil
			},
			errSubstr: "app ID or allowed app ID hashes are required",
		},
		{
			name: "invalid_allowed_app_id_hash_hex",
			mutate: func(c *LongfellowVerifierConfig) {
				c.AppID = ""
				c.AllowedAppIDHashesHex = []string{"not-hex"}
			},
			errSubstr: "invalid longfellow app ID hash",
		},
		{
			name: "allowed_app_id_hash_wrong_length",
			mutate: func(c *LongfellowVerifierConfig) {
				c.AppID = ""
				c.AllowedAppIDHashesHex = []string{"00"}
			},
			errSubstr: fmt.Sprintf(
				"invalid longfellow app ID hash %q: expected %d bytes, got %d",
				"00", sha256.Size, 1,
			),
		},
		{
			name: "circuit_id_mismatch",
			mutate: func(c *LongfellowVerifierConfig) {
				c.CircuitIDHex = strings.Repeat("ab", 32)
			},
			errSubstr: "circuit ID mismatch",
		},
		{
			// Regression for ClarifiedLabs/ackagent-monorepo#336: pinning a
			// CircuitIDHex without shipping the matching blob must fail fast
			// rather than silently falling back to an expensive
			// GenerateCircuit() at startup.
			name: "pinned_circuit_id_without_circuit_blob",
			mutate: func(c *LongfellowVerifierConfig) {
				c.Circuit = nil
				c.CircuitIDHex = strings.Repeat("ab", 32)
			},
			errSubstr: "circuit blob is required when CircuitIDHex is pinned",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseline
			// Clone slices so per-case mutations cannot leak between subtests.
			cfg.IssuerPublicKeyHexes = append([]string(nil), baseline.IssuerPublicKeyHexes...)
			cfg.AllowedAppIDHashesHex = append([]string(nil), baseline.AllowedAppIDHashesHex...)
			tc.mutate(&cfg)

			_, err := NewLongfellowProofVerifier(cfg)
			if err == nil {
				t.Fatalf("expected constructor error containing %q", tc.errSubstr)
			}
			if !contains(err.Error(), tc.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}
