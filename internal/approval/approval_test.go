package approval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
)

type mockDeviceLookup struct {
	devices map[string]DeviceInfo
}

func (m *mockDeviceLookup) GetDeviceBySigningPublicKey(_ context.Context, signingPublicKey []byte) (DeviceInfo, error) {
	key := hex.EncodeToString(signingPublicKey)
	device, ok := m.devices[key]
	if !ok {
		return DeviceInfo{}, fmt.Errorf("device not found: %s", key)
	}
	return device, nil
}

type mockNonceStore struct {
	mu     sync.Mutex
	nonces map[string]nonceEntry
}

type nonceEntry struct {
	requestID   string
	action      string
	actorUserID string
	consumed    bool
}

func newMockNonceStore() *mockNonceStore {
	return &mockNonceStore{nonces: make(map[string]nonceEntry)}
}

func (m *mockNonceStore) Create(_ context.Context, nonce, requestID, action, actorUserID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[nonce] = nonceEntry{
		requestID:   requestID,
		action:      action,
		actorUserID: actorUserID,
	}
	return nil
}

func (m *mockNonceStore) Consume(_ context.Context, nonce, requestID, actorUserID, action string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.nonces[nonce]
	if !ok {
		return fmt.Errorf("nonce not found: %s", nonce)
	}
	if entry.consumed {
		return fmt.Errorf("nonce already consumed: %s", nonce)
	}
	if entry.requestID != requestID {
		return fmt.Errorf("request id mismatch: expected %s, got %s", entry.requestID, requestID)
	}
	if entry.actorUserID != actorUserID {
		return fmt.Errorf("nonce does not belong to actor: %s", actorUserID)
	}
	if entry.action != action {
		return fmt.Errorf("nonce action mismatch: expected %s, got %s", entry.action, action)
	}
	entry.consumed = true
	m.nonces[nonce] = entry
	return nil
}

type mockProofVerifier struct {
	result   ApprovalProofVerificationResult
	err      error
	verify   func(ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error)
	requests []ApprovalProofVerificationRequest
}

func (m *mockProofVerifier) VerifyApprovalProof(_ context.Context, req ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error) {
	m.requests = append(m.requests, req)
	if m.verify != nil {
		return m.verify(req)
	}
	return m.result, m.err
}

func makeApprovalProof(t *testing.T, challenge ApprovalChallenge) ApprovalAttestedKeyProof {
	t.Helper()
	return ApprovalAttestedKeyProof{
		Version:     ApprovalAttestedKeyProofVersion,
		Challenge:   challenge,
		Statement:   mockApprovalProofStatement(),
		Attestation: mockApprovalAttestation(),
		Proof:       base64.StdEncoding.EncodeToString([]byte("mock-longfellow-proof")),
	}
}

func mockApprovalProofStatement() ApprovalProofStatement {
	return ApprovalProofStatement{
		IssuerPublicKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		AppIDHashHex:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PolicyVersion:      1,
		Now:                1714761600,
		ChallengeNonceHex:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AudienceHashHex:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ApprovalHashHex:    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
}

func mockApprovalAttestation() ApprovalAttestationV1 {
	return ApprovalAttestationV1{
		Version:   ApprovalAttestationVersion,
		Bytes:     base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		Signature: base64.StdEncoding.EncodeToString([]byte{5, 6, 7, 8}),
	}
}

func TestProofValidate_InvalidProofVersion(t *testing.T) {
	proof := ApprovalAttestedKeyProof{
		Version: "approval-attested-key-proof/v0",
		Challenge: ApprovalChallenge{
			Version:       ApprovalChallengeVersion,
			Nonce:         "n1",
			RequestID:     "rid-1",
			PlaintextHash: "sha256:deadbeef",
		},
		Statement:   mockApprovalProofStatement(),
		Attestation: mockApprovalAttestation(),
		Proof:       "proof",
	}

	if err := proof.Validate(); err == nil {
		t.Fatal("expected invalid proof version to fail")
	}
}

func TestCanonicalJSON(t *testing.T) {
	result, err := canonicalJSON(map[string]any{
		"nonce":  "abc",
		"action": "test_action",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != `{"action":"test_action","nonce":"abc"}` {
		t.Fatalf("unexpected canonical JSON: %s", result)
	}
}

func TestBuildApprovalChallenge(t *testing.T) {
	seed := ApprovalRequestSeed{
		Nonce:     "550e8400-e29b-41d4-a716-446655440000",
		RequestID: "123e4567-e89b-12d3-a456-426614174000",
	}
	actionFields := map[string]any{
		"action":         "update_member_role",
		"nonce":          seed.Nonce,
		"new_role":       "owner",
		"target_user_id": "user-xyz",
	}

	challenge, err := BuildApprovalChallenge(seed, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	expectedPlaintext := `{"action":"update_member_role","new_role":"owner","nonce":"550e8400-e29b-41d4-a716-446655440000","target_user_id":"user-xyz"}`
	expectedDigest := sha256.Sum256([]byte(expectedPlaintext))
	if challenge != (ApprovalChallenge{
		Version:       ApprovalChallengeVersion,
		Nonce:         seed.Nonce,
		RequestID:     seed.RequestID,
		PlaintextHash: "sha256:" + hex.EncodeToString(expectedDigest[:]),
	}) {
		t.Fatalf("unexpected challenge: %#v", challenge)
	}
}

func TestBuildApprovalChallenge_NonceMismatch(t *testing.T) {
	_, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "seed-nonce",
		RequestID: "rid-1",
	}, map[string]any{
		"action": "remove_member",
		"nonce":  "wrong-nonce",
	})
	if err == nil {
		t.Fatal("expected nonce mismatch")
	}
}

func TestBuildApprovalChallenge_RequiresAction(t *testing.T) {
	seed := ApprovalRequestSeed{
		Nonce:     "seed-nonce",
		RequestID: "rid-1",
	}

	tests := []struct {
		name         string
		actionFields map[string]any
	}{
		{
			name: "missing action",
			actionFields: map[string]any{
				"nonce": seed.Nonce,
			},
		},
		{
			name: "empty action",
			actionFields: map[string]any{
				"action": "",
				"nonce":  seed.Nonce,
			},
		},
		{
			name: "non string action",
			actionFields: map[string]any{
				"action": 123,
				"nonce":  seed.Nonce,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildApprovalChallenge(seed, tt.actionFields)
			if err == nil {
				t.Fatal("expected missing action error")
			}
			if !contains(err.Error(), "action fields must include an action") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyApproval_ValidProof(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{
			devices: map[string]DeviceInfo{
				hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
			},
		},
		&mockProofVerifier{
			result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
		},
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if err != nil {
		t.Fatalf("verifyApproval failed: %v", err)
	}
}

func TestVerifyApproval_ChallengeMismatch(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}
	challenge.PlaintextHash = "sha256:tampered"

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{
			devices: map[string]DeviceInfo{
				hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
			},
		},
		&mockProofVerifier{
			result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
		},
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if err == nil {
		t.Fatal("expected challenge mismatch")
	}
	if !contains(err.Error(), "approval challenge mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyApproval_ProofVerifierCalledWithCanonicalChallenge(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	proofVerifier := &mockProofVerifier{
		result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
	}

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{
			devices: map[string]DeviceInfo{
				hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
			},
		},
		proofVerifier,
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if err != nil {
		t.Fatalf("verifyApproval failed: %v", err)
	}
	if len(proofVerifier.requests) != 1 {
		t.Fatalf("expected one proof verification request, got %d", len(proofVerifier.requests))
	}
	if proofVerifier.requests[0].Challenge != challenge {
		t.Fatalf("expected verifier to receive canonical challenge")
	}
}

func TestVerifyApproval_ProofVerifierError(t *testing.T) {
	expectedErr := errors.New("proof invalid")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{},
		&mockProofVerifier{err: expectedErr},
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected proof verifier error, got %v", err)
	}
}

func TestVerifyApproval_DeviceNotFound(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{},
		&mockProofVerifier{
			result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
		},
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if err == nil {
		t.Fatal("expected device lookup failure")
	}
}

func TestVerifyApproval_WrongUser(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	err = verifyApproval(
		context.Background(),
		&mockDeviceLookup{
			devices: map[string]DeviceInfo{
				hex.EncodeToString(signingPublicKey): {UserID: "other-user", SigningPublicKey: signingPublicKey},
			},
		},
		&mockProofVerifier{
			result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
		},
		makeApprovalProof(t, challenge),
		"admin-user",
		actionFields,
	)
	if err == nil {
		t.Fatal("expected user mismatch")
	}
}

func TestVerifier_CreateAndVerify(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	devices := &mockDeviceLookup{
		devices: map[string]DeviceInfo{
			hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
		},
	}
	nonceStore := newMockNonceStore()
	verifier := NewVerifier(devices, nonceStore, WithApprovalProofVerifier(&mockProofVerifier{
		result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
	}))

	seed, err := verifier.CreateApprovalRequest(context.Background(), "update_member_role", "admin-user")
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}

	actionFields := map[string]any{
		"action": "update_member_role",
		"nonce":  seed.Nonce,
	}
	challenge, err := BuildApprovalChallenge(seed, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	if err := verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestVerifier_DefaultProofVerifierUnavailable(t *testing.T) {
	verifier := NewVerifier(&mockDeviceLookup{}, newMockNonceStore())
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  "n1",
	}
	challenge, err := BuildApprovalChallenge(ApprovalRequestSeed{
		Nonce:     "n1",
		RequestID: "rid-1",
	}, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}
	err = verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields)
	if !errors.Is(err, ErrApprovalProofVerifierUnavailable) {
		t.Fatalf("expected ErrApprovalProofVerifierUnavailable, got %v", err)
	}
}

func TestVerifier_ReplayRejected(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	devices := &mockDeviceLookup{
		devices: map[string]DeviceInfo{
			hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
		},
	}
	nonceStore := newMockNonceStore()
	verifier := NewVerifier(devices, nonceStore, WithApprovalProofVerifier(&mockProofVerifier{
		result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
	}))

	seed, err := verifier.CreateApprovalRequest(context.Background(), "remove_member", "admin-user")
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  seed.Nonce,
	}
	challenge, err := BuildApprovalChallenge(seed, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	if err := verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields); err != nil {
		t.Fatalf("first Verify failed: %v", err)
	}

	err = verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields)
	if err == nil {
		t.Fatal("expected replay to be rejected")
	}
	if !contains(err.Error(), "already consumed") {
		t.Fatalf("unexpected replay error: %v", err)
	}
}

func TestVerifier_CrossActionRejected(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	devices := &mockDeviceLookup{
		devices: map[string]DeviceInfo{
			hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
		},
	}
	nonceStore := newMockNonceStore()
	verifier := NewVerifier(devices, nonceStore, WithApprovalProofVerifier(&mockProofVerifier{
		result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
	}))

	seed, err := verifier.CreateApprovalRequest(context.Background(), "remove_member", "admin-user")
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}
	actionFields := map[string]any{
		"action": "update_member_role",
		"nonce":  seed.Nonce,
	}
	challenge, err := BuildApprovalChallenge(seed, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}

	err = verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields)
	if err == nil {
		t.Fatal("expected cross-action approval to fail")
	}
	if !contains(err.Error(), "action mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifier_RequestIDMismatchRejected(t *testing.T) {
	signingPublicKey := mustDecodeHex(t, "021111111111111111111111111111111111111111111111111111111111111111")
	devices := &mockDeviceLookup{
		devices: map[string]DeviceInfo{
			hex.EncodeToString(signingPublicKey): {UserID: "admin-user", SigningPublicKey: signingPublicKey},
		},
	}
	nonceStore := newMockNonceStore()
	verifier := NewVerifier(devices, nonceStore, WithApprovalProofVerifier(&mockProofVerifier{
		result: ApprovalProofVerificationResult{SigningPublicKey: signingPublicKey},
	}))

	seed, err := verifier.CreateApprovalRequest(context.Background(), "remove_member", "admin-user")
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}
	actionFields := map[string]any{
		"action": "remove_member",
		"nonce":  seed.Nonce,
	}
	challenge, err := BuildApprovalChallenge(seed, actionFields)
	if err != nil {
		t.Fatalf("BuildApprovalChallenge failed: %v", err)
	}
	challenge.RequestID = "wrong-request-id"

	err = verifier.Verify(context.Background(), makeApprovalProof(t, challenge), "admin-user", actionFields)
	if err == nil {
		t.Fatal("expected request id mismatch to fail")
	}
	if !contains(err.Error(), "request id mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && (func() bool {
		return stringContains(s, substr)
	})())
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
