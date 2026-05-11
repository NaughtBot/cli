package transport

import (
	"context"
	"strings"
	"testing"

	"github.com/clarifiedlabs/ackagent-monorepo/ackagent-sdk/go/approval"
)

type mockApprovalProofVerifier struct {
	verify func(approval.ApprovalProofVerificationRequest) error
}

func (m mockApprovalProofVerifier) VerifyApprovalProof(
	_ context.Context,
	req approval.ApprovalProofVerificationRequest,
) (approval.ApprovalProofVerificationResult, error) {
	if m.verify != nil {
		return approval.ApprovalProofVerificationResult{}, m.verify(req)
	}
	return approval.ApprovalProofVerificationResult{}, nil
}

func TestVerifyApprovalProofFromJSON_SkipFlag(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{"status":"approved"}`),
		testApprovalChallenge(),
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("expected no error with skip=true, got: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_MissingVerifierFailsClosed(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{"status":"approved","approvalProof":{"version":"approval-attested-key-proof/v1"}}`),
		testApprovalChallenge(),
		nil,
		false,
	)
	if err == nil {
		t.Fatal("expected missing verifier error")
	}
	if !strings.Contains(err.Error(), "missing approval proof verifier") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_MissingApprovalProof(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{"status":"approved","signature":"abc"}`),
		testApprovalChallenge(),
		mockApprovalProofVerifier{},
		false,
	)
	if err == nil {
		t.Fatal("expected missing approval proof error")
	}
	if !strings.Contains(err.Error(), "missing approval proof") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_InvalidJSON(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`not-valid-json`),
		testApprovalChallenge(),
		mockApprovalProofVerifier{},
		false,
	)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
	if !strings.Contains(err.Error(), "failed to parse response") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_RejectionResponseSkipsVerification(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{"errorCode":1,"errorMessage":"User rejected the request"}`),
		testApprovalChallenge(),
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("expected no error for rejection response, got: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_ChallengeMismatch(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{
			"status":"approved",
			"approvalProof":{
				"version":"approval-attested-key-proof/v1",
				"challenge":{
					"version":"approval-challenge/v1",
					"nonce":"wrong-nonce",
					"requestId":"req-1",
					"plaintextHash":"sha256:abc123"
				},
				"statement":{
					"issuerPublicKeyHex":"02abc",
					"appIdHashHex":"abc123",
					"policyVersion":1,
					"now":1714761600,
					"challengeNonceHex":"abc123",
					"audienceHashHex":"abc123",
					"approvalHashHex":"abc123"
				},
				"attestation":{
					"version":"approval-attestation/v1",
					"bytes":"Ynl0ZXM=",
					"signature":"c2lnbmF0dXJl"
				},
				"proof":"cHJvb2Y="
			}
		}`),
		testApprovalChallenge(),
		mockApprovalProofVerifier{},
		false,
	)
	if err == nil {
		t.Fatal("expected approval challenge mismatch")
	}
	if !strings.Contains(err.Error(), "approval challenge mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyApprovalProofFromJSON_VerifierCalled(t *testing.T) {
	expected := testApprovalChallenge()
	called := false

	err := VerifyApprovalProofFromJSON(
		[]byte(`{
			"status":"approved",
			"approvalProof":{
				"version":"approval-attested-key-proof/v1",
				"challenge":{
					"version":"approval-challenge/v1",
					"nonce":"nonce-123",
					"requestId":"req-1",
					"plaintextHash":"sha256:abc123"
				},
				"statement":{
					"issuerPublicKeyHex":"02abc",
					"appIdHashHex":"abc123",
					"policyVersion":1,
					"now":1714761600,
					"challengeNonceHex":"abc123",
					"audienceHashHex":"abc123",
					"approvalHashHex":"abc123"
				},
				"attestation":{
					"version":"approval-attestation/v1",
					"bytes":"Ynl0ZXM=",
					"signature":"c2lnbmF0dXJl"
				},
				"proof":"cHJvb2Y="
			}
		}`),
		expected,
		mockApprovalProofVerifier{
			verify: func(req approval.ApprovalProofVerificationRequest) error {
				called = true
				if req.Challenge != expected {
					t.Fatalf("unexpected challenge passed to verifier: %#v", req.Challenge)
				}
				if req.Proof.Challenge != expected {
					t.Fatalf("unexpected proof challenge passed to verifier: %#v", req.Proof.Challenge)
				}
				return nil
			},
		},
		false,
	)
	if err != nil {
		t.Fatalf("expected verification success, got: %v", err)
	}
	if !called {
		t.Fatal("expected verifier to be called")
	}
}

func TestVerifyApprovalProofFromJSON_WrapsVerifierError(t *testing.T) {
	err := VerifyApprovalProofFromJSON(
		[]byte(`{
			"status":"approved",
			"approvalProof":{
				"version":"approval-attested-key-proof/v1",
				"challenge":{
					"version":"approval-challenge/v1",
					"nonce":"nonce-123",
					"requestId":"req-1",
					"plaintextHash":"sha256:abc123"
				},
				"statement":{
					"issuerPublicKeyHex":"02abc",
					"appIdHashHex":"abc123",
					"policyVersion":1,
					"now":1714761600,
					"challengeNonceHex":"abc123",
					"audienceHashHex":"abc123",
					"approvalHashHex":"abc123"
				},
				"attestation":{
					"version":"approval-attestation/v1",
					"bytes":"Ynl0ZXM=",
					"signature":"c2lnbmF0dXJl"
				},
				"proof":"cHJvb2Y="
			}
		}`),
		testApprovalChallenge(),
		mockApprovalProofVerifier{
			verify: func(req approval.ApprovalProofVerificationRequest) error {
				return context.DeadlineExceeded
			},
		},
		false,
	)
	if err == nil {
		t.Fatal("expected verifier error")
	}
	if !strings.Contains(err.Error(), "approval proof verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testApprovalChallenge() approval.ApprovalChallenge {
	return approval.ApprovalChallenge{
		Version:       approval.ApprovalChallengeVersion,
		Nonce:         "nonce-123",
		RequestID:     "req-1",
		PlaintextHash: "sha256:abc123",
	}
}
