package transport

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/naughtbot/cli/internal/approval"
)

// approvalProofWrapper extracts the approval proof and error fields from any
// decrypted response type without depending on the full response schema.
type approvalProofWrapper struct {
	ApprovalProof json.RawMessage `json:"approvalProof"`
	ErrorCode     *int            `json:"errorCode"`
}

// VerifyApprovalProofFromJSON extracts and verifies the approval proof from a
// decrypted response JSON blob.
//
// If skip is true, verification is bypassed entirely.
// Rejection/error responses skip proof verification because they do not carry an
// approval proof.
// Otherwise, a successful approval response must contain an approvalProof that
// matches the expected challenge and verifies against the configured
// Longfellow verifier.
func VerifyApprovalProofFromJSON(
	decrypted []byte,
	expectedChallenge approval.ApprovalChallenge,
	verifier approval.ApprovalProofVerifier,
	skip bool,
) error {
	if skip {
		tlog.Debug("VerifyApprovalProof: skipped (skip=true) request_id=%s", expectedChallenge.RequestID)
		return nil
	}

	var wrapper approvalProofWrapper
	if err := json.Unmarshal(decrypted, &wrapper); err != nil {
		return fmt.Errorf("failed to parse response for approval proof: %w", err)
	}

	if wrapper.ErrorCode != nil {
		return nil
	}
	if verifier == nil {
		return fmt.Errorf("missing approval proof verifier")
	}
	if len(wrapper.ApprovalProof) == 0 || string(wrapper.ApprovalProof) == "null" {
		return fmt.Errorf("missing approval proof in approval response")
	}

	var proof approval.ApprovalAttestedKeyProof
	if err := json.Unmarshal(wrapper.ApprovalProof, &proof); err != nil {
		return fmt.Errorf("failed to decode approval proof: %w", err)
	}
	if proof.Challenge != expectedChallenge {
		return fmt.Errorf("approval challenge mismatch")
	}
	if _, err := verifier.VerifyApprovalProof(context.Background(), approval.ApprovalProofVerificationRequest{
		Challenge: expectedChallenge,
		Proof:     proof,
	}); err != nil {
		return fmt.Errorf("approval proof verification failed: %w", err)
	}
	return nil
}
