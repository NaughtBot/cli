package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// canonicalJSON produces a deterministic JSON string with sorted keys.
// This matches the frontend's canonicalJSON implementation:
// JSON.stringify(obj, Object.keys(obj).sort())
func canonicalJSON(fields map[string]any) (string, error) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]byte, 0, 256)
	ordered = append(ordered, '{')
	for i, k := range keys {
		if i > 0 {
			ordered = append(ordered, ',')
		}
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return "", err
		}
		valJSON, err := json.Marshal(fields[k])
		if err != nil {
			return "", err
		}
		ordered = append(ordered, keyJSON...)
		ordered = append(ordered, ':')
		ordered = append(ordered, valJSON...)
	}
	ordered = append(ordered, '}')

	return string(ordered), nil
}

// BuildApprovalChallenge canonicalizes the approval payload and binds it to the
// server-issued nonce/request pair.
func BuildApprovalChallenge(seed ApprovalRequestSeed, actionFields map[string]any) (ApprovalChallenge, error) {
	if seed.Nonce == "" {
		return ApprovalChallenge{}, fmt.Errorf("approval seed nonce is required")
	}
	if seed.RequestID == "" {
		return ApprovalChallenge{}, fmt.Errorf("approval seed request id is required")
	}
	action, ok := actionFields["action"].(string)
	if !ok || action == "" {
		return ApprovalChallenge{}, fmt.Errorf("action fields must include an action")
	}

	nonce, ok := actionFields["nonce"].(string)
	if !ok || nonce == "" {
		return ApprovalChallenge{}, fmt.Errorf("action fields must include a nonce")
	}
	if nonce != seed.Nonce {
		return ApprovalChallenge{}, fmt.Errorf("nonce mismatch")
	}

	plaintext, err := canonicalJSON(actionFields)
	if err != nil {
		return ApprovalChallenge{}, fmt.Errorf("failed to construct canonical plaintext: %w", err)
	}
	hash := sha256.Sum256([]byte(plaintext))

	return ApprovalChallenge{
		Version:       ApprovalChallengeVersion,
		Nonce:         seed.Nonce,
		RequestID:     seed.RequestID,
		PlaintextHash: "sha256:" + hex.EncodeToString(hash[:]),
	}, nil
}

// verifyApproval verifies the approval proof for a privileged admin action.
// This performs crypto-only verification without nonce store interaction.
func verifyApproval(
	ctx context.Context,
	devices DeviceLookup,
	proofVerifier ApprovalProofVerifier,
	proof ApprovalAttestedKeyProof,
	actorUserID string,
	actionFields map[string]any,
) error {
	expectedChallenge, err := BuildApprovalChallenge(
		ApprovalRequestSeed{
			Nonce:     proof.Challenge.Nonce,
			RequestID: proof.Challenge.RequestID,
		},
		actionFields,
	)
	if err != nil {
		return err
	}

	if proof.Challenge != expectedChallenge {
		return fmt.Errorf("approval challenge mismatch")
	}

	result, err := proofVerifier.VerifyApprovalProof(ctx, ApprovalProofVerificationRequest{
		Challenge: proof.Challenge,
		Proof:     proof,
	})
	if err != nil {
		return err
	}
	// Longfellow/attested-key-zk proofs intentionally hide the device signing
	// key, so the verifier returns an empty SigningPublicKey and the key-based
	// device lookup is skipped. Binding the approval to actorUserID is still
	// enforced: the server-issued nonce is created under actorUserID (see
	// Verifier.CreateApprovalRequest) and Verifier.Verify atomically consumes
	// it against that same actorUserID via NonceStore.Consume, which fails if
	// a different user tries to spend it. Verifiers that DO expose a signing
	// key (e.g. a legacy signature-based verifier passed via
	// WithApprovalProofVerifier) still get the device-ownership cross-check
	// below.
	if len(result.SigningPublicKey) == 0 || devices == nil {
		return nil
	}

	device, err := devices.GetDeviceBySigningPublicKey(ctx, result.SigningPublicKey)
	if err != nil {
		return fmt.Errorf("device lookup failed: %w", err)
	}
	if device.UserID != actorUserID {
		return fmt.Errorf("device does not belong to the acting user")
	}

	return nil
}
