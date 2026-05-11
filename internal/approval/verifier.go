package approval

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

var ErrApprovalProofVerifierUnavailable = errors.New("approval proof verification requires configuring WithLongfellowVerifierConfig or WithApprovalProofVerifier")

type verifierOptions struct {
	proofVerifier    ApprovalProofVerifier
	longfellowConfig *LongfellowVerifierConfig
}

// VerifierOption customizes approval proof verification.
type VerifierOption func(*verifierOptions)

// WithApprovalProofVerifier overrides the approval proof verifier implementation.
func WithApprovalProofVerifier(verifier ApprovalProofVerifier) VerifierOption {
	return func(opts *verifierOptions) {
		opts.proofVerifier = verifier
	}
}

// WithLongfellowVerifierConfig configures the built-in attested-key-zk proof
// verifier. When provided, callers do not need to implement ApprovalProofVerifier.
func WithLongfellowVerifierConfig(config LongfellowVerifierConfig) VerifierOption {
	return func(opts *verifierOptions) {
		opts.longfellowConfig = &config
	}
}

type defaultApprovalProofVerifier struct{}

func (defaultApprovalProofVerifier) VerifyApprovalProof(_ context.Context, _ ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error) {
	return ApprovalProofVerificationResult{}, ErrApprovalProofVerifierUnavailable
}

type initErrorApprovalProofVerifier struct {
	err error
}

func (v initErrorApprovalProofVerifier) VerifyApprovalProof(_ context.Context, _ ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error) {
	return ApprovalProofVerificationResult{}, v.err
}

// Verifier ties together device lookup, nonce management, and proof
// verification. It provides the high-level API for server-mediated approval
// with replay prevention.
type Verifier struct {
	devices       DeviceLookup
	nonces        NonceStore
	proofVerifier ApprovalProofVerifier
}

// NewVerifier creates a Verifier with the given device lookup and nonce store.
func NewVerifier(devices DeviceLookup, nonces NonceStore, opts ...VerifierOption) *Verifier {
	cfg := verifierOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	proofVerifier := cfg.proofVerifier
	if proofVerifier == nil && cfg.longfellowConfig != nil {
		built, err := NewLongfellowProofVerifier(*cfg.longfellowConfig)
		if err != nil {
			proofVerifier = initErrorApprovalProofVerifier{err: err}
		} else {
			proofVerifier = built
		}
	}
	if proofVerifier == nil {
		proofVerifier = defaultApprovalProofVerifier{}
	}

	return &Verifier{
		devices:       devices,
		nonces:        nonces,
		proofVerifier: proofVerifier,
	}
}

// CreateApprovalRequest generates the server-side approval seed for a privileged action.
func (v *Verifier) CreateApprovalRequest(ctx context.Context, action, actorUserID string) (ApprovalRequestSeed, error) {
	nonce, err := generateUUID()
	if err != nil {
		return ApprovalRequestSeed{}, err
	}
	requestID, err := generateUUID()
	if err != nil {
		return ApprovalRequestSeed{}, err
	}
	if err := v.nonces.Create(ctx, nonce, requestID, action, actorUserID); err != nil {
		return ApprovalRequestSeed{}, err
	}
	return ApprovalRequestSeed{
		Nonce:     nonce,
		RequestID: requestID,
	}, nil
}

// Verify validates an approval proof and atomically consumes the nonce.
// Callers are responsible for decoding the ApprovalAttestedKeyProof from
// their transport (request body, E2EE envelope, etc.) before calling this —
// the proof is not carried as an HTTP header because a Longfellow proof
// serializes to ~510 KB and exceeds typical CDN/proxy per-header limits.
// The proof is verified before the nonce is consumed to prevent DoS via
// nonce burning with invalid proofs.
func (v *Verifier) Verify(ctx context.Context, proof ApprovalAttestedKeyProof, actorUserID string, actionFields map[string]any) error {
	if err := proof.validate(); err != nil {
		return fmt.Errorf("invalid approval proof: %w", err)
	}

	if err := verifyApproval(ctx, v.devices, v.proofVerifier, proof, actorUserID, actionFields); err != nil {
		return err
	}

	action, _ := actionFields["action"].(string)
	return v.nonces.Consume(
		ctx,
		proof.Challenge.Nonce,
		proof.Challenge.RequestID,
		actorUserID,
		action,
	)
}

// generateUUID generates a crypto/rand-based v4 UUID string.
func generateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}
