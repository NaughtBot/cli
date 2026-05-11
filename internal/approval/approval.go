// Package approval provides server-mediated approval verification with replay
// prevention for privileged admin actions. It validates canonical approval
// challenges and verifies Longfellow proofs for circuit-native approval flows.
package approval

import (
	"context"
	"fmt"
)

const (
	// ApprovalChallengeVersion is the canonical approval challenge format.
	ApprovalChallengeVersion = "approval-challenge/v1"
	// ApprovalAttestationVersion is the circuit-native attestation envelope.
	ApprovalAttestationVersion = "approval-attestation/v1"
	// ApprovalAttestedKeyProofVersion is the canonical attested-key proof format.
	ApprovalAttestedKeyProofVersion = "approval-attested-key-proof/v1"
)

// DeviceInfo holds the fields needed for approval verification.
type DeviceInfo struct {
	UserID           string
	SigningPublicKey []byte // 33-byte compressed P-256 (0x02/0x03 || X)
}

// DeviceLookup resolves a device signing public key to its ownership info.
type DeviceLookup interface {
	// GetDeviceBySigningPublicKey returns the device info for the given signing
	// public key.
	// Returns an error if the device is not found.
	GetDeviceBySigningPublicKey(ctx context.Context, signingPublicKey []byte) (DeviceInfo, error)
}

// NonceStore manages nonce lifecycle for replay prevention.
type NonceStore interface {
	// Create stores a new nonce/request pair associated with an action and actor.
	Create(ctx context.Context, nonce, requestID, action, actorUserID string) error
	// Consume atomically marks a nonce/request pair as used. Returns an error if
	// the pair does not exist, has already been consumed, does not belong to the
	// actor, or was issued for a different action.
	Consume(ctx context.Context, nonce, requestID, actorUserID, action string) error
}

// ApprovalChallenge is the canonical verifier-issued challenge that the
// attested-key proof binds to.
//
// JSON tags use snake_case to match the canonical
// e2ee-payloads schema (`ApprovalChallenge` in
// `github.com/naughtbot/e2ee-payloads/go`); the canonical-JSON hash is
// committed to the Longfellow approval circuit so the casing must match the
// approver-side serialization byte-for-byte.
type ApprovalChallenge struct {
	Version       string `json:"version"`
	Nonce         string `json:"nonce"`
	RequestID     string `json:"request_id"`
	PlaintextHash string `json:"plaintext_hash"`
}

// ApprovalProofStatement is the public Longfellow statement carried alongside a
// circuit-native proof.
//
// JSON tags use snake_case to match the canonical e2ee-payloads schema.
type ApprovalProofStatement struct {
	IssuerPublicKeyHex string `json:"issuer_public_key_hex"`
	AppIDHashHex       string `json:"app_id_hash_hex"`
	PolicyVersion      uint32 `json:"policy_version"`
	Now                int64  `json:"now"`
	ChallengeNonceHex  string `json:"challenge_nonce_hex"`
	AudienceHashHex    string `json:"audience_hash_hex"`
	ApprovalHashHex    string `json:"approval_hash_hex"`
}

// ApprovalAttestationV1 carries the service-issued AttestationV1 bytes and raw
// P-256 signature.
type ApprovalAttestationV1 struct {
	Version   string `json:"version"`
	Bytes     string `json:"bytes"`
	Signature string `json:"signature"`
}

// ApprovalAttestedKeyProof is the canonical Longfellow proof payload carried in
// approval requests.
type ApprovalAttestedKeyProof struct {
	Version     string                 `json:"version"`
	Challenge   ApprovalChallenge      `json:"challenge"`
	Statement   ApprovalProofStatement `json:"statement"`
	Attestation ApprovalAttestationV1  `json:"attestation"`
	Proof       string                 `json:"proof"`
}

// ApprovalProofVerificationRequest contains the proof material that callers can
// pass to their Longfellow verifier implementation.
type ApprovalProofVerificationRequest struct {
	Challenge ApprovalChallenge
	Proof     ApprovalAttestedKeyProof
}

// ApprovalProofVerificationResult contains verifier-derived metadata needed by
// the SDK. signing_public_key is optional because circuit-native Longfellow
// proofs do not reveal the hidden device key.
type ApprovalProofVerificationResult struct {
	SigningPublicKey []byte
}

// ApprovalProofVerifier verifies the approval proof and returns the attested
// signing public key when the verifier format exposes one.
type ApprovalProofVerifier interface {
	VerifyApprovalProof(ctx context.Context, req ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error)
}

// ApprovalRequestSeed is the server-issued material the client must bind into
// the approval flow. Nonce protects the signed plaintext; RequestID scopes the
// relay request and challenge to this specific approval request.
type ApprovalRequestSeed struct {
	Nonce     string
	RequestID string
}

// Validate reports structural problems with an ApprovalAttestedKeyProof. The
// approval proof is carried in request bodies (for example inside the relay's
// encrypted E2EE response envelope) rather than as an HTTP header, because a
// Longfellow proof serializes to ~510 KB once JSON- and base64-wrapped — far
// past common CDN/proxy per-header limits (8–16 KB). Callers should decode
// the proof from whatever wire format they use and call Validate before
// handing it to Verifier.Verify.
func (proof ApprovalAttestedKeyProof) Validate() error {
	return proof.validate()
}

func (challenge ApprovalChallenge) validate() error {
	if challenge.Version != ApprovalChallengeVersion {
		return fmt.Errorf("unsupported approval challenge version %q", challenge.Version)
	}
	if challenge.Nonce == "" {
		return fmt.Errorf("approval challenge nonce is required")
	}
	if challenge.RequestID == "" {
		return fmt.Errorf("approval challenge requestId is required")
	}
	if challenge.PlaintextHash == "" {
		return fmt.Errorf("approval challenge plaintextHash is required")
	}
	return nil
}

func (proof ApprovalAttestedKeyProof) validate() error {
	if proof.Version != ApprovalAttestedKeyProofVersion {
		return fmt.Errorf("unsupported approval proof version %q", proof.Version)
	}
	if err := proof.Challenge.validate(); err != nil {
		return err
	}
	if err := proof.Statement.validate(); err != nil {
		return err
	}
	if err := proof.Attestation.validate(); err != nil {
		return err
	}
	if proof.Proof == "" {
		return fmt.Errorf("approval proof payload is required")
	}
	return nil
}

func (statement ApprovalProofStatement) validate() error {
	if statement.IssuerPublicKeyHex == "" {
		return fmt.Errorf("approval proof statement issuerPublicKeyHex is required")
	}
	if statement.AppIDHashHex == "" {
		return fmt.Errorf("approval proof statement appIdHashHex is required")
	}
	if statement.PolicyVersion == 0 {
		return fmt.Errorf("approval proof statement policyVersion is required")
	}
	if statement.Now <= 0 {
		return fmt.Errorf("approval proof statement now is required")
	}
	if statement.ChallengeNonceHex == "" {
		return fmt.Errorf("approval proof statement challengeNonceHex is required")
	}
	if statement.AudienceHashHex == "" {
		return fmt.Errorf("approval proof statement audienceHashHex is required")
	}
	if statement.ApprovalHashHex == "" {
		return fmt.Errorf("approval proof statement approvalHashHex is required")
	}
	return nil
}

func (attestation ApprovalAttestationV1) validate() error {
	if attestation.Version != ApprovalAttestationVersion {
		return fmt.Errorf("unsupported approval attestation version %q", attestation.Version)
	}
	if attestation.Bytes == "" {
		return fmt.Errorf("approval attestation bytes are required")
	}
	if attestation.Signature == "" {
		return fmt.Errorf("approval attestation signature is required")
	}
	return nil
}
