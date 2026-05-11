package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	attestedkeyzk "github.com/naughtbot/attested-key-zk/bindings/go"
)

const (
	longfellowAttestationLength = 136
	longfellowSignatureLength   = 64
	longfellowDomainLength      = 16
	longfellowSecureKeyClass    = 1
)

var longfellowAttestationDomain = [longfellowDomainLength]byte{
	'A', 'K', 'Z', 'K', '-', 'A', 'T', 'T',
	'E', 'S', 'T', '-', 'K', 'E', 'Y', '1',
}

// LongfellowVerifierConfig configures the built-in attested-key-zk approval
// verifier.
type LongfellowVerifierConfig struct {
	Audience              string
	AppID                 string
	AllowedAppIDHashesHex []string
	PolicyVersion         uint32
	IssuerPublicKeyHexes  []string
	Circuit               []byte
	CircuitIDHex          string
	Now                   func() time.Time
	MaxClockSkew          time.Duration
}

type longfellowProofVerifier struct {
	circuit            []byte
	allowedIssuerKeys  map[string]struct{}
	allowedAppIDHashes map[string]struct{}
	audienceHash       [32]byte
	policyVersion      uint32
	now                func() time.Time
	maxClockSkew       time.Duration
}

// NewLongfellowProofVerifier constructs the built-in attested-key-zk verifier.
func NewLongfellowProofVerifier(config LongfellowVerifierConfig) (ApprovalProofVerifier, error) {
	if strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("longfellow verifier audience is required")
	}
	if config.PolicyVersion == 0 {
		return nil, fmt.Errorf("longfellow verifier policy version is required")
	}
	if len(config.IssuerPublicKeyHexes) == 0 {
		return nil, fmt.Errorf("longfellow verifier issuer public keys are required")
	}

	allowedIssuerKeys := make(map[string]struct{}, len(config.IssuerPublicKeyHexes))
	for _, candidate := range config.IssuerPublicKeyHexes {
		_, normalizedHex, err := parseCompressedP256PublicKeyHex(candidate)
		if err != nil {
			return nil, fmt.Errorf("invalid longfellow issuer public key: %w", err)
		}
		allowedIssuerKeys[normalizedHex] = struct{}{}
	}

	allowedAppIDHashes := make(map[string]struct{}, len(config.AllowedAppIDHashesHex)+1)
	if appID := strings.TrimSpace(config.AppID); appID != "" {
		appIDHash := sha256.Sum256([]byte(appID))
		allowedAppIDHashes[hex.EncodeToString(appIDHash[:])] = struct{}{}
	}
	for _, candidate := range config.AllowedAppIDHashesHex {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" {
			continue
		}
		raw, err := hex.DecodeString(normalized)
		if err != nil {
			return nil, fmt.Errorf("invalid longfellow app ID hash: %w", err)
		}
		if len(raw) != sha256.Size {
			return nil, fmt.Errorf(
				"invalid longfellow app ID hash %q: expected %d bytes, got %d",
				normalized, sha256.Size, len(raw),
			)
		}
		allowedAppIDHashes[normalized] = struct{}{}
	}
	if len(allowedAppIDHashes) == 0 {
		return nil, fmt.Errorf("longfellow verifier app ID or allowed app ID hashes are required")
	}

	circuit := append([]byte(nil), config.Circuit...)
	if len(circuit) == 0 && strings.TrimSpace(config.CircuitIDHex) != "" {
		return nil, fmt.Errorf("longfellow circuit blob is required when CircuitIDHex is pinned")
	}
	if len(circuit) == 0 {
		generated, err := attestedkeyzk.GenerateCircuit()
		if err != nil {
			return nil, fmt.Errorf("generate longfellow circuit: %w", err)
		}
		circuit = generated
	}

	if expectedID := strings.TrimSpace(config.CircuitIDHex); expectedID != "" {
		actualID, err := attestedkeyzk.CircuitID(circuit)
		if err != nil {
			return nil, fmt.Errorf("compute longfellow circuit ID: %w", err)
		}
		if hex.EncodeToString(actualID[:]) != strings.ToLower(expectedID) {
			return nil, fmt.Errorf("longfellow circuit ID mismatch")
		}
	}

	nowFn := config.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	maxClockSkew := config.MaxClockSkew
	if maxClockSkew <= 0 {
		maxClockSkew = 5 * time.Minute
	}

	return &longfellowProofVerifier{
		circuit:            circuit,
		allowedIssuerKeys:  allowedIssuerKeys,
		allowedAppIDHashes: allowedAppIDHashes,
		audienceHash:       sha256.Sum256([]byte(config.Audience)),
		policyVersion:      config.PolicyVersion,
		now:                nowFn,
		maxClockSkew:       maxClockSkew,
	}, nil
}

func (v *longfellowProofVerifier) VerifyApprovalProof(_ context.Context, req ApprovalProofVerificationRequest) (ApprovalProofVerificationResult, error) {
	if err := req.Challenge.validate(); err != nil {
		return ApprovalProofVerificationResult{}, err
	}
	if err := req.Proof.validate(); err != nil {
		return ApprovalProofVerificationResult{}, err
	}
	if req.Proof.Challenge != req.Challenge {
		return ApprovalProofVerificationResult{}, fmt.Errorf("approval proof challenge mismatch")
	}

	issuerPublicKey, issuerKeyHex, statement, err := v.statementFromProof(req.Proof.Statement)
	if err != nil {
		return ApprovalProofVerificationResult{}, err
	}
	if _, ok := v.allowedIssuerKeys[issuerKeyHex]; !ok {
		return ApprovalProofVerificationResult{}, fmt.Errorf("approval proof issuer public key is not allowed")
	}
	if err := v.validateStatement(req.Challenge, req.Proof.Statement); err != nil {
		return ApprovalProofVerificationResult{}, err
	}
	if err := validateAttestationBundle(req.Proof.Attestation, req.Proof.Statement, issuerPublicKey); err != nil {
		return ApprovalProofVerificationResult{}, err
	}

	proofBytes, err := base64.StdEncoding.DecodeString(req.Proof.Proof)
	if err != nil {
		return ApprovalProofVerificationResult{}, fmt.Errorf("decode approval proof bytes: %w", err)
	}
	if len(proofBytes) == 0 {
		return ApprovalProofVerificationResult{}, fmt.Errorf("approval proof bytes are required")
	}

	if err := attestedkeyzk.Verify(v.circuit, statement, proofBytes); err != nil {
		return ApprovalProofVerificationResult{}, fmt.Errorf("verify longfellow approval proof: %w", err)
	}

	return ApprovalProofVerificationResult{}, nil
}

func (v *longfellowProofVerifier) validateStatement(challenge ApprovalChallenge, statement ApprovalProofStatement) error {
	if _, ok := v.allowedAppIDHashes[strings.ToLower(statement.AppIDHashHex)]; !ok {
		return fmt.Errorf("approval proof statement appIdHashHex mismatch")
	}
	if statement.PolicyVersion != v.policyVersion {
		return fmt.Errorf("approval proof statement policyVersion mismatch")
	}
	if !strings.EqualFold(statement.AudienceHashHex, hex.EncodeToString(v.audienceHash[:])) {
		return fmt.Errorf("approval proof statement audienceHashHex mismatch")
	}

	challengeNonce := sha256.Sum256([]byte(challenge.Nonce))
	if !strings.EqualFold(statement.ChallengeNonceHex, hex.EncodeToString(challengeNonce[:])) {
		return fmt.Errorf("approval proof statement challengeNonceHex mismatch")
	}

	challengeJSON, err := canonicalApprovalChallengeJSON(challenge)
	if err != nil {
		return fmt.Errorf("canonicalize approval challenge: %w", err)
	}
	approvalHash := sha256.Sum256([]byte(challengeJSON))
	if !strings.EqualFold(statement.ApprovalHashHex, hex.EncodeToString(approvalHash[:])) {
		return fmt.Errorf("approval proof statement approvalHashHex mismatch")
	}

	statementTime := time.Unix(statement.Now, 0).UTC()
	now := v.now().UTC()
	skew := now.Sub(statementTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > v.maxClockSkew {
		return fmt.Errorf("approval proof statement now is outside the allowed clock skew")
	}

	return nil
}

func (v *longfellowProofVerifier) statementFromProof(statement ApprovalProofStatement) (*ecdsa.PublicKey, string, attestedkeyzk.Statement, error) {
	issuerPublicKey, issuerKeyHex, err := parseCompressedP256PublicKeyHex(statement.IssuerPublicKeyHex)
	if err != nil {
		return nil, "", attestedkeyzk.Statement{}, fmt.Errorf("parse approval proof issuer public key: %w", err)
	}

	var parsed attestedkeyzk.Statement
	fillFixed32(parsed.IssuerPublicKeyX[:], issuerPublicKey.X)
	fillFixed32(parsed.IssuerPublicKeyY[:], issuerPublicKey.Y)

	if err := decodeHexInto(parsed.AppIDHash[:], statement.AppIDHashHex, "appIdHashHex"); err != nil {
		return nil, "", attestedkeyzk.Statement{}, err
	}
	binary.BigEndian.PutUint32(parsed.PolicyVersion[:], statement.PolicyVersion)
	if statement.Now <= 0 {
		return nil, "", attestedkeyzk.Statement{}, fmt.Errorf("approval proof statement now is required")
	}
	binary.BigEndian.PutUint64(parsed.Now[:], uint64(statement.Now))
	if err := decodeHexInto(parsed.ChallengeNonce[:], statement.ChallengeNonceHex, "challengeNonceHex"); err != nil {
		return nil, "", attestedkeyzk.Statement{}, err
	}
	if err := decodeHexInto(parsed.AudienceHash[:], statement.AudienceHashHex, "audienceHashHex"); err != nil {
		return nil, "", attestedkeyzk.Statement{}, err
	}
	if err := decodeHexInto(parsed.ApprovalHash[:], statement.ApprovalHashHex, "approvalHashHex"); err != nil {
		return nil, "", attestedkeyzk.Statement{}, err
	}

	return issuerPublicKey, issuerKeyHex, parsed, nil
}

func validateAttestationBundle(attestation ApprovalAttestationV1, statement ApprovalProofStatement, issuerPublicKey *ecdsa.PublicKey) error {
	attestationBytes, err := base64.StdEncoding.DecodeString(attestation.Bytes)
	if err != nil {
		return fmt.Errorf("decode approval attestation bytes: %w", err)
	}
	if len(attestationBytes) != longfellowAttestationLength {
		return fmt.Errorf("approval attestation bytes must be %d bytes", longfellowAttestationLength)
	}
	if string(attestationBytes[:longfellowDomainLength]) != string(longfellowAttestationDomain[:]) {
		return fmt.Errorf("approval attestation domain mismatch")
	}
	if !strings.EqualFold(statement.AppIDHashHex, hex.EncodeToString(attestationBytes[16:48])) {
		return fmt.Errorf("approval attestation app ID hash mismatch")
	}
	if binary.BigEndian.Uint32(attestationBytes[48:52]) != statement.PolicyVersion {
		return fmt.Errorf("approval attestation policy version mismatch")
	}
	if attestationBytes[52] != longfellowSecureKeyClass {
		return fmt.Errorf("approval attestation key class mismatch")
	}
	if attestationBytes[53] != 0 || attestationBytes[54] != 0 || attestationBytes[55] != 0 {
		return fmt.Errorf("approval attestation reserved bytes must be zero")
	}

	statementNow := uint64(statement.Now)
	notBefore := binary.BigEndian.Uint64(attestationBytes[56:64])
	notAfter := binary.BigEndian.Uint64(attestationBytes[64:72])
	if statementNow < notBefore || statementNow > notAfter {
		return fmt.Errorf("approval attestation is not valid at statement.now")
	}

	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil {
		return fmt.Errorf("decode approval attestation signature: %w", err)
	}
	if len(signature) != longfellowSignatureLength {
		return fmt.Errorf("approval attestation signature must be %d bytes", longfellowSignatureLength)
	}

	digest := sha256.Sum256(attestationBytes)
	var r, s big.Int
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])
	if err := rejectHighSSignature(issuerPublicKey, &s); err != nil {
		return err
	}
	if !ecdsa.Verify(issuerPublicKey, digest[:], &r, &s) {
		return fmt.Errorf("approval attestation signature is invalid")
	}

	return nil
}

func rejectHighSSignature(publicKey *ecdsa.PublicKey, s *big.Int) error {
	halfOrder := new(big.Int).Rsh(publicKey.Curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		return fmt.Errorf("approval attestation signature is non-canonical (high-S)")
	}
	return nil
}

// canonicalApprovalChallengeJSON emits a deterministic JSON encoding of the
// fields produced by json.Marshal(challenge), sorted by JSON key. The hash of
// this encoding is committed to the Longfellow approval circuit, so this must
// track the struct's JSON shape rather than a hand-maintained key list —
// adding a wire-visible field without updating this function would otherwise
// silently drop the field out of the circuit-bound approvalHash. Driving the
// canonical form from json.Marshal removes that footgun.
//
// Because the canonical form follows json.Marshal semantics, fields the
// standard library excludes (json:"-" fields and omitempty zero-values) are
// also absent here. Any wire-bearing field added to ApprovalChallenge is
// automatically picked up; adding a field tagged json:"-" deliberately keeps
// it out of the circuit commitment.
//
// Field values are preserved as raw JSON bytes so the re-emitted encoding is
// byte-identical to what json.Marshal(challenge) produced for each field.
func canonicalApprovalChallengeJSON(challenge ApprovalChallenge) (string, error) {
	encoded, err := json.Marshal(challenge)
	if err != nil {
		return "", fmt.Errorf("marshal approval challenge: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return "", fmt.Errorf("parse approval challenge: %w", err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return "", fmt.Errorf("marshal approval challenge key: %w", err)
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(fields[key])
	}
	buf.WriteByte('}')
	return buf.String(), nil
}

func parseCompressedP256PublicKeyHex(value string) (*ecdsa.PublicKey, string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, "", fmt.Errorf("decode hex: %w", err)
	}
	if len(raw) != 33 {
		return nil, "", fmt.Errorf("compressed P-256 public key must be 33 bytes")
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	if x == nil || y == nil {
		return nil, "", fmt.Errorf("invalid compressed P-256 public key")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, hex.EncodeToString(raw), nil
}

func decodeHexInto(dst []byte, value, field string) error {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("decode approval proof statement %s: %w", field, err)
	}
	if len(raw) != len(dst) {
		return fmt.Errorf("approval proof statement %s must be %d bytes", field, len(dst))
	}
	copy(dst, raw)
	return nil
}

func fillFixed32(dst []byte, n *big.Int) {
	for i := range dst {
		dst[i] = 0
	}
	src := n.Bytes()
	copy(dst[len(dst)-len(src):], src)
}
