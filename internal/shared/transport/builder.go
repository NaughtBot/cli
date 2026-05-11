package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/naughtbot/cli/internal/approval"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/google/uuid"

	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/multidevice"
)

// ErrNoApproverKeys is returned when the account has no active approver
// encryption keys available for multi-device wrapping.
var ErrNoApproverKeys = fmt.Errorf("no approver device keys available: re-run 'nb login' or register a device")

// ErrApprovalProofCircuitPinningRequired is returned when a managed issuer
// does not provide the expected circuit pin for approval proof verification.
var ErrApprovalProofCircuitPinningRequired = errors.New("approval proof circuit pinning required for managed issuer")

// RequestResult contains the response and decryption context from a request.
type RequestResult struct {
	// Response is the transport response
	Response *Response

	// EphemeralPrivate is the requester's ephemeral private key for response decryption
	EphemeralPrivate []byte

	// RequestID is the request ID bytes for key derivation
	RequestID []byte

	// ExpectedApprovalChallenge is the explicit approval challenge bound into the
	// encrypted payload and expected back in the approval proof.
	ExpectedApprovalChallenge approval.ApprovalChallenge

	// ProofVerifier verifies the response approval proof.
	ProofVerifier approval.ApprovalProofVerifier

	// SkipAttestationVerify disables attestation verification
	SkipAttestationVerify bool
}

// Decrypt decrypts the response payload and verifies the embedded approval proof.
func (r *RequestResult) Decrypt() ([]byte, error) {
	decrypted, err := r.DecryptWithoutAttestation()
	if err != nil {
		return nil, err
	}

	if err := VerifyApprovalProofFromJSON(
		decrypted,
		r.ExpectedApprovalChallenge,
		r.ProofVerifier,
		r.SkipAttestationVerify,
	); err != nil {
		return nil, err
	}

	return decrypted, nil
}

// DecryptWithoutAttestation decrypts the response payload but does not verify the approval proof.
// This is used by enrollment flows, which rely on key-level attestation instead.
func (r *RequestResult) DecryptWithoutAttestation() ([]byte, error) {
	return DecryptResponse(
		r.EphemeralPrivate,
		r.Response.EphemeralPublic,
		r.RequestID,
		r.Response.ResponseNonce,
		r.Response.EncryptedResponse,
	)
}

// RequestBuilder provides a fluent API for building and sending signing requests.
// It handles the common boilerplate: access token retrieval, ephemeral key generation,
// multi-device encryption, and request submission.
type RequestBuilder struct {
	cfg              *config.Config
	keyID            string
	signingPublicKey string
	expiresIn        int
	timestamp        int64
	timeout          time.Duration

	// clientRequestID, if non-nil, overrides the UUID the builder would
	// otherwise generate for this Send. Use this when the caller must
	// embed the same ID into the payload body before calling Send.
	clientRequestID *uuid.UUID

	skipAttestationVerify bool

	// err captures any error during building
	err error
}

// NewRequestBuilder creates a new request builder for the given config.
// The builder will validate that the user is logged in.
func NewRequestBuilder(cfg *config.Config) *RequestBuilder {
	b := &RequestBuilder{
		cfg:       cfg,
		expiresIn: 120, // Default 2 minutes
		timeout:   config.DefaultSigningTimeout,
	}

	if SkipAttestationRequested() {
		b.skipAttestationVerify = true
	}

	if !cfg.IsLoggedIn() {
		b.err = fmt.Errorf("not logged in: please run 'nb login' first")
	}

	return b
}

// WithKey sets the target key for the request.
// signingPublicKey is the hex-encoded public key of the key to use for signing.
func (b *RequestBuilder) WithKey(keyID, signingPublicKey string) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.keyID = keyID
	b.signingPublicKey = signingPublicKey
	return b
}

// WithExpiration sets the request expiration time in seconds.
func (b *RequestBuilder) WithExpiration(seconds int) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.expiresIn = seconds
	return b
}

// WithTimeout sets the timeout for waiting for a response.
func (b *RequestBuilder) WithTimeout(timeout time.Duration) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.timeout = timeout
	return b
}

// WithTimestamp sets the request timestamp (Unix milliseconds).
// If not set, uses current time.
func (b *RequestBuilder) WithTimestamp(ts int64) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.timestamp = ts
	return b
}

// WithClientRequestID overrides the UUID used as clientRequestId / AAD
// for this Send. Callers that embed the request ID inside the payload
// body (e.g., SSH enroll) should generate a UUID, stamp it into the
// payload, and pass it here so the wire-level AAD matches the payload.
func (b *RequestBuilder) WithClientRequestID(id uuid.UUID) *RequestBuilder {
	if b.err != nil {
		return b
	}
	b.clientRequestID = &id
	return b
}

// Send encrypts the payload and sends the request, waiting for a response.
// The request is wrapped for every active approver device and sent as a
// single authenticated exchange.
// Returns a RequestResult that can be used to decrypt the response.
func (b *RequestBuilder) Send(ctx context.Context, payload any) (*RequestResult, error) {
	if b.err != nil {
		tlog.Debug("Send: precondition error %v", b.err)
		return nil, b.err
	}

	accessToken, err := b.cfg.GetValidAccessToken(ctx)
	if err != nil {
		tlog.Debug("Send: failed to get access token %v", err)
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	tlog.Debug("Send: obtained access token len=%d", len(accessToken))

	var proofVerifier approval.ApprovalProofVerifier
	if !b.skipAttestationVerify {
		proofVerifier, err = b.approvalProofVerifier(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("load approval proof verifier: %w", err)
		}
	}

	// Generate ephemeral keypair for forward secrecy
	tlog.Debug("Send: generating ephemeral keypair")
	ephemeral, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Generate (or reuse caller-supplied) request ID (clientRequestId, used as AAD)
	var requestID uuid.UUID
	if b.clientRequestID != nil {
		requestID = *b.clientRequestID
		tlog.Debug("Send: using caller-supplied request ID %s", requestID.String())
	} else {
		requestID = uuid.New()
		tlog.Debug("Send: generated new request ID %s", requestID.String())
	}
	requestIDBytes, err := requestID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request ID: %w", err)
	}

	// Marshal payload and bind it to an explicit approval challenge so the
	// requester and approver agree on the exact challenge bytes.
	payloadBytes, expectedChallenge, err := marshalPayloadWithApprovalChallenge(payload, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare payload: %w", err)
	}
	tlog.Debug("Send: marshaled payload bytes=%d request_id=%s", len(payloadBytes), requestID.String())

	deviceKeys, err := b.fetchApproverKeys(ctx, accessToken)
	if err != nil {
		tlog.Debug("Send: failed to fetch approver keys %v", err)
		return nil, err
	}

	// Multi-device encryption (wraps symmetric key for every active approver device)
	tlog.Debug("Send: multi-device encrypting payload request_id=%s devices=%d", requestID.String(), len(deviceKeys))
	encrypted, err := multidevice.EncryptForDeviceList(payloadBytes, deviceKeys, requestID)
	if err != nil {
		tlog.Debug("Send: encryption failed %v", err)
		return nil, err
	}
	tlog.Debug("Send: encrypted request_id=%s ciphertext_len=%d wrapped_keys=%d",
		requestID.String(), len(encrypted.EncryptedPayload), len(encrypted.WrappedKeys))

	// Set timestamp if not provided
	timestamp := b.timestamp
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	baseReq := &Request{
		ID:               requestID.String(),
		RequesterID:      b.cfg.UserAccount().RequesterID,
		KeyID:            b.keyID,
		SigningPublicKey: b.signingPublicKey,
		EphemeralPublic:  ephemeral.PublicKey[:],
		EncryptedPayload: encrypted.EncryptedPayload,
		PayloadNonce:     encrypted.PayloadNonce,
		WrappedKeys:      encrypted.WrappedKeys,
		ClientRequestID:  encrypted.ClientRequestID,
		ExpiresIn:        b.expiresIn,
		Timestamp:        timestamp,
	}

	tlog.Debug("Send: dispatching request_id=%s", requestID.String())
	resp, err := b.newManager(accessToken).Send(ctx, baseReq, b.timeout)
	if err != nil {
		tlog.Debug("Send: request failed request_id=%s err=%v", requestID.String(), err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	tlog.Debug("Send: request complete request_id=%s status=%s exchange_id=%s",
		requestID.String(), resp.Status, resp.ID)

	return &RequestResult{
		Response:                  resp,
		EphemeralPrivate:          ephemeral.PrivateKey[:],
		RequestID:                 requestIDBytes,
		ExpectedApprovalChallenge: expectedChallenge,
		ProofVerifier:             proofVerifier,
		SkipAttestationVerify:     b.skipAttestationVerify,
	}, nil
}

func (b *RequestBuilder) newManager(accessToken string) *Manager {
	return NewManagerWithConfig(b.cfg, accessToken)
}

// SendAndDecrypt sends the request and decrypts the response in one step.
// Returns the decrypted response bytes.
func (b *RequestBuilder) SendAndDecrypt(ctx context.Context, payload any) ([]byte, error) {
	result, err := b.Send(ctx, payload)
	if err != nil {
		return nil, err
	}

	// Check response status
	switch result.Response.Status {
	case "expired":
		return nil, fmt.Errorf("request expired")
	case "responded":
		// Continue to decrypt
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	return result.Decrypt()
}

func (b *RequestBuilder) fetchApproverKeys(ctx context.Context, accessToken string) ([]crypto.DeviceKey, error) {
	account := b.cfg.UserAccount()
	if account == nil {
		return nil, ErrNoApproverKeys
	}

	httpClient, err := client.NewClient(b.cfg.IssuerURL(), b.cfg.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("create client for approver keys: %w", err)
	}

	keys, err := httpClient.GetApproverKeys(ctx, account.UserID, accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch approver keys: %w", err)
	}

	deviceKeys := make([]crypto.DeviceKey, 0, len(keys))
	for _, key := range keys {
		encryptionPublicKeyHex := derefString(key.EncryptionPublicKeyHex)
		if encryptionPublicKeyHex == "" {
			continue
		}
		publicKey, err := hex.DecodeString(encryptionPublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode approver key %q: %w", encryptionPublicKeyHex, err)
		}
		if len(publicKey) != crypto.PublicKeySize {
			continue
		}
		deviceKeys = append(deviceKeys, crypto.DeviceKey{
			EncryptionPublicKeyHex: encryptionPublicKeyHex,
			PublicKey:              publicKey,
		})
	}

	if len(deviceKeys) == 0 {
		return nil, ErrNoApproverKeys
	}

	return deviceKeys, nil
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func marshalPayloadWithApprovalChallenge(payload any, requestID uuid.UUID) ([]byte, approval.ApprovalChallenge, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, approval.ApprovalChallenge{}, err
	}

	var payloadObject map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadObject); err != nil {
		return nil, approval.ApprovalChallenge{}, fmt.Errorf("payload must be a JSON object: %w", err)
	}

	if challengeValue, ok := payloadObject["approvalChallenge"]; ok && challengeValue != nil {
		challengeBytes, err := json.Marshal(challengeValue)
		if err != nil {
			return nil, approval.ApprovalChallenge{}, fmt.Errorf("marshal explicit approvalChallenge: %w", err)
		}
		var challenge approval.ApprovalChallenge
		if err := json.Unmarshal(challengeBytes, &challenge); err != nil {
			return nil, approval.ApprovalChallenge{}, fmt.Errorf("decode explicit approvalChallenge: %w", err)
		}
		if challenge.Version != approval.ApprovalChallengeVersion {
			return nil, approval.ApprovalChallenge{}, fmt.Errorf("approvalChallenge.version must be %q", approval.ApprovalChallengeVersion)
		}
		if challenge.RequestID != requestID.String() {
			return nil, approval.ApprovalChallenge{}, fmt.Errorf("approvalChallenge.requestId must match request ID")
		}
		return payloadBytes, challenge, nil
	}

	nonce, _ := payloadObject["nonce"].(string)
	if nonce == "" {
		nonce = requestID.String()
	}
	digest := sha256.Sum256(payloadBytes)
	challenge := approval.ApprovalChallenge{
		Version:       approval.ApprovalChallengeVersion,
		Nonce:         nonce,
		RequestID:     requestID.String(),
		PlaintextHash: "sha256:" + hex.EncodeToString(digest[:]),
	}
	payloadObject["approvalChallenge"] = challenge

	withChallenge, err := json.Marshal(payloadObject)
	if err != nil {
		return nil, approval.ApprovalChallenge{}, fmt.Errorf("marshal payload with approvalChallenge: %w", err)
	}
	return withChallenge, challenge, nil
}

func (b *RequestBuilder) approvalProofVerifier(ctx context.Context, accessToken string) (approval.ApprovalProofVerifier, error) {
	proofConfig, err := b.loadApprovalProofConfig(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	profile, err := b.cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}

	userAccount := b.cfg.UserAccount()
	if userAccount == nil || userAccount.RequesterID == "" {
		return nil, fmt.Errorf("requester ID is required for approval proof verification")
	}
	if err := validateApprovalProofCircuitPinning(profile.IssuerURL, proofConfig.CircuitIDHex); err != nil {
		return nil, err
	}

	issuerPublicKeyHexes := make([]string, 0, len(proofConfig.IssuerKeys))
	for _, issuerKey := range proofConfig.IssuerKeys {
		if issuerKey.PublicKeyHex != "" {
			issuerPublicKeyHexes = append(issuerPublicKeyHexes, issuerKey.PublicKeyHex)
		}
	}

	return approval.NewLongfellowProofVerifier(approval.LongfellowVerifierConfig{
		Audience:              userAccount.RequesterID,
		AllowedAppIDHashesHex: append([]string(nil), proofConfig.AllowedAppIDHashesHex...),
		PolicyVersion:         proofConfig.PolicyVersion,
		IssuerPublicKeyHexes:  issuerPublicKeyHexes,
		CircuitIDHex:          proofConfig.CircuitIDHex,
	})
}

func validateApprovalProofCircuitPinning(issuerURL, circuitIDHex string) error {
	if isManagedApprovalProofIssuerURL(issuerURL) && strings.TrimSpace(circuitIDHex) == "" {
		return fmt.Errorf("%w: prod/sandbox issuer returned empty CircuitIDHex; refusing to run without circuit pinning", ErrApprovalProofCircuitPinningRequired)
	}
	return nil
}

func isManagedApprovalProofIssuerURL(issuerURL string) bool {
	normalized := normalizeIssuerOrigin(issuerURL)
	return normalized == normalizeIssuerOrigin(config.Production.IssuerURL) ||
		normalized == normalizeIssuerOrigin(config.Sandbox.IssuerURL)
}

func normalizeIssuerOrigin(raw string) string {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimRight(strings.ToLower(trimmed), "/")
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.TrimRight(strings.ToLower(parsed.Hostname()), ".")
	port := parsed.Port()
	if port != "" && port == defaultPortForScheme(parsed.Scheme) {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else {
		parsed.Host = host
	}

	return parsed.Scheme + "://" + parsed.Host
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func (b *RequestBuilder) loadApprovalProofConfig(ctx context.Context, accessToken string) (*config.ApprovalProofVerifierConfig, error) {
	profile, err := b.cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	if profile.ApprovalProofConfig != nil &&
		profile.ApprovalProofConfig.PolicyVersion > 0 &&
		len(profile.ApprovalProofConfig.IssuerKeys) > 0 {
		if err := validateApprovalProofCircuitPinning(profile.IssuerURL, profile.ApprovalProofConfig.CircuitIDHex); err == nil {
			return profile.ApprovalProofConfig, nil
		}
	}
	if profile.IssuerURL == "" {
		return nil, fmt.Errorf("active profile missing issuer URL")
	}

	authClient, err := client.NewClient(profile.IssuerURL, b.cfg.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("create auth client: %w", err)
	}
	authClient.SetAccessToken(accessToken)

	remoteConfig, err := authClient.GetApprovalProofConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch approval proof config: %w", err)
	}

	issuerKeys := make([]config.ApprovalProofIssuerKey, 0, len(remoteConfig.IssuerKeys))
	for _, issuerKey := range remoteConfig.IssuerKeys {
		issuerKeys = append(issuerKeys, config.ApprovalProofIssuerKey{
			KeyID:        issuerKey.KeyId,
			PublicKeyHex: issuerKey.PublicKeyHex,
		})
	}

	cached := &config.ApprovalProofVerifierConfig{
		AttestationVersion:      remoteConfig.AttestationVersion,
		ProofVersion:            remoteConfig.ProofVersion,
		CircuitIDHex:            remoteConfig.CircuitIdHex,
		ActiveKeyID:             remoteConfig.ActiveKeyId,
		IssuerKeys:              issuerKeys,
		PolicyVersion:           uint32(remoteConfig.PolicyVersion),
		AttestationLifetimeSecs: int64(remoteConfig.AttestationLifetimeSeconds),
	}
	if remoteConfig.AllowedAppIdHashesHex != nil {
		cached.AllowedAppIDHashesHex = append([]string(nil), (*remoteConfig.AllowedAppIdHashesHex)...)
	}
	if err := validateApprovalProofCircuitPinning(profile.IssuerURL, cached.CircuitIDHex); err != nil {
		return nil, err
	}

	profile.ApprovalProofConfig = cached
	if err := b.cfg.Save(); err != nil {
		return nil, fmt.Errorf("persist approval proof config: %w", err)
	}

	return cached, nil
}
