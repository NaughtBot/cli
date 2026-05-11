// Package client provides HTTP communication with the backend service.
//
// The legacy `/api/v1/exchanges` + ackagent-api/auth surface that previous
// versions of this CLI targeted has been deleted. The replacement design
// against github.com/naughtbot/api/{auth,mailbox} pairing endpoints is
// tracked as a follow-up to NaughtBot/cli#12. Until that lands the public
// types and constructors here keep the dependent transport / sync / sk-provider
// code compiling, but every network method returns ErrNotImplemented at
// runtime.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/naughtbot/cli/internal/shared/version"
)

var httpLog = log.New("http")

// ErrNotImplemented is returned by network methods on this package while the
// rewire against NaughtBot/api auth/mailbox is in progress.
var ErrNotImplemented = errors.New("client: not yet rewired to NaughtBot/api auth/mailbox surface")

var (
	ErrTimeout    = errors.New("timeout waiting for response")
	ErrExpired    = errors.New("request expired")
	ErrRejected   = errors.New("request rejected")
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
	ErrServer     = errors.New("server error")
)

// userAgent returns the User-Agent string for HTTP requests.
func userAgent() string {
	return "nb/" + version.Version
}

// Client handles communication with the backend service.
//
// The network methods below all return ErrNotImplemented until the
// NaughtBot/api auth + mailbox rewire is complete; the constructor and
// shape are preserved so dependent packages keep compiling.
type Client struct {
	baseURL     string
	deviceID    string
	accessToken string
	httpClient  *http.Client
}

// NewClient creates a new backend client.
func NewClient(baseURL, deviceID string) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	return &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (c *Client) SetAccessToken(token string) { c.accessToken = token }

// ApprovalProofIssuerKey carries the public-key entry for a single issuer used
// by the approval-proof verifier. The wire shape mirrors the legacy
// /approval-proofs/config response.
//
// TODO(WS3.x): there is no matching schema in the current
// `github.com/naughtbot/api/auth` generated client (the
// `/approval-proofs/config` endpoint has not yet been added upstream). When
// that endpoint is published, alias this type to the generated equivalent
// per the AGENTS.md rule against hand-written schema mirrors and delete this
// local copy. Until then, this is the contract dependent transport / approval
// code expects, so changes must mirror the OpenAPI schema once it lands.
type ApprovalProofIssuerKey struct {
	KeyId            string `json:"key_id"`
	PublicKeyHex     string `json:"public_key_hex"`
	NotBeforeUnixSec int64  `json:"not_before_unix_sec"`
	NotAfterUnixSec  int64  `json:"not_after_unix_sec"`
}

// ApprovalProofConfigResponse carries the approval-proof verifier configuration
// used by the transport request builder.
//
// TODO(WS3.x): same note as ApprovalProofIssuerKey — replace with the
// generated type from `github.com/naughtbot/api/auth` once the upstream
// `/approval-proofs/config` schema lands.
type ApprovalProofConfigResponse struct {
	ActiveKeyId                string                   `json:"active_key_id"`
	AllowedAppIdHashesHex      *[]string                `json:"allowed_app_id_hashes_hex,omitempty"`
	AttestationLifetimeSeconds int32                    `json:"attestation_lifetime_seconds"`
	AttestationVersion         string                   `json:"attestation_version"`
	CircuitIdHex               string                   `json:"circuit_id_hex"`
	IssuerKeys                 []ApprovalProofIssuerKey `json:"issuer_keys"`
	PolicyVersion              int32                    `json:"policy_version"`
	ProofVersion               string                   `json:"proof_version"`
}

// AttestationData mirrors the per-approver attestation snapshot returned by the
// legacy /approvers/{id}/attestation endpoint. The CLI sync layer uses this to
// decide whether an approver device's keys may be added to the routing set.
type AttestationData struct {
	AttestationPublicKeyHex *string   `json:"attestation_public_key_hex,omitempty"`
	AttestationType         string    `json:"attestation_type"`
	CertificateChain        *[][]byte `json:"certificate_chain,omitempty"`
	DeviceName              *string   `json:"device_name,omitempty"`
	DeviceType              string    `json:"device_type"`
	Mode                    string    `json:"mode"`
	ResponseAssertion       *[]byte   `json:"response_assertion,omitempty"`
	Timestamp               int64     `json:"timestamp"`
}

// ApproverInfo describes one approver device for the active user, used by the
// CLI multi-device routing and sync layers.
type ApproverInfo struct {
	ApproverId             *string          `json:"approver_id,omitempty"`
	Attestation            *AttestationData `json:"attestation,omitempty"`
	CreatedAt              *time.Time       `json:"created_at,omitempty"`
	DeviceName             *string          `json:"device_name,omitempty"`
	DeviceType             *string          `json:"device_type,omitempty"`
	EncryptionPublicKeyHex *string          `json:"encryption_public_key_hex,omitempty"`
	LastUsedAt             *time.Time       `json:"last_used_at,omitempty"`
}

// SessionTokensResponse is the OIDC token bundle returned to the CLI after a
// successful requester-session claim.
type SessionTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserId       string `json:"user_id"`
}

// CreateRequesterSessionRequest is the body of POST /requester-sessions.
type CreateRequesterSessionRequest struct {
	ClientID    string  `json:"client_id"`
	RelayURL    *string `json:"relay_url,omitempty"`
	RedirectURI string  `json:"redirect_uri"`
}

// CreateRequesterSessionResponse is the body returned by POST /requester-sessions.
type CreateRequesterSessionResponse struct {
	SessionId        string `json:"session_id"`
	TokenClaimSecret string `json:"token_claim_secret"`
}

// GetRequesterSessionStatusResponse mirrors the legacy session-status response.
type GetRequesterSessionStatusResponse struct {
	Status *string `json:"status,omitempty"`
}

// ListUserDevices stubs the legacy /users/{id}/approvers endpoint.
func (c *Client) ListUserDevices(ctx context.Context, userID, accessToken string) ([]ApproverInfo, error) {
	_ = ctx
	_ = userID
	_ = accessToken
	httpLog.Debug("client.ListUserDevices: stub")
	return nil, ErrNotImplemented
}

// GetApproverKeys mirrors the legacy fallback that returns the active approver
// device list when /approver-keys is not yet available.
func (c *Client) GetApproverKeys(ctx context.Context, userID, accessToken string) ([]ApproverInfo, error) {
	return c.ListUserDevices(ctx, userID, accessToken)
}

// GetApprovalProofConfig stubs the legacy /approval-proofs/config endpoint.
func (c *Client) GetApprovalProofConfig(ctx context.Context) (*ApprovalProofConfigResponse, error) {
	_ = ctx
	httpLog.Debug("client.GetApprovalProofConfig: stub")
	return nil, ErrNotImplemented
}

// GetAttestation stubs the legacy /approvers/{id}/attestation endpoint.
func (c *Client) GetAttestation(ctx context.Context, approverId, accessToken string) (*AttestationData, error) {
	_ = ctx
	_ = approverId
	_ = accessToken
	httpLog.Debug("client.GetAttestation: stub")
	return nil, ErrNotImplemented
}

// GetSessionTokens stubs the legacy /requester-sessions/{id}/tokens endpoint.
func (c *Client) GetSessionTokens(ctx context.Context, sessionID, tokenClaimSecret string) (*SessionTokensResponse, error) {
	_ = ctx
	_ = sessionID
	_ = tokenClaimSecret
	httpLog.Debug("client.GetSessionTokens: stub")
	return nil, ErrNotImplemented
}

// CreateRequesterSession stubs the legacy POST /requester-sessions endpoint.
func (c *Client) CreateRequesterSession(ctx context.Context, req *CreateRequesterSessionRequest) (*CreateRequesterSessionResponse, error) {
	_ = ctx
	_ = req
	httpLog.Debug("client.CreateRequesterSession: stub")
	return nil, ErrNotImplemented
}

// GetRequesterSessionStatus stubs the legacy GET /requester-sessions/{id}/status endpoint.
func (c *Client) GetRequesterSessionStatus(ctx context.Context, sessionID string) (*GetRequesterSessionStatusResponse, error) {
	_ = ctx
	_ = sessionID
	httpLog.Debug("client.GetRequesterSessionStatus: stub")
	return nil, ErrNotImplemented
}

// PollRequesterSession stubs the long-poll loop over GetRequesterSessionStatus.
func (c *Client) PollRequesterSession(ctx context.Context, sessionID string, timeout time.Duration, cfg PollConfig) (*GetRequesterSessionStatusResponse, error) {
	_ = ctx
	_ = sessionID
	_ = timeout
	_ = cfg
	httpLog.Debug("client.PollRequesterSession: stub")
	return nil, ErrNotImplemented
}
