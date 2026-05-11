//go:build !legacy_api

// Package client provides HTTP communication with the backend service.
//
// TODO(WS3.3): The legacy /api/v1/exchanges + ackagent-api/auth surface is
// gone; the real implementations live behind the `legacy_api` build tag while
// WS3.3 rewires this package against github.com/naughtbot/api/auth and
// github.com/naughtbot/api/mailbox. Until then this file provides type
// aliases and method stubs that let dependents compile, but every call
// returns ErrNotImplemented at runtime.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/naughtbot/cli/internal/shared/version"
)

var httpLog = log.New("http")

// ErrNotImplemented is returned by stubbed methods that still need WS3.3
// rewiring to the regenerated NaughtBot/api clients.
var ErrNotImplemented = errors.New("client: not yet rewired to NaughtBot/api (WS3.3)")

var (
	ErrTimeout    = errors.New("timeout waiting for response")
	ErrExpired    = errors.New("request expired")
	ErrRejected   = errors.New("request rejected")
	ErrNotFound   = errors.New("not found")
	ErrBadRequest = errors.New("bad request")
	ErrServer     = errors.New("server error")
)

// userAgent returns the User-Agent string for HTTP requests.
//
// TODO(WS3.3): rename to `nb/` once the rebrand sweep lands.
func userAgent() string {
	return "oobsign-cli/" + version.Version
}

// Client handles communication with the backend service.
//
// TODO(WS3.3): Replace the stubbed methods with calls into the regenerated
// `github.com/naughtbot/api/auth` and `github.com/naughtbot/api/mailbox`
// clients. The legacy /api/v1/exchanges + AckAgent /requester-sessions
// surface is no longer published.
type Client struct {
	baseURL     string
	deviceID    string
	accessToken string
	httpClient  *http.Client
}

// NewClient creates a new backend client.
//
// TODO(WS3.3): Wire to the regenerated auth + mailbox clients.
func NewClient(baseURL, deviceID string) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	return &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (c *Client) SetAccessToken(token string) { c.accessToken = token }

// ApprovalProofIssuerKey mirrors the legacy auth.ApprovalProofIssuerKey shape.
//
// TODO(WS3.3): replace with the regenerated type from NaughtBot/api/auth.
type ApprovalProofIssuerKey struct {
	KeyId            string `json:"keyId"`
	PublicKeyHex     string `json:"publicKeyHex"`
	NotBeforeUnixSec int64  `json:"notBeforeUnixSec"`
	NotAfterUnixSec  int64  `json:"notAfterUnixSec"`
}

// ApprovalProofConfigResponse mirrors the legacy auth.ApprovalProofConfigResponse
// shape used by transport.builder. The new NaughtBot/api/auth package does not
// export this type yet — WS3.3 will replace this with the regenerated type.
type ApprovalProofConfigResponse struct {
	ActiveKeyId                 string                   `json:"activeKeyId"`
	AllowedAppIdHashesHex       *[]string                `json:"allowedAppIdHashesHex,omitempty"`
	AttestationLifetimeSeconds  int32                    `json:"attestationLifetimeSeconds"`
	AttestationVersion          string                   `json:"attestationVersion"`
	CircuitIdHex                string                   `json:"circuitIdHex"`
	IssuerKeys                  []ApprovalProofIssuerKey `json:"issuerKeys"`
	PolicyVersion               int32                    `json:"policyVersion"`
	ProofVersion                string                   `json:"proofVersion"`
}

// AttestationData mirrors the legacy auth.AttestationData shape used by
// internal/shared/sync/attestation.go.
//
// TODO(WS3.3): replace with the regenerated type from NaughtBot/api/auth.
type AttestationData struct {
	AttestationPublicKeyHex *string   `json:"attestationPublicKeyHex,omitempty"`
	AttestationType         string    `json:"attestationType"`
	CertificateChain        *[][]byte `json:"certificateChain,omitempty"`
	DeviceName              *string   `json:"deviceName,omitempty"`
	DeviceType              string    `json:"deviceType"`
	Mode                    string    `json:"mode"`
	ResponseAssertion       *[]byte   `json:"responseAssertion,omitempty"`
	Timestamp               int64     `json:"timestamp"`
}

// ApproverInfo mirrors the legacy auth.ApproverInfo shape used by login.go and
// device_sync.go.
//
// TODO(WS3.3): replace with the regenerated type from NaughtBot/api/auth.
type ApproverInfo struct {
	ApproverId             *string          `json:"approverId,omitempty"`
	Attestation            *AttestationData `json:"attestation,omitempty"`
	CreatedAt              *time.Time       `json:"createdAt,omitempty"`
	DeviceName             *string          `json:"deviceName,omitempty"`
	DeviceType             *string          `json:"deviceType,omitempty"`
	EncryptionPublicKeyHex *string          `json:"encryptionPublicKeyHex,omitempty"`
	LastUsedAt             *time.Time       `json:"lastUsedAt,omitempty"`
}

// SessionTokensResponse mirrors the legacy auth.GetRequesterSessionTokensResponse.
//
// TODO(WS3.3): replace with the regenerated type once the requester-session
// flow is mapped onto the new pairing-based naughtbot/api/auth surface.
type SessionTokensResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	UserId       string `json:"userId"`
}

// CreateRequesterSessionRequest mirrors the legacy auth.CreateRequesterSessionRequest.
//
// TODO(WS3.3): rebuild against naughtbot/api/auth pairing endpoints.
type CreateRequesterSessionRequest struct {
	ClientID    string  `json:"clientId"`
	RelayURL    *string `json:"relayUrl,omitempty"`
	RedirectURI string  `json:"redirectUri"`
}

// CreateRequesterSessionResponse mirrors the legacy auth.CreateRequesterSessionResponse.
//
// TODO(WS3.3): rebuild against naughtbot/api/auth.
type CreateRequesterSessionResponse struct {
	SessionId        string `json:"sessionId"`
	TokenClaimSecret string `json:"tokenClaimSecret"`
}

// ListUserDevices is a stub. WS3.3 will rewire to NaughtBot/api/auth pairings.
func (c *Client) ListUserDevices(ctx context.Context, userID, accessToken string) ([]ApproverInfo, error) {
	_ = ctx
	_ = userID
	_ = accessToken
	httpLog.Debug("client.ListUserDevices: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// GetApproverKeys is a stub. WS3.3 will rewire to NaughtBot/api/auth.
func (c *Client) GetApproverKeys(ctx context.Context, userID, accessToken string) ([]ApproverInfo, error) {
	return c.ListUserDevices(ctx, userID, accessToken)
}

// GetApprovalProofConfig is a stub. WS3.3 will rewire.
func (c *Client) GetApprovalProofConfig(ctx context.Context) (*ApprovalProofConfigResponse, error) {
	_ = ctx
	httpLog.Debug("client.GetApprovalProofConfig: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// GetAttestation is a stub. WS3.3 will rewire to NaughtBot/api/auth.
func (c *Client) GetAttestation(ctx context.Context, approverId, accessToken string) (*AttestationData, error) {
	_ = ctx
	_ = approverId
	_ = accessToken
	httpLog.Debug("client.GetAttestation: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// GetSessionTokens is a stub. WS3.3 will rewire.
func (c *Client) GetSessionTokens(ctx context.Context, sessionID, tokenClaimSecret string) (*SessionTokensResponse, error) {
	_ = ctx
	_ = sessionID
	_ = tokenClaimSecret
	httpLog.Debug("client.GetSessionTokens: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// CreateRequesterSession is a stub. WS3.3 will rewire to pairing flow.
func (c *Client) CreateRequesterSession(ctx context.Context, req *CreateRequesterSessionRequest) (*CreateRequesterSessionResponse, error) {
	_ = ctx
	_ = req
	httpLog.Debug("client.CreateRequesterSession: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// GetRequesterSessionStatus is a stub. WS3.3 will rewire to pairing flow.
type GetRequesterSessionStatusResponse struct {
	Status *string `json:"status,omitempty"`
}

func (c *Client) GetRequesterSessionStatus(ctx context.Context, sessionID string) (*GetRequesterSessionStatusResponse, error) {
	_ = ctx
	_ = sessionID
	httpLog.Debug("client.GetRequesterSessionStatus: stub (WS3.3)")
	return nil, ErrNotImplemented
}

// PollRequesterSession is a stub. WS3.3 will rewire.
func (c *Client) PollRequesterSession(ctx context.Context, sessionID string, timeout time.Duration, cfg PollConfig) (*GetRequesterSessionStatusResponse, error) {
	_ = ctx
	_ = sessionID
	_ = timeout
	_ = cfg
	httpLog.Debug("client.PollRequesterSession: stub (WS3.3)")
	return nil, ErrNotImplemented
}
