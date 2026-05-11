//go:build legacy_api

// Package client provides HTTP communication with the backend service.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	authapi "github.com/naughtbot/api/auth"
	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/naughtbot/cli/internal/shared/version"
	exchangesapi "github.com/naughtbot/api/mailbox"
)

var httpLog = log.New("http")

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
	return "oobsign-cli/" + version.Version
}

// Client handles communication with the backend service.
// It uses generated OpenAPI clients for the exchanges and auth services.
type Client struct {
	baseURL      string
	deviceID     string
	accessToken  string
	httpClient   *http.Client
	exchangesAPI *exchangesapi.ClientWithResponses
	authAPI      *authapi.ClientWithResponses
}

// NewClient creates a new backend client with generated relay and auth API clients.
func NewClient(baseURL, deviceID string) (*Client, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Client-side hard ceiling must exceed the relay's long-poll cap
	// (maxLongPollSeconds=25 on the relay, longPollTimeoutSeconds=30 on the
	// CLI long-poll loop) plus network margin, otherwise exchange GETs race
	// against http.Client.Timeout and surface as
	// "Client.Timeout exceeded while awaiting headers" at exactly the
	// moment the relay is writing the responded body. Per-request deadlines
	// are still enforced via context by each caller (transport layer
	// bounds the overall long-poll via ctx.WithTimeout).
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	c := &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		httpClient: httpClient,
	}

	// Common request editor that adds standard headers.
	// The closure captures c to read the current accessToken at call time.
	headerEditor := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("User-Agent", userAgent())
		req.Header.Set("X-Device-ID", c.deviceID)
		if c.accessToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.accessToken)
		}
		return nil
	}

	exchangesClient, err := exchangesapi.NewClientWithResponses(baseURL,
		exchangesapi.WithHTTPClient(httpClient),
		exchangesapi.WithRequestEditorFn(exchangesapi.RequestEditorFn(headerEditor)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create exchanges API client: %w", err)
	}
	c.exchangesAPI = exchangesClient

	authClient, err := authapi.NewClientWithResponses(baseURL,
		authapi.WithHTTPClient(httpClient),
		authapi.WithRequestEditorFn(authapi.RequestEditorFn(headerEditor)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth API client: %w", err)
	}
	c.authAPI = authClient

	return c, nil
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (c *Client) SetAccessToken(token string) {
	c.accessToken = token
}

// ExchangesAPI returns the underlying /api/v1/exchanges OpenAPI client.
// Used by the transport layer for the exchanges-based request flow.
func (c *Client) ExchangesAPI() *exchangesapi.ClientWithResponses {
	return c.exchangesAPI
}

// Login Session Endpoints (Multi-Device)

// ApprovalProofConfigResponse is an alias for the generated approval-proof
// verifier config response.
type ApprovalProofConfigResponse = authapi.ApprovalProofConfigResponse

// ListUserDevices gets the list of approver devices for a user via the generated auth API client.
// Returns the generated ApproverInfo slice directly — callers dereference pointer fields inline.
func (c *Client) ListUserDevices(ctx context.Context, userID, accessToken string) ([]authapi.ApproverInfo, error) {
	httpLog.Debug("GET users/%s/approvers", userID)

	// Use per-request editor to override the access token for this call.
	authEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return nil
	})

	resp, err := c.authAPI.UserApproversListWithResponse(ctx, userID, authEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET users/%s/approvers status=%d", userID, resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to list devices: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON200 == nil || resp.JSON200.Approvers == nil {
		return nil, nil
	}

	return *resp.JSON200.Approvers, nil
}

// GetApproverKeys fetches the active approver devices that still expose stable
// encryption keys. During the per-pairing-key rollout, the generated
// /approver-keys endpoint only returns approver IDs, so OOBSign falls back to
// the device list until the pairing-key flow is wired through end to end.
func (c *Client) GetApproverKeys(ctx context.Context, userID, accessToken string) ([]authapi.ApproverInfo, error) {
	return c.ListUserDevices(ctx, userID, accessToken)
}

// GetApprovalProofConfig fetches the public verifier configuration for
// approval proofs.
func (c *Client) GetApprovalProofConfig(ctx context.Context) (*ApprovalProofConfigResponse, error) {
	httpLog.Debug("GET approval-proofs/config")

	resp, err := c.authAPI.ApprovalProofsGetConfigWithResponse(ctx)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET approval-proofs/config status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf(
			"failed to fetch approval proof config: %d - %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("missing approval proof config response body")
	}

	return resp.JSON200, nil
}

// Attestation Endpoints

// AttestationData is an alias for the generated auth.AttestationData type.
type AttestationData = authapi.AttestationData

// GetAttestation retrieves attestation data for a device via the generated auth API client.
// The approverId parameter is the UUID of the approver device.
func (c *Client) GetAttestation(ctx context.Context, approverId, accessToken string) (*AttestationData, error) {
	httpLog.Debug("GET approvers/%s/attestation", approverId)

	// Use per-request editor to set the access token for this call.
	authEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		return nil
	})

	resp, err := c.authAPI.ApproverAttestationGetWithResponse(ctx, approverId, authEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET approvers/%s/attestation status=%d", approverId, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		if resp.JSON200.Attestation == nil {
			return nil, fmt.Errorf("no attestation data for device")
		}
		return resp.JSON200.Attestation, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusForbidden:
		return nil, fmt.Errorf("device belongs to different user")
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication required")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), string(resp.Body))
	}
}

// SessionTokensResponse is the generated auth.GetRequesterSessionTokensResponse type.
// Use generated type directly to prevent spec drift.
type SessionTokensResponse = authapi.GetRequesterSessionTokensResponse

// GetSessionTokens gets OIDC tokens for a verified requester session (no auth required).
// The tokenClaimSecret must be provided for session fixation prevention.
func (c *Client) GetSessionTokens(ctx context.Context, sessionID, tokenClaimSecret string) (*SessionTokensResponse, error) {
	httpLog.Debug("GET requester-sessions/%s/tokens", sessionID)

	// The secret query parameter is not in the OpenAPI spec, so we add it via a request editor.
	secretEditor := authapi.RequestEditorFn(func(_ context.Context, req *http.Request) error {
		q := req.URL.Query()
		q.Set("secret", tokenClaimSecret)
		req.URL.RawQuery = q.Encode()
		return nil
	})

	resp, err := c.authAPI.RequesterSessionTokensGetWithResponse(ctx, sessionID, secretEditor)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET requester-sessions/%s/tokens status=%d", sessionID, resp.StatusCode())

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("get session tokens failed: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected nil response body")
	}

	return resp.JSON200, nil
}

// Requester Session Endpoints (CLI login flow)

// CreateRequesterSessionRequest is the generated auth.CreateRequesterSessionRequest type.
type CreateRequesterSessionRequest = authapi.CreateRequesterSessionRequest

// CreateRequesterSessionResponse is the generated auth.CreateRequesterSessionResponse type.
type CreateRequesterSessionResponse = authapi.CreateRequesterSessionResponse

// CreateRequesterSession creates a requester session (no auth required) via the generated auth API client.
// The session starts unclaimed and will be claimed by iOS after scanning the QR code.
func (c *Client) CreateRequesterSession(ctx context.Context, req *CreateRequesterSessionRequest) (*CreateRequesterSessionResponse, error) {
	httpLog.Debug("POST requester-sessions")

	resp, err := c.authAPI.RequesterSessionsCreateWithResponse(ctx, *req)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("POST requester-sessions status=%d", resp.StatusCode())

	if resp.StatusCode() != http.StatusCreated && resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("create requester session failed: %d - %s", resp.StatusCode(), string(resp.Body))
	}

	if resp.JSON201 == nil {
		// Fall back to parsing the body directly for 200 responses.
		var result CreateRequesterSessionResponse
		if err := json.Unmarshal(resp.Body, &result); err != nil {
			return nil, err
		}
		return &result, nil
	}

	return resp.JSON201, nil
}

// GetRequesterSessionStatus gets the status of a requester session via the generated auth API client.
// Returns the generated type directly — callers dereference pointer fields inline.
func (c *Client) GetRequesterSessionStatus(ctx context.Context, sessionID string) (*authapi.GetRequesterSessionStatusResponse, error) {
	httpLog.Debug("GET requester-sessions/%s/status", sessionID)

	resp, err := c.authAPI.RequesterSessionStatusGetWithResponse(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	httpLog.Debug("GET requester-sessions/%s/status status=%d", sessionID, resp.StatusCode())

	switch resp.StatusCode() {
	case http.StatusOK:
		if resp.JSON200 == nil {
			return nil, fmt.Errorf("unexpected nil response body")
		}
		return resp.JSON200, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusGone:
		return nil, ErrExpired
	default:
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode())
	}
}

// PollRequesterSession polls until the requester session is verified or timeout.
func (c *Client) PollRequesterSession(ctx context.Context, sessionID string, timeout time.Duration, cfg PollConfig) (*authapi.GetRequesterSessionStatusResponse, error) {
	return poll(ctx, timeout, cfg,
		func(ctx context.Context) (*authapi.GetRequesterSessionStatusResponse, error) {
			return c.GetRequesterSessionStatus(ctx, sessionID)
		},
		func(status *authapi.GetRequesterSessionStatusResponse) (bool, error) {
			s := ""
			if status.Status != nil {
				s = string(*status.Status)
			}
			switch s {
			case "verified":
				return true, nil
			case "rejected":
				return true, ErrRejected
			case "expired":
				return true, ErrExpired
			case "pending", "claimed":
				return false, nil
			default:
				return true, fmt.Errorf("unknown status: %s", s)
			}
		},
	)
}
