package transport

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/client"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/multidevice"
	exchangesapi "github.com/clarifiedlabs/ackagent-monorepo/relay-api/go/relay"
)

// longPollTimeoutSeconds is the per-request long-poll window for exchange
// status polling. Bounded by 30s on the server; the caller's context
// deadline (RequestBuilder.timeout) is the outer bound.
const longPollTimeoutSeconds = 30

// RelayTransport implements Transport using the HTTP relay server's
// /api/v1/exchanges API with long-polling for responses.
type RelayTransport struct {
	relayURL    string
	deviceID    string
	accessToken string
	pollConfig  client.PollConfig
}

// NewRelayTransport creates a new relay transport.
func NewRelayTransport(relayURL, deviceID string) *RelayTransport {
	return &RelayTransport{
		relayURL:   relayURL,
		deviceID:   deviceID,
		pollConfig: client.DefaultPollConfig(),
	}
}

// SetAccessToken sets the OIDC access token for authenticated requests.
func (t *RelayTransport) SetAccessToken(token string) {
	t.accessToken = token
}

// SetPollConfig sets the polling configuration.
// Retained for API compatibility; long-polling is driven by the server
// timeout parameter, but this field is still honored as a fallback.
func (t *RelayTransport) SetPollConfig(cfg client.PollConfig) {
	t.pollConfig = cfg
}

// Name returns the transport name.
func (t *RelayTransport) Name() string {
	return "relay"
}

// Priority returns the transport priority.
func (t *RelayTransport) Priority() int {
	return 50
}

// IsAvailable checks if the relay server is reachable.
// For the relay transport, we assume it's always available since network
// errors will be handled during Send.
func (t *RelayTransport) IsAvailable(ctx context.Context) (bool, error) {
	return true, nil
}

// Send sends an exchange via the relay server and long-polls for a response.
//
// Wire format:
//   - encrypted_payload, payload_nonce, wrapped_keys: base64url(unpadded) strings
//   - requester_ephemeral_key: hex string
//
// wrapped_keys is the base64url of a JSON multidevice.WrappedKeysEnvelope whose
// per-entry byte fields are themselves base64url strings. See
// internal/shared/multidevice/types.go for the envelope schema.
func (t *RelayTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	if len(req.ClientRequestID) != 16 {
		return nil, fmt.Errorf("transport: client request ID must be 16 bytes, got %d", len(req.ClientRequestID))
	}

	// Create the shared client (wraps both legacy and new relay APIs).
	httpClient, err := client.NewClient(t.relayURL, t.deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay client: %w", err)
	}
	if t.accessToken != "" {
		httpClient.SetAccessToken(t.accessToken)
	}
	exchanges := httpClient.ExchangesAPI()

	// Build the wrapped_keys envelope. Per-entry byte fields become base64url
	// strings; the envelope is itself JSON-then-base64url-encoded on the wire.
	envelope := multidevice.WrappedKeysEnvelope{
		ClientRequestID: base64.RawURLEncoding.EncodeToString(req.ClientRequestID),
		Entries:         make([]multidevice.WrappedKey, 0, len(req.WrappedKeys)),
	}
	for _, k := range req.WrappedKeys {
		envelope.Entries = append(envelope.Entries, multidevice.WrappedKey{
			EncryptionPublicKeyHex: k.EncryptionPublicKeyHex,
			WrappedKey:             base64.RawURLEncoding.EncodeToString(k.WrappedKey),
			WrappedKeyNonce:        base64.RawURLEncoding.EncodeToString(k.WrappedKeyNonce),
			RequesterEphemeralKey:  base64.RawURLEncoding.EncodeToString(k.RequesterEphemeralKey),
			ClientRequestID:        base64.RawURLEncoding.EncodeToString(req.ClientRequestID),
		})
	}
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped_keys envelope: %w", err)
	}

	tlog.Debug("relay: POST /api/v1/exchanges")
	createResp, err := t.createExchange(ctx, req, envelopeJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create exchange: %w", err)
	}
	tlog.Debug("relay: POST /api/v1/exchanges status=%d", createResp.StatusCode)

	switch createResp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// fall through
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication required: please run 'oobsign login' first")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limited by relay")
	default:
		return nil, fmt.Errorf("exchanges create: unexpected status %d: %s", createResp.StatusCode, string(createResp.Body))
	}
	createExchange, err := parseCreateExchangeResponse(createResp)
	if err != nil {
		return nil, err
	}
	exchangeID := createExchange.Id

	// Long-poll GET /api/v1/exchanges/{id}?timeout=30 bounded by ctx deadline.
	status, err := t.longPollExchange(ctx, exchanges, exchangeID, timeout)
	if err != nil {
		return nil, err
	}

	return statusToResponse(status)
}

// longPollExchange repeatedly long-polls ExchangesGet until the exchange
// reaches a terminal status (responded/expired) or the effective deadline
// (the earlier of ctx deadline and now+timeout) expires.
func (t *RelayTransport) longPollExchange(
	ctx context.Context,
	exchanges *exchangesapi.ClientWithResponses,
	exchangeID string,
	timeout time.Duration,
) (*exchangesapi.ExchangeStatus, error) {
	// Derive a deadline for the entire long-poll loop. The inner call also
	// has its own HTTP timeout equal to longPollTimeoutSeconds+margin.
	pollCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		pollCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	timeoutParam := exchangesapi.LongPollTimeout(longPollTimeoutSeconds)
	params := &exchangesapi.ExchangesGetParams{Timeout: &timeoutParam}
	pollCfg := t.normalizedPollConfig()
	retryInterval := pollCfg.InitialInterval

	for {
		if err := pollCtx.Err(); err != nil {
			return nil, fmt.Errorf("timeout waiting for exchange response: %w", err)
		}

		tlog.Debug("relay: GET /api/v1/exchanges/%s?timeout=%d", exchangeID, longPollTimeoutSeconds)
		getResp, err := exchanges.ExchangesGetWithResponse(pollCtx, exchangeID, params)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, fmt.Errorf("timeout waiting for exchange response: %w", err)
			}
			tlog.Warn(
				"relay: GET /api/v1/exchanges/%s transient error: %v (retrying in %v)",
				exchangeID,
				err,
				retryInterval,
			)
			if err := waitForRetry(pollCtx, retryInterval); err != nil {
				return nil, fmt.Errorf("timeout waiting for exchange response: %w", err)
			}
			retryInterval = nextRetryInterval(retryInterval, pollCfg)
			continue
		}
		retryInterval = pollCfg.InitialInterval
		tlog.Debug("relay: GET /api/v1/exchanges/%s status=%d", exchangeID, getResp.StatusCode())

		switch getResp.StatusCode() {
		case http.StatusOK:
			if getResp.JSON200 == nil {
				return nil, fmt.Errorf("exchanges get: missing response body")
			}
			es := getResp.JSON200
			switch es.Status {
			case exchangesapi.ExchangeStatusEnumResponded:
				return es, nil
			case exchangesapi.ExchangeStatusEnumExpired:
				return es, nil
			case exchangesapi.ExchangeStatusEnumPending:
				// Loop again; server held the request up to longPollTimeoutSeconds.
				continue
			default:
				return nil, fmt.Errorf("unknown exchange status: %q", es.Status)
			}
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("authentication required")
		case http.StatusNotFound:
			return nil, fmt.Errorf("exchange not found")
		default:
			return nil, fmt.Errorf("exchanges get: unexpected status %d: %s", getResp.StatusCode(), string(getResp.Body))
		}
	}
}

func (t *RelayTransport) normalizedPollConfig() client.PollConfig {
	cfg := t.pollConfig
	defaults := client.DefaultPollConfig()
	if cfg.InitialInterval <= 0 {
		cfg.InitialInterval = defaults.InitialInterval
	}
	if cfg.MaxInterval <= 0 {
		cfg.MaxInterval = defaults.MaxInterval
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = defaults.Multiplier
	}
	if cfg.MaxInterval < cfg.InitialInterval {
		cfg.MaxInterval = cfg.InitialInterval
	}
	return cfg
}

func nextRetryInterval(current time.Duration, cfg client.PollConfig) time.Duration {
	next := time.Duration(float64(current) * cfg.Multiplier)
	if next < cfg.InitialInterval {
		next = cfg.InitialInterval
	}
	if next > cfg.MaxInterval {
		next = cfg.MaxInterval
	}
	return next
}

type createExchangeResponse struct {
	StatusCode int
	Body       []byte
}

type createExchangePayload struct {
	Id        string `json:"id"`
	ExpiresAt string `json:"expires_at"`
	Routable  bool   `json:"routable"`
}

func parseCreateExchangeResponse(createResp *createExchangeResponse) (*createExchangePayload, error) {
	if len(createResp.Body) == 0 {
		return nil, fmt.Errorf("exchanges create: missing response body")
	}

	var createBody createExchangePayload
	if err := json.Unmarshal(createResp.Body, &createBody); err != nil {
		return nil, fmt.Errorf("exchanges create: failed to decode response body: %w", err)
	}
	if createBody.Id == "" {
		return nil, fmt.Errorf("exchanges create: missing response body")
	}
	return &createBody, nil
}

func (t *RelayTransport) createExchange(
	ctx context.Context,
	req *Request,
	envelopeJSON []byte,
) (*createExchangeResponse, error) {
	body := map[string]string{
		"encrypted_payload":      base64.RawURLEncoding.EncodeToString(req.EncryptedPayload),
		"payload_nonce":          base64.RawURLEncoding.EncodeToString(req.PayloadNonce),
		"requester_ephemeral_key": hex.EncodeToString(req.EphemeralPublic),
		"wrapped_keys":           base64.RawURLEncoding.EncodeToString(envelopeJSON),
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.relayURL+"/api/v1/exchanges",
		strings.NewReader(string(bodyBytes)),
	)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Device-ID", t.deviceID)
	if t.accessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.accessToken)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &createExchangeResponse{
		StatusCode: resp.StatusCode,
		Body:       responseBody,
	}, nil
}

func waitForRetry(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// statusToResponse converts an ExchangeStatus (all-strings wire format)
// into a transport.Response (decoded []byte fields).
func statusToResponse(es *exchangesapi.ExchangeStatus) (*Response, error) {
	resp := &Response{
		ID:        es.Id,
		Status:    string(es.Status),
		ExpiresAt: es.ExpiresAt,
	}

	if es.ApproverEphemeralKey != nil && *es.ApproverEphemeralKey != "" {
		key, err := hex.DecodeString(*es.ApproverEphemeralKey)
		if err != nil {
			return nil, fmt.Errorf("invalid approver_ephemeral_key: %w", err)
		}
		resp.EphemeralPublic = key
	}

	if es.EncryptedResponse != nil && *es.EncryptedResponse != "" {
		blob, err := base64.RawURLEncoding.DecodeString(*es.EncryptedResponse)
		if err != nil {
			return nil, fmt.Errorf("invalid encrypted_response: %w", err)
		}
		resp.EncryptedResponse = blob
	}

	if es.ResponseNonce != nil && *es.ResponseNonce != "" {
		nonce, err := base64.RawURLEncoding.DecodeString(*es.ResponseNonce)
		if err != nil {
			return nil, fmt.Errorf("invalid response_nonce: %w", err)
		}
		resp.ResponseNonce = nonce
	}

	return resp, nil
}
