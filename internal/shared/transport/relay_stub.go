//go:build !legacy_api

package transport

import (
	"context"
	"errors"
	"time"

	"github.com/naughtbot/cli/internal/shared/client"
)

// TODO(WS3.3): RelayTransport.Send currently fails with ErrRelayNotImplemented
// because the legacy /api/v1/exchanges relay surface was replaced by the
// pairing-keyed /api/v1/requests surface in github.com/naughtbot/api/mailbox.
// WS3.3 will rewire this whole transport against mailbox.ClientWithResponses
// and the wait_seconds long-poll parameter. Until then the relay transport
// returns ErrRelayNotImplemented from Send so dependents still compile.

// ErrRelayNotImplemented is returned by RelayTransport.Send while WS3.3 is
// pending. The error is exported so callers (and tests) can distinguish the
// stub from real network errors.
var ErrRelayNotImplemented = errors.New("transport: relay not yet rewired to NaughtBot/api/mailbox (WS3.3)")

// RelayTransport implements Transport using the HTTP relay server's
// /api/v1/requests API (formerly /api/v1/exchanges) with long-polling for
// responses.
//
// TODO(WS3.3): replace the stub with the real implementation against
// github.com/naughtbot/api/mailbox.
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

// IsAvailable returns true because network errors are surfaced from Send().
// TODO(WS3.3): probe the new /api/v1/requests endpoint.
func (t *RelayTransport) IsAvailable(ctx context.Context) (bool, error) {
	_ = ctx
	return true, nil
}

// Send is a stub. WS3.3 will rewire to mailbox.ClientWithResponses.
func (t *RelayTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	_ = ctx
	_ = req
	_ = timeout
	return nil, ErrRelayNotImplemented
}
