package transport

import (
	"context"
	"errors"
	"time"

	"github.com/naughtbot/cli/internal/shared/client"
)

// ErrRelayNotImplemented is returned by RelayTransport.Send while the rewire
// against github.com/naughtbot/api/mailbox is pending. The error is exported
// so callers (and tests) can distinguish the stub from real network errors.
//
// The legacy /api/v1/exchanges relay surface that the previous CLI targeted
// no longer exists; the replacement mailbox /api/v1/requests surface is
// DPoP-bound and requires the new pairing-keyed auth flow to be wired up
// first. Re-enabling this transport is tracked as a follow-up to
// NaughtBot/cli#12.
var ErrRelayNotImplemented = errors.New("transport: relay not yet rewired to NaughtBot/api/mailbox")

// RelayTransport implements Transport against the relay/mailbox server.
//
// While the new mailbox surface rewire is in progress, Send returns
// ErrRelayNotImplemented; the constructor, transport metadata, and
// SetAccessToken / SetPollConfig accessors are kept so dependents keep
// compiling.
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

// IsAvailable returns true because the transport's network errors are surfaced
// from Send().
func (t *RelayTransport) IsAvailable(ctx context.Context) (bool, error) {
	_ = ctx
	return true, nil
}

// Send is a stub returning ErrRelayNotImplemented. The full implementation
// against github.com/naughtbot/api/mailbox lands in a follow-up to
// NaughtBot/cli#12.
func (t *RelayTransport) Send(ctx context.Context, req *Request, timeout time.Duration) (*Response, error) {
	_ = ctx
	_ = req
	_ = timeout
	return nil, ErrRelayNotImplemented
}
