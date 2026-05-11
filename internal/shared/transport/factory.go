package transport

import (
	"github.com/naughtbot/cli/internal/shared/config"
)

// NewManagerWithConfig creates a transport manager with the relay transport configured.
func NewManagerWithConfig(cfg *config.Config, accessToken string) *Manager {
	m := NewManager()

	relay := NewRelayTransport(cfg.RelayURL(), cfg.DeviceID)
	relay.SetAccessToken(accessToken)
	m.Register(relay)

	return m
}
