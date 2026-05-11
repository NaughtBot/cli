package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/naughtbot/cli/internal/shared/config"
)

// Regression coverage for the post-wake-handle login model: a failed login
// rollback should clear token/device state without wiping profile metadata
// that was already configured for the selected profile.
func TestClearActiveProfileLoginState_RemovesTokenDeviceStateOnly(t *testing.T) {
	cleanup := configTestDir(t)
	defer cleanup()

	cfg := config.NewDefault()
	profile, err := cfg.GetActiveProfile()
	require.NoError(t, err)

	profile.RelayURL = "https://relay.example.test"
	profile.IssuerURL = "https://issuer.example.test"
	profile.BlobURL = "https://blob.example.test"
	profile.ApprovalProofConfig = &config.ApprovalProofVerifierConfig{
		ActiveKeyID: "issuer-key-1",
	}
	profile.UserAccount = &config.UserAccount{
		UserID:      "user-1",
		RequesterID: "requester-1",
		SASVerified: true,
		Devices: []config.UserDevice{
			{ApproverId: "device-1", DeviceName: "Primary iPhone"},
			{ApproverId: "device-2", DeviceName: "Backup iPad"},
		},
		IdentityPublicKey: []byte{0x01, 0x02, 0x03},
	}
	profile.Keys = []config.KeyMetadata{
		{IOSKeyID: "key-1", Label: "Primary SSH Key"},
	}

	require.NoError(t, clearActiveProfileLoginState(cfg))

	assert.Nil(t, profile.UserAccount)
	assert.Empty(t, profile.Keys)
	assert.Equal(t, "https://relay.example.test", profile.RelayURL)
	assert.Equal(t, "https://issuer.example.test", profile.IssuerURL)
	assert.Equal(t, "https://blob.example.test", profile.BlobURL)
	require.NotNil(t, profile.ApprovalProofConfig)
	assert.Equal(t, "issuer-key-1", profile.ApprovalProofConfig.ActiveKeyID)
}

// Regression coverage for the new device-key login model: login completion is
// gated on persisted approver devices rather than wake-handle entries.
func TestValidatedApproverDeviceCount_CountsStoredDevices(t *testing.T) {
	cleanup := configTestDir(t)
	defer cleanup()

	cfg := config.NewDefault()
	profile, err := cfg.GetActiveProfile()
	require.NoError(t, err)

	profile.UserAccount = &config.UserAccount{
		UserID: "user-1",
		Devices: []config.UserDevice{
			{ApproverId: "device-1", DeviceName: "Primary iPhone"},
			{ApproverId: "device-2", DeviceName: "Backup iPad"},
			{ApproverId: "device-3", DeviceName: "Test Mac"},
		},
	}

	deviceCount, err := validatedApproverDeviceCount(cfg)
	require.NoError(t, err)
	assert.Equal(t, 3, deviceCount)
}
