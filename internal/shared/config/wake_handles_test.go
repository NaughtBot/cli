package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression coverage for the replacement persistence model: device metadata is
// stored directly on UserAccount, and the old wake_handles field must stay gone.
func TestUserDevice_JSONWireFormat(t *testing.T) {
	device := UserDevice{
		ApproverId:           "11111111-2222-3333-4444-555555555555",
		AuthPublicKey:        []byte{0x01, 0x02, 0x03},
		DeviceName:           "Primary iPhone",
		PublicKey:            []byte{0x04, 0x05, 0x06},
		AttestationPublicKey: []byte{0x07, 0x08, 0x09},
		IsPrimary:            true,
	}

	encoded, err := json.Marshal(device)
	require.NoError(t, err)
	got := string(encoded)

	for _, want := range []string{
		`"approverId"`,
		`"authPublicKey"`,
		`"device_name"`,
		`"public_key"`,
		`"attestation_public_key"`,
		`"is_primary"`,
	} {
		assert.Contains(t, got, want)
	}
	assert.NotContains(t, got, `"wake_handle"`)
	assert.NotContains(t, got, `"encryption_public_key"`)

	var decoded UserDevice
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, device, decoded)
}

// Regression coverage for on-disk profile/account state after the wake-handle
// model removal: profiles persist token refs plus the synced device list.
func TestUserAccount_JSONWireFormat_UsesDevicesInsteadOfWakeHandles(t *testing.T) {
	account := UserAccount{
		UserID:          "user-1",
		RequesterID:     "requester-1",
		TokenRef:        "default-access-token-user-1",
		RefreshTokenRef: "default-refresh-token-user-1",
		ExpiresAt:       time.Unix(1_700_000_000, 0).UTC(),
		LoggedInAt:      time.Unix(1_699_000_000, 0).UTC(),
		SASVerified:     true,
		Devices: []UserDevice{
			{
				ApproverId: "device-1",
				DeviceName: "Primary iPhone",
				PublicKey:  []byte{0x01, 0x02, 0x03},
			},
			{
				ApproverId: "device-2",
				DeviceName: "Backup iPad",
				PublicKey:  []byte{0x04, 0x05, 0x06},
			},
		},
		IdentityPrivateKeyRef: "default-identity-private-user-1",
		IdentityPublicKey:     []byte{0x0a, 0x0b, 0x0c},
	}

	encoded, err := json.Marshal(account)
	require.NoError(t, err)
	got := string(encoded)

	for _, want := range []string{
		`"user_id"`,
		`"requester_id"`,
		`"access_token_ref"`,
		`"refresh_token_ref"`,
		`"expires_at"`,
		`"logged_in_at"`,
		`"sas_verified"`,
		`"devices"`,
		`"identity_private_key_ref"`,
		`"identity_public_key"`,
	} {
		assert.Contains(t, got, want)
	}
	assert.NotContains(t, got, `"wake_handles"`)

	var decoded UserAccount
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, account, decoded)
}
