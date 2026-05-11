package main

import (
	"context"
	"errors"
	"testing"

	authapi "github.com/clarifiedlabs/ackagent-monorepo/ackagent-api/go/auth"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/crypto"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/client"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/config"
	sharedsync "github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "login" {
			found = true
			break
		}
	}
	assert.True(t, found, "login command should be registered as a subcommand of root")
}

func TestLoginCommand_FlagsExist(t *testing.T) {
	flags := loginCmd.Flags()

	tests := []struct {
		name     string
		defValue string
	}{
		{"localdev", "false"},
		{"sandbox", "false"},
		{"relay", ""},
		{"issuer", ""},
		{"device-name", ""},
		{"config", "false"},
		{"keys", "false"},
		{"logout", "false"},
		{"force", "false"},
		{"accept-software-approver-keys", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := flags.Lookup(tt.name)
			require.NotNil(t, f, "flag %q should be defined", tt.name)
			assert.Equal(t, tt.defValue, f.DefValue, "flag %q default mismatch", tt.name)
		})
	}
}

func TestLoginCommand_ForceShorthand(t *testing.T) {
	f := loginCmd.Flags().Lookup("force")
	require.NotNil(t, f)
	assert.Equal(t, "f", f.Shorthand, "force should have -f shorthand")
}

func TestRenderQRWithLogo_EmptyBitmap(t *testing.T) {
	result := renderQRWithLogo([][]bool{}, []string{"X"})
	assert.Empty(t, result, "empty bitmap should produce empty output")
}

func TestRenderQRWithLogo_SmallBitmap(t *testing.T) {
	// Create a small 4x4 bitmap
	bitmap := [][]bool{
		{true, false, true, false},
		{false, true, false, true},
		{true, false, true, false},
		{false, true, false, true},
	}
	result := renderQRWithLogo(bitmap, []string{"X"})
	assert.NotEmpty(t, result, "should produce output for valid bitmap")
}

func TestVerifiedRequesterID(t *testing.T) {
	requesterID := "requester-123"

	tests := []struct {
		name    string
		status  *authapi.GetRequesterSessionStatusResponse
		want    string
		wantErr bool
	}{
		{
			name:    "missing status",
			status:  nil,
			wantErr: true,
		},
		{
			name:    "missing requester id",
			status:  &authapi.GetRequesterSessionStatusResponse{},
			wantErr: true,
		},
		{
			name: "returns requester id",
			status: &authapi.GetRequesterSessionStatusResponse{
				RequesterId: &requesterID,
			},
			want: requesterID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifiedRequesterID(tt.status)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClearActiveProfileLoginState(t *testing.T) {
	cleanup := configTestDir(t)
	defer cleanup()

	cfg := config.NewDefault()
	profile, err := cfg.GetActiveProfile()
	require.NoError(t, err)

	profile.UserAccount = &config.UserAccount{UserID: "user-1"}
	profile.Keys = []config.KeyMetadata{
		{IOSKeyID: "key-1", Label: "Old Key"},
	}

	require.NoError(t, clearActiveProfileLoginState(cfg))
	assert.Nil(t, profile.UserAccount)
	assert.Empty(t, profile.Keys)
}

func TestValidatedApproverDeviceCount(t *testing.T) {
	cleanup := configTestDir(t)
	defer cleanup()

	cfg := config.NewDefault()

	_, err := validatedApproverDeviceCount(cfg)
	require.Error(t, err)

	profile, err := cfg.GetActiveProfile()
	require.NoError(t, err)

	profile.UserAccount = &config.UserAccount{}
	_, err = validatedApproverDeviceCount(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no approver devices")

	profile.UserAccount.Devices = []config.UserDevice{{ApproverId: "device-1"}}
	deviceCount, err := validatedApproverDeviceCount(cfg)
	require.NoError(t, err)
	assert.Equal(t, 1, deviceCount)
}

func TestAttestationEnvironmentForIssuerURL(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
		want      crypto.AttestationEnvironment
	}{
		{name: "production", issuerURL: config.Production.IssuerURL, want: crypto.EnvProduction},
		{name: "sandbox", issuerURL: config.Sandbox.IssuerURL, want: crypto.EnvSandbox},
		{name: "localdev", issuerURL: config.LocalDev.IssuerURL, want: crypto.EnvDevelopment},
		{name: "custom sandbox host", issuerURL: "https://login.internal-sandbox.example.com", want: crypto.EnvSandbox},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, attestationEnvironmentForIssuerURL(tt.issuerURL))
		})
	}
}

func TestResolveAcceptSoftwareApproverKeys(t *testing.T) {
	t.Setenv("OOBSIGN_ACCEPT_SOFTWARE_APPROVER_KEYS", "true")
	assert.True(t, resolveAcceptSoftwareApproverKeys(false))
	assert.True(t, resolveAcceptSoftwareApproverKeys(true))

	t.Setenv("OOBSIGN_ACCEPT_SOFTWARE_APPROVER_KEYS", "")
	assert.False(t, resolveAcceptSoftwareApproverKeys(false))
}

func TestSyncSigningKeys_PropagatesSyncErrors(t *testing.T) {
	original := syncKeysFunc
	t.Cleanup(func() { syncKeysFunc = original })

	syncKeysFunc = func(
		ctx context.Context,
		cfg *config.Config,
		c *client.Client,
		userID, accessToken string,
		opts sharedsync.SyncOptions,
	) (*sharedsync.SyncResult, error) {
		return nil, errors.New("attestation backend unavailable")
	}

	_, err := syncSigningKeys(config.NewDefault(), nil, "user-1", "token", crypto.EnvSandbox, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation backend unavailable")
}

func TestSyncSigningKeys_PassesAttestationOptions(t *testing.T) {
	original := syncKeysFunc
	t.Cleanup(func() { syncKeysFunc = original })

	var gotOpts sharedsync.SyncOptions
	syncKeysFunc = func(
		ctx context.Context,
		cfg *config.Config,
		c *client.Client,
		userID, accessToken string,
		opts sharedsync.SyncOptions,
	) (*sharedsync.SyncResult, error) {
		gotOpts = opts
		return &sharedsync.SyncResult{
			Devices: []sharedsync.SyncedDevice{
				{DeviceName: "Secure Enclave iPhone", IsAttested: true, AttestationType: "ios_secure_enclave"},
			},
			Keys: []sharedsync.SyncedKey{
				{PublicKeyHex: "a"},
				{PublicKeyHex: "b"},
			},
		}, nil
	}

	syncedKeys, err := syncSigningKeys(config.NewDefault(), nil, "user-1", "token", crypto.EnvSandbox, true)
	require.NoError(t, err)
	assert.Equal(t, 2, syncedKeys)
	assert.True(t, gotOpts.VerifyAttestation)
	assert.Equal(t, crypto.EnvSandbox, gotOpts.AttestationEnv)
	assert.True(t, gotOpts.AcceptSoftwareApproverKeys)
}

func configTestDir(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	return func() {
		config.ResetConfigDir()
	}
}
