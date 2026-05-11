package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/crypto"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/client"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/config"
)

func TestSyncDevices_RejectsSoftwareAttestedDevicesFromRoutingSet(t *testing.T) {
	cfg := config.NewDefault()
	profile, err := cfg.GetActiveProfile()
	if err != nil {
		t.Fatalf("GetActiveProfile() error = %v", err)
	}
	profile.UserAccount = &config.UserAccount{UserID: "user-1"}

	authPublicKeyHex := "020000000000000000000000000000000000000000000000000000000000000001"
	encryptionPublicKeyHex := "030000000000000000000000000000000000000000000000000000000000000002"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/user-1/approvers", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer access-token" {
			t.Fatalf("Authorization header = %q, want %q", auth, "Bearer access-token")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"approvers": []map[string]any{
				{
					"approverId":             "approver-1",
					"deviceName":             "Rejected iPhone",
					"authPublicKeyHex":       authPublicKeyHex,
					"encryptionPublicKeyHex": encryptionPublicKeyHex,
				},
			},
		}); err != nil {
			t.Fatalf("encoding approver response: %v", err)
		}
	})
	mux.HandleFunc("/api/v1/approvers/approver-1/attestation", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer access-token" {
			t.Fatalf("Authorization header = %q, want %q", auth, "Bearer access-token")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"attestation": map[string]any{
				"attestationType":        "software",
				"authPublicKeyHex":       authPublicKeyHex,
				"deviceType":             "ios",
				"encryptionPublicKeyHex": encryptionPublicKeyHex,
				"mode":                   "identified",
				"timestamp":              int64(1700000000000),
			},
			"attested": false,
		}); err != nil {
			t.Fatalf("encoding attestation response: %v", err)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	apiClient, err := client.NewClient(server.URL, "desktop-device")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	syncedDevices, err := syncDevices(context.Background(), cfg, apiClient, "user-1", "access-token", SyncOptions{
		VerifyAttestation:          true,
		AttestationEnv:             crypto.EnvProduction,
		AcceptSoftwareApproverKeys: false,
	})
	if err != nil {
		t.Fatalf("syncDevices() error = %v", err)
	}

	if len(syncedDevices) != 1 {
		t.Fatalf("syncedDevices count = %d, want 1", len(syncedDevices))
	}
	if syncedDevices[0].VerificationErr == nil {
		t.Fatal("expected verification error for rejected software-attested device")
	}

	if profile.UserAccount == nil {
		t.Fatal("expected user account to remain set")
	}
	if len(profile.UserAccount.Devices) != 0 {
		t.Fatalf("profile.UserAccount.Devices count = %d, want 0", len(profile.UserAccount.Devices))
	}
}

func TestSyncKeys_ClearsProfileKeysWhenBlobNotFound(t *testing.T) {
	originalSyncDevices := syncDevicesFunc
	originalSyncKeyMetadata := syncKeyMetadataFunc
	t.Cleanup(func() {
		syncDevicesFunc = originalSyncDevices
		syncKeyMetadataFunc = originalSyncKeyMetadata
	})

	syncDevicesFunc = func(
		context.Context,
		*config.Config,
		*client.Client,
		string,
		string,
		SyncOptions,
	) ([]SyncedDevice, error) {
		return nil, nil
	}
	syncKeyMetadataFunc = func(context.Context, *config.Config, string, SyncOptions) ([]SyncedKey, error) {
		return nil, client.ErrNotFound
	}

	cfg := &config.Config{
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				Keys: []config.KeyMetadata{
					{IOSKeyID: "stale-key", Label: "Stale Key", PublicKey: []byte{0x01}},
				},
			},
		},
	}

	result, err := SyncKeys(context.Background(), cfg, nil, "user-1", "token", SyncOptions{})
	if err != nil {
		t.Fatalf("SyncKeys() error = %v", err)
	}
	if result.KeyCount() != 0 {
		t.Fatalf("result.KeyCount() = %d, want 0", result.KeyCount())
	}

	profile, err := cfg.GetActiveProfile()
	if err != nil {
		t.Fatalf("GetActiveProfile() error = %v", err)
	}
	if len(profile.Keys) != 0 {
		t.Fatalf("profile.Keys length = %d, want 0", len(profile.Keys))
	}
}
