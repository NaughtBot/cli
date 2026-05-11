package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupTestDir creates a temp directory and configures it as the config directory.
// Returns a cleanup function that should be deferred.
func setupTestDir(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)
	return func() {
		ResetConfigDir()
	}
}

func TestNewDefault(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if cfg.Version != ConfigVersion {
		t.Errorf("Version = %d, want %d", cfg.Version, ConfigVersion)
	}

	if cfg.DeviceID == "" {
		t.Error("DeviceID is empty")
	}

	if cfg.DeviceName == "" {
		t.Error("DeviceName is empty")
	}

	if cfg.ActiveProfile != DefaultProfileName {
		t.Errorf("ActiveProfile = %s, want %s", cfg.ActiveProfile, DefaultProfileName)
	}

	if len(cfg.Profiles) != 1 {
		t.Errorf("Profiles count = %d, want 1", len(cfg.Profiles))
	}

	if cfg.IsLoggedIn() {
		t.Error("New config should not be logged in")
	}
}

func TestSaveLoad(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// Create a config
	cfg := NewDefault()
	profile, _ := cfg.GetActiveProfile()
	profile.RelayURL = "http://test.example.com"
	cfg.AddKey(KeyMetadata{
		IOSKeyID:  "key-1",
		Label:     "Test Key",
		PublicKey: []byte{0x04, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56},
		Algorithm: "ecdsa-sha2-nistp256",
		CreatedAt: time.Now(),
	})

	// Save using the proper Save method (now uses temp dir)
	if err := cfg.Save(); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify the config file was written
	if _, err := os.Stat(ConfigPath()); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Verify the profile file was written
	if _, err := os.Stat(ProfilePath(DefaultProfileName)); os.IsNotExist(err) {
		t.Error("Profile file was not created")
	}

	// Load config back using Load()
	loadedCfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify the data
	loadedProfile, err := loadedCfg.GetActiveProfile()
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}
	if loadedProfile.RelayURL != "http://test.example.com" {
		t.Errorf("RelayURL = %s, want http://test.example.com", loadedProfile.RelayURL)
	}
	if len(loadedProfile.Keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(loadedProfile.Keys))
	}
}

func TestIsLoggedIn(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if cfg.IsLoggedIn() {
		t.Error("New config should not be logged in")
	}

	profile, _ := cfg.GetActiveProfile()
	profile.UserAccount = &UserAccount{
		UserID: "user-123",
	}

	if cfg.IsLoggedIn() {
		t.Error("UserAccount without SAS verified should not be logged in")
	}

	profile.UserAccount.SASVerified = true

	if cfg.IsLoggedIn() {
		t.Error("UserAccount without devices should not be logged in")
	}

	profile.UserAccount.Devices = []UserDevice{
		{ApproverId: "test-approver-uuid", PublicKey: []byte("pubkey")},
	}

	if !cfg.IsLoggedIn() {
		t.Error("Config with SAS verified and devices should be logged in")
	}
}

func TestFindKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{
		IOSKeyID:  "key-uuid-123",
		PublicKey: []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56},
		Label:     "My Key",
	})

	tests := []struct {
		query   string
		wantID  string
		wantErr bool
	}{
		{"key-uuid-123", "key-uuid-123", false},
		{"abcdef123456", "key-uuid-123", false},
		{"My Key", "key-uuid-123", false},
		{"123456", "key-uuid-123", false}, // suffix match
		{"nonexistent", "", true},
	}

	for _, tt := range tests {
		key, err := cfg.FindKey(tt.query)
		if tt.wantErr {
			if err == nil {
				t.Errorf("FindKey(%q) expected error", tt.query)
			}
		} else {
			if err != nil {
				t.Errorf("FindKey(%q) unexpected error: %v", tt.query, err)
			} else if key.IOSKeyID != tt.wantID {
				t.Errorf("FindKey(%q) = %s, want %s", tt.query, key.IOSKeyID, tt.wantID)
			}
		}
	}
}

func TestAddKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	key1 := KeyMetadata{IOSKeyID: "key-1", Label: "Key 1"}
	key2 := KeyMetadata{IOSKeyID: "key-2", Label: "Key 2"}

	cfg.AddKey(key1)
	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}

	cfg.AddKey(key2)
	keys = cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count = %d, want 2", len(keys))
	}

	// Update existing key
	key1Updated := KeyMetadata{IOSKeyID: "key-1", Label: "Key 1 Updated"}
	cfg.AddKey(key1Updated)
	keys = cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count after update = %d, want 2", len(keys))
	}

	found, _ := cfg.FindKey("key-1")
	if found.Label != "Key 1 Updated" {
		t.Errorf("Key label = %s, want Key 1 Updated", found.Label)
	}
}

func TestAddKey_EmptyIOSKeyID_DoesNotOverwrite(t *testing.T) {
	// Regression: two GPG keys with IOSKeyID="" should coexist, not overwrite
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	key1 := KeyMetadata{
		IOSKeyID:  "",
		Label:     "Key 1 <key1@test.com>",
		PublicKey: []byte{0x01, 0x02, 0x03},
		Purpose:   KeyPurposeGPG,
	}
	key2 := KeyMetadata{
		IOSKeyID:  "",
		Label:     "Key 2 <key2@test.com>",
		PublicKey: []byte{0x04, 0x05, 0x06},
		Purpose:   KeyPurposeGPG,
	}

	cfg.AddKey(key1)
	cfg.AddKey(key2)
	keys := cfg.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys count = %d, want 2 (two distinct empty-IOSKeyID keys)", len(keys))
	}
}

func TestAddKey_EmptyIOSKeyID_UpdatesBySamePublicKey(t *testing.T) {
	// Update case: same public key + purpose with empty IOSKeyID should update in place
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	pubKey := []byte{0x01, 0x02, 0x03}

	key1 := KeyMetadata{IOSKeyID: "", Label: "Old Label", PublicKey: pubKey, Purpose: KeyPurposeGPG}
	cfg.AddKey(key1)

	key1Updated := KeyMetadata{IOSKeyID: "", Label: "New Label", PublicKey: pubKey, Purpose: KeyPurposeGPG}
	cfg.AddKey(key1Updated)

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1 (same key updated)", len(keys))
	}
	if keys[0].Label != "New Label" {
		t.Errorf("Label = %s, want New Label", keys[0].Label)
	}
}

func TestAddKey_NonEmptyIOSKeyID_StillDeduplicates(t *testing.T) {
	// Existing behavior preserved: keys with matching non-empty IOSKeyID update
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{IOSKeyID: "abc", Label: "Old"})
	cfg.AddKey(KeyMetadata{IOSKeyID: "abc", Label: "New"})

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}
	if keys[0].Label != "New" {
		t.Errorf("Label = %s, want New", keys[0].Label)
	}
}

func TestRemoveKey(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.AddKey(KeyMetadata{IOSKeyID: "key-1"})
	cfg.AddKey(KeyMetadata{IOSKeyID: "key-2"})

	if !cfg.RemoveKey("key-1") {
		t.Error("RemoveKey should return true for existing key")
	}

	keys := cfg.Keys()
	if len(keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys))
	}

	if cfg.RemoveKey("key-1") {
		t.Error("RemoveKey should return false for non-existing key")
	}
}

func TestConfigDir(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir returned empty string")
	}

	// Should contain the app ID
	if filepath.Base(dir) != AppID {
		t.Errorf("ConfigDir base = %s, want %s", filepath.Base(dir), AppID)
	}
}

func TestConfigPath(t *testing.T) {
	path := ConfigPath()
	if path == "" {
		t.Error("ConfigPath returned empty string")
	}

	if filepath.Base(path) != "config.json" {
		t.Errorf("ConfigPath base = %s, want config.json", filepath.Base(path))
	}
}

func TestListProfiles(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	profiles := cfg.ListProfiles()
	if len(profiles) != 1 {
		t.Errorf("ListProfiles count = %d, want 1", len(profiles))
	}
	if profiles[0] != DefaultProfileName {
		t.Errorf("ListProfiles[0] = %s, want %s", profiles[0], DefaultProfileName)
	}

	// Add more profiles
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	cfg.CreateProfile("production", "https://prod.example.com", "https://auth.prod.example.com")

	profiles = cfg.ListProfiles()
	if len(profiles) != 3 {
		t.Errorf("ListProfiles count = %d, want 3", len(profiles))
	}
}

func TestSetActiveProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")

	if err := cfg.SetActiveProfile("sandbox"); err != nil {
		t.Errorf("SetActiveProfile failed: %v", err)
	}

	if cfg.ActiveProfile != "sandbox" {
		t.Errorf("ActiveProfile = %s, want sandbox", cfg.ActiveProfile)
	}

	// Try non-existent profile
	if err := cfg.SetActiveProfile("nonexistent"); err == nil {
		t.Error("SetActiveProfile should fail for non-existent profile")
	}
}

func TestCreateProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if err := cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com"); err != nil {
		t.Errorf("CreateProfile failed: %v", err)
	}

	profile, err := cfg.GetProfile("sandbox")
	if err != nil {
		t.Errorf("GetProfile failed: %v", err)
	}
	if profile.RelayURL != "https://sandbox.example.com" {
		t.Errorf("RelayURL = %s, want https://sandbox.example.com", profile.RelayURL)
	}

	// Creating duplicate should fail
	if err := cfg.CreateProfile("sandbox", "https://other.example.com", "https://auth.other.example.com"); err == nil {
		t.Error("CreateProfile should fail for duplicate name")
	}
}

func TestCreateProfile_InvalidName(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	err := cfg.CreateProfile("../escape", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	if err != ErrInvalidProfileName {
		t.Fatalf("CreateProfile() error = %v, want %v", err, ErrInvalidProfileName)
	}
}

func TestDeleteProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	cfg.CreateProfile("sandbox", "https://sandbox.example.com", "https://auth.sandbox.example.com")
	cfg.SetActiveProfile("sandbox")

	if err := cfg.DeleteProfile("sandbox"); err != nil {
		t.Errorf("DeleteProfile failed: %v", err)
	}

	// Active should have switched
	if cfg.ActiveProfile == "sandbox" {
		t.Error("Active profile should have switched after deletion")
	}

	// Profile should be gone
	if _, err := cfg.GetProfile("sandbox"); err == nil {
		t.Error("Deleted profile should not be found")
	}

	// Can't delete last profile
	if err := cfg.DeleteProfile(cfg.ActiveProfile); err != ErrCannotDeleteLast {
		t.Errorf("DeleteProfile should fail with ErrCannotDeleteLast, got: %v", err)
	}
}

func TestRenameProfile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	if err := cfg.RenameProfile(DefaultProfileName, "production"); err != nil {
		t.Errorf("RenameProfile failed: %v", err)
	}

	if cfg.ActiveProfile != "production" {
		t.Errorf("ActiveProfile = %s, want production", cfg.ActiveProfile)
	}

	if _, err := cfg.GetProfile(DefaultProfileName); err == nil {
		t.Error("Old profile name should not exist after rename")
	}

	if _, err := cfg.GetProfile("production"); err != nil {
		t.Errorf("New profile name should exist: %v", err)
	}
}

func TestKeysForPurpose(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add keys with different purposes
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "SSH Key 1", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-2", Label: "SSH Key 2", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "gpg-1", Label: "GPG Key 1", Purpose: KeyPurposeGPG})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-1", Label: "Age Key 1", Purpose: KeyPurposeAge})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-2", Label: "Age Key 2", Purpose: KeyPurposeAge})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-3", Label: "Age Key 3", Purpose: KeyPurposeAge})

	tests := []struct {
		purpose   KeyPurpose
		wantCount int
	}{
		{KeyPurposeSSH, 2},
		{KeyPurposeGPG, 1},
		{KeyPurposeAge, 3},
		{"unknown", 0},
	}

	for _, tt := range tests {
		keys := cfg.KeysForPurpose(tt.purpose)
		if len(keys) != tt.wantCount {
			t.Errorf("KeysForPurpose(%s) count = %d, want %d", tt.purpose, len(keys), tt.wantCount)
		}

		// Verify all returned keys have the correct purpose
		for _, k := range keys {
			if k.Purpose != tt.purpose {
				t.Errorf("KeysForPurpose(%s) returned key with purpose %s", tt.purpose, k.Purpose)
			}
		}
	}
}

func TestIsLabelUnique(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add some keys
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "mykey", Purpose: KeyPurposeSSH})
	cfg.AddKey(KeyMetadata{IOSKeyID: "gpg-1", Label: "Test User <test@example.com>", Purpose: KeyPurposeGPG})
	cfg.AddKey(KeyMetadata{IOSKeyID: "age-1", Label: "nb-age", Purpose: KeyPurposeAge})

	tests := []struct {
		purpose    KeyPurpose
		label      string
		wantUnique bool
	}{
		// Existing labels should not be unique for their purpose
		{KeyPurposeSSH, "mykey", false},
		{KeyPurposeGPG, "Test User <test@example.com>", false},
		{KeyPurposeAge, "nb-age", false},
		// Same label but different purpose should be unique
		{KeyPurposeGPG, "mykey", true},
		{KeyPurposeAge, "mykey", true},
		{KeyPurposeSSH, "nb-age", true},
		// New labels should be unique
		{KeyPurposeSSH, "newkey", true},
		{KeyPurposeGPG, "Another User <another@example.com>", true},
		{KeyPurposeAge, "personal-age", true},
	}

	for _, tt := range tests {
		isUnique := cfg.IsLabelUnique(tt.purpose, tt.label)
		if isUnique != tt.wantUnique {
			t.Errorf("IsLabelUnique(%s, %q) = %v, want %v", tt.purpose, tt.label, isUnique, tt.wantUnique)
		}
	}
}

func TestMultipleKeysPerPurpose(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()

	// Add multiple SSH keys
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-1", Label: "work", Purpose: KeyPurposeSSH, PublicKey: []byte{0xab, 0xcd}})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-2", Label: "personal", Purpose: KeyPurposeSSH, PublicKey: []byte{0xde, 0xf0}})
	cfg.AddKey(KeyMetadata{IOSKeyID: "ssh-3", Label: "backup", Purpose: KeyPurposeSSH, PublicKey: []byte{0x12, 0x34}})

	// Verify we can list all
	sshKeys := cfg.KeysForPurpose(KeyPurposeSSH)
	if len(sshKeys) != 3 {
		t.Errorf("Expected 3 SSH keys, got %d", len(sshKeys))
	}

	// Verify FindKeyByPurpose returns first matching key
	firstKey := cfg.FindKeyByPurpose(KeyPurposeSSH)
	if firstKey == nil {
		t.Error("FindKeyByPurpose returned nil")
	} else if firstKey.IOSKeyID != "ssh-1" {
		t.Errorf("FindKeyByPurpose returned %s, expected ssh-1", firstKey.IOSKeyID)
	}

	// Verify we can find specific keys
	key, err := cfg.FindKey("personal")
	if err != nil {
		t.Errorf("FindKey(personal) failed: %v", err)
	} else if key.IOSKeyID != "ssh-2" {
		t.Errorf("FindKey(personal) returned %s, expected ssh-2", key.IOSKeyID)
	}

	// Verify label uniqueness is enforced
	if cfg.IsLabelUnique(KeyPurposeSSH, "work") {
		t.Error("IsLabelUnique should return false for existing label 'work'")
	}
	if !cfg.IsLabelUnique(KeyPurposeSSH, "new-key") {
		t.Error("IsLabelUnique should return true for new label 'new-key'")
	}
}

func TestFindKeyAcrossProfiles(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	cfg := NewDefault()
	p, _ := cfg.GetActiveProfile()

	// Add profile-level keys
	p.Keys = []KeyMetadata{
		{IOSKeyID: "profile-key", Label: "Profile Key"},
		{IOSKeyID: "ssh-key", Label: "SSH Key"},
	}

	// Find profile-level key
	key, profileName, err := cfg.FindKeyAcrossProfiles("profile-key")
	if err != nil {
		t.Fatalf("FindKeyAcrossProfiles(profile-key) failed: %v", err)
	}
	if key.Label != "Profile Key" {
		t.Errorf("Label = %s, want Profile Key", key.Label)
	}
	if profileName != DefaultProfileName {
		t.Errorf("Profile = %s, want %s", profileName, DefaultProfileName)
	}

	// Not found
	_, _, err = cfg.FindKeyAcrossProfiles("nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got: %v", err)
	}
}
