package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/naughtbot/cli/internal/gpg/openpgp"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/log"
)

var keysLog = log.New("keys")

var keysSyncFlag bool

var getValidAccessTokenForSync = func(ctx context.Context, cfg *config.Config) (string, error) {
	return cfg.GetValidAccessToken(ctx)
}

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage enrolled signing keys",
	Run:   runKeys,
}

func init() {
	keysCmd.Flags().BoolVar(&keysSyncFlag, "sync", false, "Sync signing keys from your iOS devices")
}

func runKeys(cmd *cobra.Command, args []string) {
	keysLog.Info("keys: invoked profile=%q sync=%v", profile, keysSyncFlag)
	if keysSyncFlag {
		syncKeysCmd(profile)
		return
	}

	// Default: list keys
	showEnrolledKeysCmd(profile)
}

func showEnrolledKeysCmd(profileOverride string) {
	cfg := loadConfigWithProfile(profileOverride)

	keys := cfg.Keys()
	if len(keys) == 0 {
		fmt.Println("No signing keys enrolled.")
		fmt.Println()
		fmt.Println("To enroll keys:")
		fmt.Println("  1. Register a device via the iOS app")
		fmt.Println("  2. Run 'nb login' to connect your CLI")
		fmt.Println("  3. Run 'nb keys --sync' to sync keys")
		return
	}

	// Group keys by purpose
	sshKeys := cfg.KeysForPurpose(config.KeyPurposeSSH)
	gpgKeys := cfg.KeysForPurpose(config.KeyPurposeGPG)
	ageKeys := cfg.KeysForPurpose(config.KeyPurposeAge)

	fmt.Printf("Enrolled Signing Keys (%d total):\n\n", len(keys))

	// Show SSH keys
	if len(sshKeys) > 0 {
		fmt.Printf("SSH keys (%d):\n", len(sshKeys))
		for i, key := range sshKeys {
			printKey(i+1, key)
		}
		fmt.Println()
	}

	// Show GPG keys
	if len(gpgKeys) > 0 {
		fmt.Printf("GPG keys (%d):\n", len(gpgKeys))
		for i, key := range gpgKeys {
			printKey(i+1, key)
		}
		fmt.Println()
	}

	// Show Age keys
	if len(ageKeys) > 0 {
		fmt.Printf("Age keys (%d):\n", len(ageKeys))
		for i, key := range ageKeys {
			printKey(i+1, key)
		}
		fmt.Println()
	}

	// Show keys without purpose (legacy or other)
	var otherKeys []config.KeyMetadata
	for _, k := range keys {
		if k.Purpose != config.KeyPurposeSSH && k.Purpose != config.KeyPurposeGPG && k.Purpose != config.KeyPurposeAge {
			otherKeys = append(otherKeys, k)
		}
	}
	if len(otherKeys) > 0 {
		fmt.Printf("Other keys (%d):\n", len(otherKeys))
		for i, key := range otherKeys {
			printKey(i+1, key)
		}
		fmt.Println()
	}
}

func printKey(index int, key config.KeyMetadata) {
	fmt.Printf("  %d. %s\n", index, key.Label)
	fmt.Printf("     Public Key: %s\n", truncateFingerprint(key.Hex()))

	// Show protocol-specific fingerprint
	switch key.Purpose {
	case config.KeyPurposeGPG:
		if fp := computeGPGFingerprintForKey(key); fp != "" {
			fmt.Printf("     GPG Fingerprint: %s\n", fp)
		}
	}

	if key.StorageType != "" {
		storageDesc := string(key.StorageType)
		switch key.StorageType {
		case config.StorageTypeSecureEnclave:
			storageDesc = "Secure Enclave (hardware-backed)"
		case config.StorageTypeICloudKeychain:
			storageDesc = "iCloud Keychain (synced)"
		case config.StorageTypeSoftwareLocal:
			storageDesc = "Local software"
		}
		fmt.Printf("     Storage: %s\n", storageDesc)
	}
	if key.DeviceName != "" {
		fmt.Printf("     Device: %s\n", key.DeviceName)
	}
}

// computeGPGFingerprintForKey computes the GPG V4 fingerprint (40-char uppercase hex).
func computeGPGFingerprintForKey(key config.KeyMetadata) string {
	if len(key.PublicKey) == 0 {
		return ""
	}

	creationTime := key.CreatedAt
	if key.KeyCreationTimestamp > 0 {
		creationTime = time.Unix(key.KeyCreationTimestamp, 0)
	}

	algorithm := strings.ToLower(key.Algorithm)
	var fp []byte
	switch {
	case strings.Contains(algorithm, "ed25519"):
		fp = openpgp.V4FingerprintEd25519(key.PublicKey, creationTime)
	case len(key.PublicKey) == 65 && key.PublicKey[0] == 0x04: // P-256 uncompressed (0x04 || X || Y)
		fp = openpgp.V4Fingerprint(key.PublicKey, creationTime)
	default:
		return ""
	}

	return strings.ToUpper(hex.EncodeToString(fp))
}

func syncKeysCmd(profileOverride string) {
	cfg := loadConfigWithProfile(profileOverride)

	if !cfg.IsLoggedIn() {
		die("Not logged in. Run 'nb login' first.")
	}

	syncedKeys, err := syncKeysWithConfig(context.Background(), cfg)
	if err != nil {
		die("%v", err)
	}

	if syncedKeys == 0 {
		fmt.Println("No signing keys found on your devices.")
	} else {
		fmt.Printf("Synced %d signing key(s).\n", syncedKeys)
	}
}

func syncKeysWithConfig(ctx context.Context, cfg *config.Config) (int, error) {
	keysLog.Debug("sync: obtaining access token")
	accessToken, err := getValidAccessTokenForSync(ctx, cfg)
	if err != nil {
		return 0, fmt.Errorf("Error getting access token: %w", err)
	}
	keysLog.Debug("sync: got access token len=%d issuer=%s", len(accessToken), cfg.IssuerURL())

	// Use issuer URL for device management endpoints (login service)
	authClient, err := client.NewClient(cfg.IssuerURL(), cfg.DeviceID)
	if err != nil {
		return 0, fmt.Errorf("Error creating API client: %w", err)
	}
	keysLog.Debug("sync: syncing user_id=%s", cfg.UserAccount().UserID)

	syncedKeys, err := syncSigningKeys(
		cfg,
		authClient,
		cfg.UserAccount().UserID,
		accessToken,
		attestationEnvironmentForIssuerURL(cfg.IssuerURL()),
		resolveAcceptSoftwareApproverKeys(false),
	)
	if err != nil {
		return 0, fmt.Errorf("Error syncing keys: %w", err)
	}

	if err := cfg.Save(); err != nil {
		return 0, fmt.Errorf("Error saving config: %w", err)
	}
	keysLog.Info("sync: complete synced_keys=%d", syncedKeys)

	return syncedKeys, nil
}
