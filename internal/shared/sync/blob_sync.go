package sync

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
)

// KeyMetadataBlob is the structure stored in the encrypted blob.
// This is what gets encrypted/decrypted - the server never sees this.
type KeyMetadataBlob struct {
	Keys      []config.KeyMetadata `json:"keys"`
	UpdatedAt time.Time            `json:"updatedAt"`
}

// syncKeyMetadata fetches and decrypts key metadata from the blob service.
func syncKeyMetadata(
	ctx context.Context,
	cfg *config.Config,
	accessToken string,
	opts SyncOptions,
) ([]SyncedKey, error) {
	profile, err := cfg.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("no active profile: %w", err)
	}

	blobURL := opts.BlobURL
	if blobURL == "" {
		if profile.BlobURL != "" {
			blobURL = profile.BlobURL
		} else {
			blobURL = config.LocalDev.BlobURL
		}
	}

	blobClient, err := client.NewBlobClient(blobURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob client: %w", err)
	}

	blobResult, err := blobClient.GetBlob(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	identityPrivate, err := profile.GetIdentityPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity private key: %w", err)
	}
	if profile.UserAccount == nil || len(profile.UserAccount.IdentityPublicKey) == 0 {
		return nil, fmt.Errorf("failed to get identity public key for blob decryption")
	}

	keyMetadata, err := decryptBlob(identityPrivate, hex.EncodeToString(profile.UserAccount.IdentityPublicKey), blobResult)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blob: %w", err)
	}

	validKeys := filterKeysByAttestation(keyMetadata.Keys, opts.AttestationEnv, opts.AcceptSoftwareApproverKeys)
	rejectedCount := len(keyMetadata.Keys) - len(validKeys)
	if rejectedCount > 0 {
		syncLog.Warn("rejected %d keys with invalid attestation", rejectedCount)
	}

	syncedKeys := replaceProfileKeys(profile, validKeys)

	syncLog.Debug("synced %d keys from blob (%d rejected)", len(syncedKeys), rejectedCount)
	return syncedKeys, nil
}

func replaceProfileKeys(profile *config.ProfileConfig, keys []config.KeyMetadata) []SyncedKey {
	profile.Keys = append([]config.KeyMetadata(nil), keys...)

	syncedKeys := make([]SyncedKey, 0, len(keys))
	for _, key := range profile.Keys {
		syncedKeys = append(syncedKeys, SyncedKey{
			PublicKeyHex: key.Hex(),
			Label:        key.Label,
			Purpose:      key.Purpose,
			DeviceName:   key.DeviceName,
		})
	}

	return syncedKeys
}

// decryptBlob decrypts the encrypted blob using the provided identity private key.
func decryptBlob(identityPrivateKey []byte, deviceEncryptionPublicKeyHex string, blobResult *client.BlobResult) (*KeyMetadataBlob, error) {
	var ourWrappedKey *client.WrappedKey
	for i := range blobResult.WrappedKeys {
		if blobResult.WrappedKeys[i].EncryptionPublicKeyHex == deviceEncryptionPublicKeyHex {
			ourWrappedKey = &blobResult.WrappedKeys[i]
			break
		}
	}

	if ourWrappedKey == nil {
		return nil, fmt.Errorf("no wrapped key found for device %s", deviceEncryptionPublicKeyHex)
	}

	ephemeralPublic, err := hex.DecodeString(ourWrappedKey.EphemeralPublicHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	wrappingKey, err := crypto.DeriveWrappingKey(
		identityPrivateKey,
		ephemeralPublic,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive unwrapping key: %w", err)
	}

	symmetricKey, err := crypto.Decrypt(
		wrappingKey,
		ourWrappedKey.WrappedKeyNonce,
		ourWrappedKey.WrappedKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap symmetric key: %w", err)
	}

	plaintext, err := crypto.Decrypt(
		symmetricKey,
		blobResult.BlobNonce,
		blobResult.EncryptedBlob,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blob: %w", err)
	}

	var metadata KeyMetadataBlob
	if err := json.Unmarshal(plaintext, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse key metadata: %w", err)
	}

	return &metadata, nil
}
