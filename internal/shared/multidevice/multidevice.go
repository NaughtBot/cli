// Package multidevice provides helpers for multi-device encryption.
package multidevice

import (
	"encoding/hex"
	"fmt"

	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/google/uuid"
)

// EncryptedPayload contains the encrypted payload and wrapped keys for multi-device encryption.
// ClientRequestID is the raw 16 bytes of the per-Send UUIDv4 used as AAD for both the
// payload AEAD and the per-device wrap AEAD.
type EncryptedPayload struct {
	EncryptedPayload []byte
	PayloadNonce     []byte
	ClientRequestID  []byte
	WrappedKeys      []crypto.WrappedKeyRaw
}

// EncryptForDevices encrypts a payload for all devices in the user's account.
// It returns the encrypted payload and per-device wrapped keys.
//
// clientRequestID is the UUIDv4 generated fresh per Send(). Its raw 16 bytes
// are used as AAD for both the payload AEAD and per-device wrap AEAD.
func EncryptForDevices(cfg *config.Config, plaintext []byte, clientRequestID uuid.UUID) (*EncryptedPayload, error) {
	userAccount := cfg.UserAccount()
	if userAccount == nil {
		// Debug: check what profile exists
		profile, err := cfg.GetActiveProfile()
		if profile != nil {
			log.Debug("Profile exists but userAccount is nil, err=%v", err)
		} else {
			log.Debug("No active profile found, err=%v", err)
		}
		return nil, fmt.Errorf("not logged in")
	}
	// Debug: log device info
	log.Debug("EncryptForDevices: %d devices in account", len(userAccount.Devices))
	for i, dev := range userAccount.Devices {
		log.Debug("Device %d: approverId=%s, publicKey len=%d", i, dev.ApproverId, len(dev.PublicKey))
	}
	deviceKeys := make([]crypto.DeviceKey, 0, len(userAccount.Devices))
	for _, dev := range userAccount.Devices {
		if dev.ApproverId == "" {
			continue
		}
		if len(dev.PublicKey) == crypto.PublicKeySize {
			// Hex-encode 33-byte compressed P-256 key (0x02/0x03 || X = 66 hex chars)
			// to match the format iOS/Android register with the backend
			deviceKeys = append(deviceKeys, crypto.DeviceKey{
				EncryptionPublicKeyHex: hex.EncodeToString(dev.PublicKey),
				PublicKey:              dev.PublicKey,
			})
		}
	}

	if len(deviceKeys) == 0 {
		return nil, fmt.Errorf("no valid devices found in account")
	}

	return EncryptForDeviceList(plaintext, deviceKeys, clientRequestID)
}

// EncryptForDeviceList encrypts a payload against an explicit list of device
// encryption keys, producing per-device wrapped symmetric keys. This is used
// by callers that already have an explicit device list instead of reading
// from the active user-account config.
//
// clientRequestID is the UUIDv4 for this Send; its raw 16 bytes are used as
// AAD for both the payload AEAD and the per-device wrap AEAD.
func EncryptForDeviceList(plaintext []byte, devices []crypto.DeviceKey, clientRequestID uuid.UUID) (*EncryptedPayload, error) {
	if len(devices) == 0 {
		return nil, fmt.Errorf("no devices provided")
	}

	ridBytes, err := clientRequestID.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode client request ID: %w", err)
	}

	multiPayload, err := crypto.EncryptForMultipleDevices(plaintext, devices, ridBytes)
	if err != nil {
		return nil, fmt.Errorf("multi-device encryption failed: %w", err)
	}

	return &EncryptedPayload{
		EncryptedPayload: multiPayload.EncryptedPayload,
		PayloadNonce:     multiPayload.PayloadNonce,
		ClientRequestID:  multiPayload.ClientRequestID,
		WrappedKeys:      multiPayload.WrappedKeys,
	}, nil
}
