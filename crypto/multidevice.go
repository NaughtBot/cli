// Package crypto provides multi-device encryption support
// for encrypting payloads to multiple devices with per-device key wrapping.
package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// hkdfWrappingInfo is used for per-device key wrapping
	hkdfWrappingInfo = "signer-wrap-v1"
)

// DeviceKey represents a device's public key for multi-device encryption
type DeviceKey struct {
	EncryptionPublicKeyHex string // Hex-encoded P-256 ECDH public key of the device
	PublicKey              []byte // P-256 33 bytes (compressed: 0x02/0x03 || X)
}

// WrappedKeyRaw is the in-memory representation of one per-device wrapped
// key entry before base64url-encoding into the wire-level envelope. All
// byte-valued fields are raw bytes here; encoding happens at the transport
// boundary when assembling the WrappedKeysEnvelope.
type WrappedKeyRaw struct {
	EncryptionPublicKeyHex string // Hex-encoded device encryption public key
	WrappedKey             []byte // ChaCha20-Poly1305 ciphertext of the symmetric key
	WrappedKeyNonce        []byte // 12-byte nonce used to wrap symmetric key
	RequesterEphemeralKey  []byte // 33-byte compressed P-256 ephemeral public key
}

// MultiDevicePayload represents an encrypted payload with per-device wrapped keys.
// ClientRequestID is the raw 16 bytes of the per-Send UUIDv4 used as AAD.
type MultiDevicePayload struct {
	EncryptedPayload []byte
	PayloadNonce     []byte
	ClientRequestID  []byte // Raw 16 bytes used as AAD for payload + wrap AEAD
	WrappedKeys      []WrappedKeyRaw
}

// DeriveWrappingKey derives a key wrapping key from an ECDH shared secret.
// The clientRequestID is used as the HKDF salt, binding the derived key to
// this specific Send().
func DeriveWrappingKey(ourPrivate, theirPublic, clientRequestID []byte) ([]byte, error) {
	// Compute ECDH shared secret
	sharedSecret, err := SharedSecret(ourPrivate, theirPublic)
	if err != nil {
		return nil, err
	}
	defer clear(sharedSecret) // Zero shared secret after key derivation

	// Use HKDF to derive wrapping key
	return deriveKeyWithInfo(sharedSecret, clientRequestID, hkdfWrappingInfo)
}

// EncryptForMultipleDevices encrypts a payload for multiple devices
// using per-device key wrapping.
//
// The algorithm:
//  1. Generate a random symmetric key
//  2. Encrypt the payload with the symmetric key (ChaCha20-Poly1305),
//     using clientRequestID (raw 16 bytes) as AAD.
//  3. For each device:
//     - Generate ephemeral P-256 key pair
//     - Derive wrapping key: HKDF(ECDH(ephemeral, device_pub), clientRequestID)
//     - Wrap symmetric key with ChaCha20-Poly1305, clientRequestID as AAD.
//  4. Return encrypted payload + wrapped keys (raw bytes, unencoded).
func EncryptForMultipleDevices(payload []byte, devices []DeviceKey, clientRequestID []byte) (*MultiDevicePayload, error) {
	if len(devices) == 0 {
		return nil, ErrInvalidKeySize
	}

	// Generate random symmetric key (32 bytes)
	symmetricKey, err := GenerateRandomBytes(KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey) // Zero symmetric key when done

	// Encrypt payload with symmetric key (clientRequestID as AAD binds ciphertext to this request)
	encryptedPayload, payloadNonce, err := Encrypt(symmetricKey, payload, clientRequestID)
	if err != nil {
		return nil, err
	}

	// Wrap the symmetric key for each device
	wrappedKeys := make([]WrappedKeyRaw, 0, len(devices))
	for _, device := range devices {
		if len(device.PublicKey) != PublicKeySize {
			continue // Skip invalid keys
		}

		// Generate ephemeral key pair for this device
		ephemeralKP, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		// Derive wrapping key
		wrappingKey, err := DeriveWrappingKey(ephemeralKP.PrivateKey[:], device.PublicKey, clientRequestID)
		if err != nil {
			clear(ephemeralKP.PrivateKey[:]) // Zero ephemeral private key on error
			return nil, err
		}
		clear(ephemeralKP.PrivateKey[:]) // Zero ephemeral private key after use

		// Wrap the symmetric key (clientRequestID as AAD binds wrapped key to this request)
		wrappedSymKey, wrappedKeyNonce, err := Encrypt(wrappingKey, symmetricKey, clientRequestID)
		clear(wrappingKey) // Zero wrapping key after use
		if err != nil {
			return nil, err
		}

		// Copy ephemeral public key to a heap buffer (ephemeralKP.PublicKey is a fixed-size array).
		ephemeralPub := make([]byte, PublicKeySize)
		copy(ephemeralPub, ephemeralKP.PublicKey[:])

		wrappedKeys = append(wrappedKeys, WrappedKeyRaw{
			EncryptionPublicKeyHex: device.EncryptionPublicKeyHex,
			WrappedKey:             wrappedSymKey,
			WrappedKeyNonce:        wrappedKeyNonce,
			RequesterEphemeralKey:  ephemeralPub,
		})
	}

	ridCopy := make([]byte, len(clientRequestID))
	copy(ridCopy, clientRequestID)

	return &MultiDevicePayload{
		EncryptedPayload: encryptedPayload,
		PayloadNonce:     payloadNonce,
		ClientRequestID:  ridCopy,
		WrappedKeys:      wrappedKeys,
	}, nil
}

// DecryptFromMultiDevice decrypts a payload using the wrapped key for our device.
// The encryptionPublicKeyHex parameter is the hex-encoded P-256 ECDH public key of our device.
// clientRequestID is the raw 16 bytes used as AAD.
func DecryptFromMultiDevice(
	payload *MultiDevicePayload,
	encryptionPublicKeyHex string,
	devicePrivateKey []byte,
	clientRequestID []byte,
) ([]byte, error) {
	// Find our device's wrapped key
	var ourWrappedKey *WrappedKeyRaw
	for i := range payload.WrappedKeys {
		if payload.WrappedKeys[i].EncryptionPublicKeyHex == encryptionPublicKeyHex {
			ourWrappedKey = &payload.WrappedKeys[i]
			break
		}
	}

	if ourWrappedKey == nil {
		return nil, ErrDecryptionFailed
	}

	// Derive wrapping key
	wrappingKey, err := DeriveWrappingKey(devicePrivateKey, ourWrappedKey.RequesterEphemeralKey, clientRequestID)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingKey) // Zero wrapping key after use

	// Unwrap symmetric key (clientRequestID as AAD verifies key belongs to this request)
	symmetricKey, err := Decrypt(wrappingKey, ourWrappedKey.WrappedKeyNonce, ourWrappedKey.WrappedKey, clientRequestID)
	if err != nil {
		return nil, err
	}
	defer clear(symmetricKey) // Zero symmetric key after use

	// Decrypt payload (clientRequestID as AAD verifies payload belongs to this request)
	return Decrypt(symmetricKey, payload.PayloadNonce, payload.EncryptedPayload, clientRequestID)
}

// deriveKeyWithInfo derives a key using HKDF with custom info string
func deriveKeyWithInfo(secret, salt []byte, info string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, salt, []byte(info))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, ErrKeyDeriveFailed
	}
	return key, nil
}
