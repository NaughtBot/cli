// Package multidevice provides helpers for multi-device encryption.
//
// This file defines the wire-format types for the /api/v1/exchanges
// migration. The `wrapped_keys` field in CreateExchangeRequest /
// MailboxExchange is a base64url-encoded JSON envelope containing an
// array of WrappedKey entries plus metadata. These types are the
// in-memory representation of that envelope.
//
// Field naming is normative on the wire:
//   - encryptionPublicKeyHex: hex-encoded P-256 ECDH public key of the device
//   - wrappedKey:            base64url of ChaCha20-Poly1305 ciphertext of the sym key
//   - wrappedKeyNonce:       base64url of the 12-byte nonce used to wrap sym key
//   - requesterEphemeralKey: base64url of the 33-byte compressed P-256 ephemeral key
//   - clientRequestId:       base64url of the raw 16 bytes of the per-Send UUIDv4
//
// AAD for both the payload AEAD and the per-device wrap AEAD is the
// raw 16 bytes of clientRequestId (NOT its base64url encoding).
package multidevice

// WrappedKey is one entry in the per-device wrapped-keys envelope.
//
// All byte-valued fields are base64url-encoded (unpadded) on the wire.
// encryptionPublicKeyHex is hex-encoded to match how devices register
// their long-lived encryption public key with the backend.
type WrappedKey struct {
	EncryptionPublicKeyHex string `json:"encryptionPublicKeyHex"`
	WrappedKey             string `json:"wrappedKey"`
	WrappedKeyNonce        string `json:"wrappedKeyNonce"`
	RequesterEphemeralKey  string `json:"requesterEphemeralKey"`
	ClientRequestID        string `json:"clientRequestId"`
}

// WrappedKeysEnvelope is the JSON envelope that, when base64url-encoded,
// becomes the `wrapped_keys` field of CreateExchangeRequest (and the
// mirror `wrapped_keys` field of MailboxExchange).
//
// ClientRequestID is carried here (in addition to per-entry) so approvers
// can recover the AAD without having to parse any per-entry fields first.
type WrappedKeysEnvelope struct {
	ClientRequestID string       `json:"clientRequestId"`
	Entries         []WrappedKey `json:"entries"`
}
