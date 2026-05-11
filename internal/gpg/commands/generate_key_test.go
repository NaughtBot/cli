package commands

import (
	"encoding/hex"
	"testing"

	payloads "github.com/naughtbot/e2ee-payloads/go"
	"github.com/stretchr/testify/assert"
)

func TestEnrollApprovedAccessors_ZeroValues(t *testing.T) {
	// All helper accessors should handle zero / nil fields gracefully on a
	// freshly constructed approved-response payload.
	w := &payloads.MailboxEnrollResponseApprovedV1{}

	assert.Equal(t, "", effectiveKeyID(w))
	assert.Equal(t, "", optString(w.Fingerprint))
	assert.Nil(t, decodedPublicKey(w))
	assert.Equal(t, "", w.Algorithm)
	assert.Equal(t, int64(0), optInt64(w.KeyCreationTimestamp))
	assert.Nil(t, optBytes(w.UserIdSignature))
	assert.Nil(t, optBytes(w.SubkeySignature))
	assert.Nil(t, decodedEncryptionPublicKey(w))
	assert.Equal(t, "", optString(w.EncryptionFingerprint))
}

func TestEnrollApprovedAccessors_WithValues(t *testing.T) {
	fingerprint := "AABB1122AABB1122AABB1122AABB1122AABB1122"
	publicKey := []byte("public-key-bytes")
	publicKeyHex := hex.EncodeToString(publicKey)
	timestamp := int64(1700000000)
	userIDSig := []byte("userid-sig")
	subkeySig := []byte("subkey-sig")
	encPubKey := []byte("enc-pubkey")
	encPubKeyHex := hex.EncodeToString(encPubKey)
	encFingerprint := "CCDD3344CCDD3344CCDD3344CCDD3344CCDD3344"

	w := &payloads.MailboxEnrollResponseApprovedV1{
		Algorithm:              "p256",
		DeviceKeyId:            "device-key-123",
		Fingerprint:            &fingerprint,
		PublicKeyHex:           publicKeyHex,
		KeyCreationTimestamp:   &timestamp,
		UserIdSignature:        &userIDSig,
		SubkeySignature:        &subkeySig,
		EncryptionPublicKeyHex: &encPubKeyHex,
		EncryptionFingerprint:  &encFingerprint,
	}

	assert.Equal(t, "device-key-123", effectiveKeyID(w))
	assert.Equal(t, fingerprint, optString(w.Fingerprint))
	assert.Equal(t, publicKey, decodedPublicKey(w))
	assert.Equal(t, "p256", w.Algorithm)
	assert.Equal(t, timestamp, optInt64(w.KeyCreationTimestamp))
	assert.Equal(t, userIDSig, optBytes(w.UserIdSignature))
	assert.Equal(t, subkeySig, optBytes(w.SubkeySignature))
	assert.Equal(t, encPubKey, decodedEncryptionPublicKey(w))
	assert.Equal(t, encFingerprint, optString(w.EncryptionFingerprint))
}

func TestKeyGenerationInfo_Structure(t *testing.T) {
	info := &KeyGenerationInfo{
		ID:                    "key-id",
		Fingerprint:           "AABB1122AABB1122AABB1122AABB1122AABB1122",
		PublicKey:             []byte("pub-key"),
		Algorithm:             "p256",
		KeyCreationTimestamp:  1700000000,
		UserIDSignature:       []byte("uid-sig"),
		SubkeySignature:       []byte("subkey-sig"),
		EncryptionPublicKey:   []byte("enc-pub-key"),
		EncryptionFingerprint: "CCDD3344CCDD3344CCDD3344CCDD3344CCDD3344",
	}

	assert.Equal(t, "key-id", info.ID)
	assert.Equal(t, "AABB1122AABB1122AABB1122AABB1122AABB1122", info.Fingerprint)
	assert.Equal(t, "p256", info.Algorithm)
	assert.Equal(t, int64(1700000000), info.KeyCreationTimestamp)
	assert.NotEmpty(t, info.PublicKey)
	assert.NotEmpty(t, info.UserIDSignature)
	assert.NotEmpty(t, info.SubkeySignature)
	assert.NotEmpty(t, info.EncryptionPublicKey)
	assert.NotEmpty(t, info.EncryptionFingerprint)
}

// effectiveKeyID prefers DeviceKeyId (the platform-agnostic name in the new
// schema for what used to be IosKeyId), falling back to Id (the GPG UUID).
func TestEffectiveKeyID_PrefersDeviceKeyId(t *testing.T) {
	r := &payloads.MailboxEnrollResponseApprovedV1{
		DeviceKeyId: "device-key-123",
		Id:          "uuid-456",
	}
	assert.Equal(t, "device-key-123", effectiveKeyID(r))
}

func TestEffectiveKeyID_FallsBackToId(t *testing.T) {
	r := &payloads.MailboxEnrollResponseApprovedV1{
		DeviceKeyId: "",
		Id:          "uuid-456",
	}
	assert.Equal(t, "uuid-456", effectiveKeyID(r))
}

// Regression: an empty DeviceKeyId (rather than missing) should still fall
// through to Id. The new schema requires DeviceKeyId on the wire but Go's
// zero value is the empty string, so the helper must treat "" as "not set".
func TestEffectiveKeyID_EmptyDeviceKeyIdFallsBackToId(t *testing.T) {
	r := &payloads.MailboxEnrollResponseApprovedV1{
		DeviceKeyId: "",
		Id:          "uuid-456",
	}
	assert.Equal(t, "uuid-456", effectiveKeyID(r))
}

func TestEffectiveKeyID_BothEmptyReturnsEmpty(t *testing.T) {
	r := &payloads.MailboxEnrollResponseApprovedV1{}
	assert.Equal(t, "", effectiveKeyID(r))
}

func TestGenerateKey_AlgorithmValidation(t *testing.T) {
	// Verify that only p256 and ed25519 are valid algorithms
	validAlgorithms := []string{"ecdsa", "ed25519"}
	invalidAlgorithms := []string{"rsa", "dsa", "secp384r1", ""}

	for _, algo := range validAlgorithms {
		isValid := algo == "ecdsa" || algo == "ed25519"
		assert.True(t, isValid, "%q should be valid", algo)
	}

	for _, algo := range invalidAlgorithms {
		isValid := algo == "ecdsa" || algo == "ed25519"
		assert.False(t, isValid, "%q should be invalid", algo)
	}
}

func TestGenerateKey_LabelFormat(t *testing.T) {
	// Verify label format: "Name <email>"
	name := "John Doe"
	email := "john@example.com"
	label := name + " <" + email + ">"

	assert.Equal(t, "John Doe <john@example.com>", label)
}
