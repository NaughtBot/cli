// Package config manages desktop client configuration including
// pairing state, encryption keys, and enrolled signing keys.
package config

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/naughtbot/cli/internal/shared/log"
)

var cfgLog = log.New("config")

// configDirOverride allows overriding the config directory for testing
var configDirOverride string

// SetConfigDir overrides the config directory (for testing)
func SetConfigDir(dir string) {
	configDirOverride = dir
}

// ResetConfigDir clears the config directory override
func ResetConfigDir() {
	configDirOverride = ""
}

const (
	// ConfigVersion is the current config file format version
	ConfigVersion = 1

	// AppID is the application identifier used for config paths
	AppID = "com.naughtbot.nb"

	// DefaultProfileName is the name used for the default profile
	DefaultProfileName = "default"

	// maxBackups is the number of timestamped config backups to retain
	maxBackups = 5
)

var (
	ErrKeyNotFound        = errors.New("key not found")
	ErrKeyringRequired    = errors.New("keyring unavailable: secure credential storage is required")
	ErrProfileNotFound    = errors.New("profile not found")
	ErrProfileExists      = errors.New("profile already exists")
	ErrNoActiveProfile    = errors.New("no active profile")
	ErrCannotDeleteLast   = errors.New("cannot delete last profile")
	ErrInvalidProfileName = errors.New("invalid profile name: must be alphanumeric with hyphens or underscores")
)

// Config represents the desktop client configuration (v3 with file-based profiles)
type Config struct {
	Version       int                       `json:"version"`
	DeviceID      string                    `json:"device_id"`
	DeviceName    string                    `json:"device_name"`
	ActiveProfile string                    `json:"active_profile"`
	Profiles      map[string]*ProfileConfig `json:"-"` // Loaded from profiles/*.json, not stored in config.json

	// workingProfile overrides ActiveProfile when set (via --profile flag or env var)
	workingProfile string
}

// ProfileConfig contains per-profile configuration
type ProfileConfig struct {
	RelayURL            string                       `json:"relay_url"`
	IssuerURL           string                       `json:"issuer_url,omitempty"` // OIDC issuer URL for token refresh
	BlobURL             string                       `json:"blob_url,omitempty"`   // Blob service URL for encrypted key metadata
	ApprovalProofConfig *ApprovalProofVerifierConfig `json:"approval_proof_config,omitempty"`
	UserAccount         *UserAccount                 `json:"user_account,omitempty"`
	Keys                []KeyMetadata                `json:"keys,omitempty"`
}

// ApprovalProofVerifierConfig caches the server-published verifier config for
// Longfellow approval proofs.
type ApprovalProofVerifierConfig struct {
	AttestationVersion      string                   `json:"attestation_version"`
	ProofVersion            string                   `json:"proof_version"`
	CircuitIDHex            string                   `json:"circuit_id_hex"`
	ActiveKeyID             string                   `json:"active_key_id,omitempty"`
	IssuerKeys              []ApprovalProofIssuerKey `json:"issuer_keys"`
	PolicyVersion           uint32                   `json:"policy_version"`
	AttestationLifetimeSecs int64                    `json:"attestation_lifetime_seconds,omitempty"`
	AllowedAppIDHashesHex   []string                 `json:"allowed_app_id_hashes_hex,omitempty"`
}

// ApprovalProofIssuerKey is a cached issuer verification key entry from the
// approval-proofs config endpoint.
type ApprovalProofIssuerKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

// IsLoggedIn returns true if this profile is logged into a user account with verified SAS
func (p *ProfileConfig) IsLoggedIn() bool {
	return p.UserAccount != nil && p.UserAccount.SASVerified && len(p.UserAccount.Devices) > 0
}

// UserAccount represents a logged-in user account with multiple approver devices
type UserAccount struct {
	UserID          string       `json:"user_id"`
	RequesterID     string       `json:"requester_id,omitempty"`      // Requester ID for signing requests
	TokenRef        string       `json:"access_token_ref,omitempty"`  // Keyring reference for access token
	RefreshTokenRef string       `json:"refresh_token_ref,omitempty"` // Keyring reference for refresh token
	ExpiresAt       time.Time    `json:"expires_at"`
	LoggedInAt      time.Time    `json:"logged_in_at"`
	SASVerified     bool         `json:"sas_verified"`
	Devices         []UserDevice `json:"devices"`
	// Our identity key pair for this account
	IdentityPrivateKeyRef string `json:"identity_private_key_ref,omitempty"` // Keyring reference
	IdentityPublicKey     []byte `json:"identity_public_key"`
}

// UserDevice represents a device in the user's account
type UserDevice struct {
	ApproverId           string `json:"approverId"`    // Approver UUID from backend registration
	AuthPublicKey        []byte `json:"authPublicKey"` // P-256 33 bytes compressed (0x02/0x03 || X) for auth
	DeviceName           string `json:"device_name"`
	PublicKey            []byte `json:"public_key"`                       // P-256 33 bytes compressed (0x02/0x03 || X) for ECDH
	AttestationPublicKey []byte `json:"attestation_public_key,omitempty"` // P-256 33 bytes compressed (0x02/0x03 || X) for attestation verification
	IsPrimary            bool   `json:"is_primary"`
}

// KeyPurpose represents the intended use of a signing key
type KeyPurpose string

const (
	KeyPurposeSSH KeyPurpose = "ssh" // SSH authentication/signing
	KeyPurposeGPG KeyPurpose = "gpg" // GPG signing (git commits)
	KeyPurposeAge KeyPurpose = "age" // Age encryption/decryption
)

// KeyStorageType indicates where/how a key is stored on iOS
type KeyStorageType string

const (
	StorageTypeSecureEnclave  KeyStorageType = "secureEnclave"  // Hardware-backed, device-only
	StorageTypeICloudKeychain KeyStorageType = "icloudKeychain" // Software key with iCloud Keychain sync
	StorageTypeSoftwareLocal  KeyStorageType = "softwareLocal"  // Software key, device-only
)

// Key algorithm constants
const (
	AlgorithmP256    = "ecdsa"   // ECDSA P-256 (default for SSH/GPG)
	AlgorithmEd25519 = "ed25519" // EdDSA Ed25519 (software-only)
	AlgorithmX25519  = "X25519"  // X25519 (for Age encryption)
)

// KeyMetadataAttestation proves a key was created on attested device hardware
type KeyMetadataAttestation struct {
	PublicKey            []byte `json:"publicKey"`                      // The attested public key
	Assertion            []byte `json:"assertion"`                      // App Attest assertion or software signature
	AttestationType      string `json:"attestationType"`                // "ios_secure_enclave", "android_tee", "android_strongbox", "software"
	AttestationObject    []byte `json:"attestationObject,omitempty"`    // CBOR attestation (for hardware)
	Challenge            []byte `json:"challenge"`                      // SHA256(id || publicKey || createdAt || deviceAuthPublicKey)
	AttestationTimestamp int64  `json:"attestationTimestamp"`           // Unix timestamp in milliseconds
	AttestationPublicKey []byte `json:"attestationPublicKey,omitempty"` // Attestation key's public key (33 bytes compressed)
}

// KeyMetadata represents an enrolled signing key
type KeyMetadata struct {
	IOSKeyID     string         `json:"ios_key_id"`             // UUID of key on iOS
	Label        string         `json:"label"`                  // User-provided label
	PublicKey    []byte         `json:"public_key"`             // 33 bytes compressed (0x02/0x03 || X) for P-256, or 32 bytes for X25519/Ed25519
	Algorithm    string         `json:"algorithm"`              // e.g., "ecdsa-sha2-nistp256" or "X25519"
	Purpose      KeyPurpose     `json:"purpose,omitempty"`      // ssh, gpg, or age
	StorageType  KeyStorageType `json:"storage_type,omitempty"` // secureEnclave, icloudKeychain, softwareLocal
	DeviceName   string         `json:"device_name,omitempty"`  // Device name where key is stored
	CreatedAt    time.Time      `json:"created_at"`
	AgeRecipient string         `json:"age_recipient,omitempty"` // Age recipient string (age1nb1...)

	// GPG encryption subkey fields (for OpenPGP subkey binding)
	// These are only populated for GPG keys that have a separate ECDH encryption subkey
	EncryptionPublicKey   []byte `json:"encryption_public_key,omitempty"`  // 33 bytes compressed (0x02/0x03 || X) for P-256
	EncryptionFingerprint string `json:"encryption_fingerprint,omitempty"` // 40-char hex fingerprint of ECDH subkey
	KeyCreationTimestamp  int64  `json:"key_creation_timestamp,omitempty"` // Unix timestamp for consistent fingerprint computation

	// GPG signature packets (created at key generation time for offline export)
	// These are complete OpenPGP signature packets (tag 2) ready for export
	UserIDSignature []byte `json:"user_id_signature,omitempty"` // Self-certification (type 0x13) on User ID
	SubkeySignature []byte `json:"subkey_signature,omitempty"`  // Subkey binding (type 0x18) for encryption subkey

	// Key attestation (proves key was created on attested hardware)
	Attestation *KeyMetadataAttestation `json:"attestation,omitempty"`

	// ApproverId is the UUID of the approver device where this key is stored.
	ApproverId string `json:"approverId,omitempty"`
}

// IsHardwareBacked returns true if the key is stored in Secure Enclave
func (k *KeyMetadata) IsHardwareBacked() bool {
	return k.StorageType == StorageTypeSecureEnclave
}

// IsSyncable returns true if the key syncs via iCloud Keychain
func (k *KeyMetadata) IsSyncable() bool {
	return k.StorageType == StorageTypeICloudKeychain
}

// IsEd25519 returns true if the key uses Ed25519 algorithm
func (k *KeyMetadata) IsEd25519() bool {
	return k.Algorithm == AlgorithmEd25519
}

// IsP256 returns true if the key uses P-256 ECDSA algorithm
func (k *KeyMetadata) IsP256() bool {
	return k.Algorithm == AlgorithmP256 || k.Algorithm == ""
}

// IsX25519 returns true if the key uses X25519 algorithm (Age)
func (k *KeyMetadata) IsX25519() bool {
	return k.Algorithm == AlgorithmX25519
}

// PublicKeySize returns the expected public key size based on algorithm
func (k *KeyMetadata) PublicKeySize() int {
	if k.IsEd25519() || k.IsX25519() {
		return 32
	}
	return 33 // P-256 compressed
}

// Hex returns the hex-encoded public key string.
func (k *KeyMetadata) Hex() string {
	return hex.EncodeToString(k.PublicKey)
}

// HasEncryptionSubkey returns true if the key has a separate ECDH encryption subkey
func (k *KeyMetadata) HasEncryptionSubkey() bool {
	return len(k.EncryptionPublicKey) > 0 && k.EncryptionFingerprint != ""
}

// EffectiveEncryptionPublicKey returns the public key to use for ECDH encryption.
// Returns the encryption subkey if available, otherwise falls back to the primary key.
func (k *KeyMetadata) EffectiveEncryptionPublicKey() []byte {
	if k.HasEncryptionSubkey() {
		return k.EncryptionPublicKey
	}
	return k.PublicKey
}

// EffectiveEncryptionFingerprint returns the GPG fingerprint to use for PKESK key ID.
// Returns the encryption subkey fingerprint if available, otherwise falls back to the primary public key hex.
// Note: For GPG keys, the GPG V4 fingerprint should be computed on demand from the public key.
func (k *KeyMetadata) EffectiveEncryptionFingerprint() string {
	if k.HasEncryptionSubkey() {
		return k.EncryptionFingerprint
	}
	return k.Hex()
}

// profileNameRegex validates profile names: alphanumeric, hyphens, underscores
var profileNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ValidateProfileName checks if a profile name is valid
func ValidateProfileName(name string) error {
	if name == "" || !profileNameRegex.MatchString(name) {
		return ErrInvalidProfileName
	}
	return nil
}
