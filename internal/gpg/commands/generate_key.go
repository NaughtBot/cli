package commands

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/naughtbot/cli/internal/gpg/cli"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/sysinfo"
	"github.com/naughtbot/cli/internal/shared/transport"
	"github.com/naughtbot/cli/internal/shared/util"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

const keyPurposeGPG = "gpg"

// GenerateKey generates a new GPG key on the iOS device
func GenerateKey(cfg *config.Config, args *cli.Args) {
	if !cfg.IsLoggedIn() {
		fmt.Fprintln(os.Stderr, "Error: Not logged in. Please run 'nb login' first.")
		os.Exit(1)
	}

	// Get name and email from args or prompt
	name := args.Name
	email := args.Email

	if name == "" || email == "" {
		reader := bufio.NewReader(os.Stdin)

		if name == "" {
			fmt.Print("Name: ")
			name, _ = reader.ReadString('\n')
			name = strings.TrimSpace(name)
		}

		if email == "" {
			fmt.Print("Email: ")
			email, _ = reader.ReadString('\n')
			email = strings.TrimSpace(email)
		}
	}

	if name == "" || email == "" {
		fmt.Fprintln(os.Stderr, "Error: Name and email are required.")
		os.Exit(1)
	}

	// Get algorithm from args (default to ecdsa)
	algorithm := args.Algorithm
	if algorithm == "" {
		algorithm = config.AlgorithmP256
	}
	if algorithm != config.AlgorithmP256 && algorithm != config.AlgorithmEd25519 {
		fmt.Fprintf(os.Stderr, "Error: Invalid key type: %s (use 'ecdsa' or 'ed25519')\n", algorithm)
		os.Exit(1)
	}

	label := fmt.Sprintf("%s <%s>", name, email)

	// Check for label uniqueness among GPG keys
	if !cfg.IsLabelUnique(config.KeyPurposeGPG, label) {
		fmt.Fprintf(os.Stderr, "Error: GPG key for %q already exists. Use a different name/email combination.\n", label)
		os.Exit(1)
	}

	algorithmDisplay := "ECDSA P-256"
	if algorithm == config.AlgorithmEd25519 {
		algorithmDisplay = "Ed25519"
	}

	fmt.Fprintf(os.Stderr, "Generating %s GPG key on mobile device...\n", algorithmDisplay)
	fmt.Fprintf(os.Stderr, "User ID: %s\n", label)

	keyInfo, err := requestKeyGeneration(cfg, keyPurposeGPG, label, algorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Store the key in config
	// Use algorithm from response if provided, otherwise use requested algorithm
	respAlgorithm := keyInfo.Algorithm
	if respAlgorithm == "" {
		respAlgorithm = algorithm
	}

	keyMetadata := config.KeyMetadata{
		IOSKeyID:              keyInfo.ID,
		Label:                 label,
		PublicKey:             keyInfo.PublicKey,
		Algorithm:             respAlgorithm,
		Purpose:               config.KeyPurposeGPG,
		CreatedAt:             time.Now(),
		KeyCreationTimestamp:  keyInfo.KeyCreationTimestamp,
		UserIDSignature:       keyInfo.UserIDSignature,
		SubkeySignature:       keyInfo.SubkeySignature,
		EncryptionPublicKey:   keyInfo.EncryptionPublicKey,
		EncryptionFingerprint: keyInfo.EncryptionFingerprint,
	}
	cfg.AddKey(keyMetadata)
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to save config: %v\n", err)
	}

	// Compute GPG fingerprint for display
	gpgFP := GPGFingerprint(&keyMetadata)

	fmt.Println()
	fmt.Printf("GPG key generated successfully!\n")
	fmt.Printf("  Fingerprint: %s\n", gpgFP)
	fmt.Printf("  Algorithm:   %s\n", algorithmDisplay)
	fmt.Println()
	fmt.Println("Add to git config:")
	fmt.Printf("  git config --global user.signingkey %s\n", gpgFP)
	fmt.Printf("  git config --global commit.gpgsign true\n")
	fmt.Printf("  git config --global gpg.program \"nb gpg\"\n")
}

// KeyGenerationInfo contains the response from iOS key generation.
type KeyGenerationInfo struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   []byte `json:"public_key"`
	Algorithm   string `json:"algorithm,omitempty"` // p256 or ed25519

	// Signature data for OpenPGP export (created at key generation time)
	KeyCreationTimestamp int64  `json:"key_creation_timestamp,omitempty"` // Unix timestamp used for fingerprint
	UserIDSignature      []byte `json:"user_id_signature,omitempty"`      // Self-certification signature (0x13)
	SubkeySignature      []byte `json:"subkey_signature,omitempty"`       // Subkey binding signature (0x18)

	// ECDH encryption subkey data (for GPG P-256 keys)
	EncryptionPublicKey   []byte `json:"encryption_public_key,omitempty"`   // ECDH P-256 public key (33 bytes compressed: 0x02/0x03 || X)
	EncryptionFingerprint string `json:"encryption_fingerprint,omitempty"` // 40-char hex fingerprint of ECDH subkey
}

// GPGKeyGenPayload is the e2ee-payloads enroll request payload used by the GPG
// key generation flow.
type GPGKeyGenPayload = payloads.MailboxEnrollRequestPayloadV1

// effectiveKeyID returns the best available key identifier from the approved
// enroll response. Prefers DeviceKeyId (set on every successful enrollment),
// falls back to Id (the GPG UUID).
func effectiveKeyID(r *payloads.MailboxEnrollResponseApprovedV1) string {
	if r.DeviceKeyId != "" {
		return r.DeviceKeyId
	}
	return r.Id
}

func decodedPublicKey(r *payloads.MailboxEnrollResponseApprovedV1) []byte {
	if r.PublicKeyHex == "" {
		return nil
	}
	key, _ := hex.DecodeString(r.PublicKeyHex)
	return key
}

func decodedEncryptionPublicKey(r *payloads.MailboxEnrollResponseApprovedV1) []byte {
	if r.EncryptionPublicKeyHex == nil || *r.EncryptionPublicKeyHex == "" {
		return nil
	}
	key, _ := hex.DecodeString(*r.EncryptionPublicKeyHex)
	return key
}

func optString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func optInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func optBytes(b *[]byte) []byte {
	if b == nil {
		return nil
	}
	return *b
}

func requestKeyGeneration(cfg *config.Config, purpose, label, algorithm string) (*KeyGenerationInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Build display fields for GPG key generation
	algorithmDisplay := "ECDSA P-256"
	if algorithm == config.AlgorithmEd25519 {
		algorithmDisplay = "Ed25519"
	}

	processInfo := sysinfo.GetProcessInfo()
	fields := []payloads.DisplayField{
		{Label: "Purpose", Value: "GPG Signing"},
		{Label: "Algorithm", Value: algorithmDisplay},
		{Label: "User ID", Value: label},
	}

	icon := "key.fill"
	historyTitle := "GPG Key Generated"
	subtitle := label
	payload := &GPGKeyGenPayload{
		Purpose:              payloads.KeyPurpose(purpose),
		Label:                &label,
		Algorithm:            &algorithm,
		IncludeCertification: util.Ptr(true),
		SourceInfo:           processInfo.ToSourceInfo(),
		Display: &payloads.DisplaySchema{
			Title:        "Generate GPG Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       fields,
		},
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")
	decrypted, err := transport.SendAndDecryptEnrollment(ctx, cfg, payload, config.DefaultSigningTimeout)
	if err != nil {
		return nil, fmt.Errorf("waiting for response failed: %w", err)
	}

	response, err := transport.ParseEnrollResponse(decrypted)
	if err != nil {
		return nil, err
	}

	return &KeyGenerationInfo{
		ID:                    effectiveKeyID(response),
		Fingerprint:           optString(response.Fingerprint),
		PublicKey:             decodedPublicKey(response),
		Algorithm:             response.Algorithm,
		KeyCreationTimestamp:  optInt64(response.KeyCreationTimestamp),
		UserIDSignature:       optBytes(response.UserIdSignature),
		SubkeySignature:       optBytes(response.SubkeySignature),
		EncryptionPublicKey:   decodedEncryptionPublicKey(response),
		EncryptionFingerprint: optString(response.EncryptionFingerprint),
	}, nil
}
