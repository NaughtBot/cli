package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/naughtbot/cli/internal/gpg/openpgp"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/sysinfo"
	"github.com/naughtbot/cli/internal/shared/transport"
	"github.com/naughtbot/cli/internal/shared/util"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// GPGFingerprint computes the GPG V4 fingerprint (40-char hex) from a key's metadata.
// For GPG keys, the V4 fingerprint is computed from the raw public key and creation timestamp.
// Returns empty string if the key is not a GPG key or computation fails.
func GPGFingerprint(key *config.KeyMetadata) string {
	if key.Purpose != config.KeyPurposeGPG {
		return ""
	}
	if len(key.PublicKey) == 0 {
		return ""
	}
	var creationTime time.Time
	if key.KeyCreationTimestamp > 0 {
		creationTime = time.Unix(key.KeyCreationTimestamp, 0)
	} else {
		creationTime = key.CreatedAt
	}
	var fp []byte
	if key.IsEd25519() {
		fp = openpgp.V4FingerprintEd25519(key.PublicKey, creationTime)
	} else {
		fp = openpgp.V4Fingerprint(key.PublicKey, creationTime)
	}
	return strings.ToUpper(hex.EncodeToString(fp))
}

// FindKey finds a key in the configuration by ID or label, filtered by purpose.
func FindKey(cfg *config.Config, keyID string, purpose config.KeyPurpose) *config.KeyMetadata {
	keys := cfg.KeysForPurpose(purpose)
	if len(keys) == 0 {
		return nil
	}

	if keyID == "" {
		// Return first key as default
		return &keys[0]
	}

	keyID = strings.ToUpper(strings.ReplaceAll(keyID, " ", ""))

	for i := range keys {
		gpgFP := strings.ToUpper(GPGFingerprint(&keys[i]))

		// Match full GPG fingerprint
		if gpgFP == keyID {
			return &keys[i]
		}

		// Match last 16 hex chars (key ID)
		if len(gpgFP) >= 16 && len(keyID) <= 16 && strings.HasSuffix(gpgFP, keyID) {
			return &keys[i]
		}

		// Match last 8 hex chars (short key ID)
		if len(gpgFP) >= 8 && len(keyID) <= 8 && strings.HasSuffix(gpgFP, keyID) {
			return &keys[i]
		}

		// Match label
		if strings.EqualFold(keys[i].Label, keyID) {
			return &keys[i]
		}
	}

	return nil
}

// ActionContext provides action-oriented metadata for the iOS approval UI
type ActionContext struct {
	Title            string               // e.g., "Sign commit?"
	Description      string               // e.g., first line of commit message
	OperationContext *GPGOperationContext // Full operation context (git or general)
}

// RequestGPGSignature sends raw data to iOS for GPG signing.
// iOS builds the complete OpenPGP signature and returns it armored.
// This ensures users see and approve the actual data being signed.
func RequestGPGSignature(cfg *config.Config, key *config.KeyMetadata, rawData []byte, actionCtx *ActionContext) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Collect process and system information
	processInfo := sysinfo.GetProcessInfo()

	// Build display fields starting with key info
	signatureIcon := "signature"
	fields := []payloads.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &signatureIcon},
		{Label: "Fingerprint", Value: GPGFingerprint(key), Monospace: util.Ptr(true)},
	}

	// Determine title and subtitle based on action context
	title := "Sign data?"
	var subtitle *string
	historyTitle := "GPG Signature"

	if actionCtx != nil {
		if actionCtx.Title != "" {
			title = actionCtx.Title
		}
		if actionCtx.Description != "" {
			subtitle = &actionCtx.Description
		}

		// Add operation-specific display fields
		if actionCtx.OperationContext != nil {
			if actionCtx.OperationContext.IsGitCommit && actionCtx.OperationContext.GitContext != nil {
				git := actionCtx.OperationContext.GitContext
				historyTitle = "Git Commit Signed"
				fields = append(fields,
					payloads.DisplayField{Label: "Commit Message", Value: git.Message, Multiline: util.Ptr(true)},
					payloads.DisplayField{Label: "Author", Value: fmt.Sprintf("%s <%s>", git.AuthorName, git.AuthorEmail)},
				)
				if git.Branch != "" {
					fields = append(fields, payloads.DisplayField{Label: "Branch", Value: git.Branch, Monospace: util.Ptr(true)})
				}
				if git.RepoName != "" {
					fields = append(fields, payloads.DisplayField{Label: "Repository", Value: git.RepoName})
				}
			} else if actionCtx.OperationContext.GeneralContext != nil {
				gen := actionCtx.OperationContext.GeneralContext
				fields = append(fields,
					payloads.DisplayField{Label: "Operation", Value: gen.OperationType},
					payloads.DisplayField{Label: "Input", Value: gen.InputSource},
					payloads.DisplayField{Label: "Size", Value: fmt.Sprintf("%d bytes", gen.ContentSize)},
				)
				if gen.ContentPreview != "" {
					fields = append(fields, payloads.DisplayField{Label: "Content Preview", Value: gen.ContentPreview, Monospace: util.Ptr(true), Multiline: util.Ptr(true)})
				}
			}
		}
	}

	// Build GPG sign payload using the generated e2ee-payloads request type.
	icon := "signature"
	display := &payloads.DisplaySchema{
		Title:        title,
		HistoryTitle: &historyTitle,
		Subtitle:     subtitle,
		Icon:         &icon,
		Fields:       fields,
	}

	// The mailbox/poll path strips the signing public key from the envelope, so
	// the hex-encoded device key id is embedded in the encrypted payload so
	// the approver can resolve which on-device GPG primary key to use for
	// signing. The new schema uses DeviceKeyId (non-pointer, required) for
	// this; iOS / Android / etc. all consume the same field name.
	payload := payloads.MailboxGpgSignRequestPayloadV1{
		DeviceKeyId: key.Hex(),
		Display:     display,
		RawData:     rawData,
		SourceInfo:  processInfo.ToSourceInfo(),
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	// Send request using builder (handles encryption, submission, polling)
	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey(key.IOSKeyID, key.Hex()).
		SendAndDecrypt(ctx, payload)
	if err != nil {
		return "", err
	}

	// Parse the JSON response
	var gpgResponse client.GPGSignResponse
	if err := json.Unmarshal(decrypted, &gpgResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if !gpgResponse.IsSuccess() {
		return "", gpgResponse.Error()
	}

	return gpgResponse.GetArmoredSignature(), nil
}

// GPGDecryptContext provides context for the decryption approval UI.
type GPGDecryptContext struct {
	SenderKeyID string // Key ID of the sender (if signed)
	EncryptedTo string // Email/user ID this was encrypted to
	MessageSize int    // Size of the encrypted message
	IsAnonymous bool   // Whether the recipient key ID is hidden (wildcard)
}

// RequestGPGDecrypt sends PKESK data to iOS for session key unwrapping.
// iOS performs ECDH key agreement and returns the unwrapped session key.
// The CLI then uses this session key to decrypt the SEIPD data locally.
func RequestGPGDecrypt(cfg *config.Config, key *config.KeyMetadata, pkesk *payloads.PkeskData, decryptCtx *GPGDecryptContext) (*client.GPGDecryptResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Collect process and system information
	processInfo := sysinfo.GetProcessInfo()

	// Build display fields for GPG decryption
	lockIcon := "lock.open"
	fields := []payloads.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &lockIcon},
		{Label: "Fingerprint", Value: GPGFingerprint(key), Monospace: util.Ptr(true)},
	}

	// Add decryption context fields
	if decryptCtx != nil {
		if decryptCtx.SenderKeyID != "" {
			fields = append(fields, payloads.DisplayField{Label: "Sender Key ID", Value: decryptCtx.SenderKeyID, Monospace: util.Ptr(true)})
		}
		if decryptCtx.EncryptedTo != "" {
			fields = append(fields, payloads.DisplayField{Label: "Encrypted To", Value: decryptCtx.EncryptedTo})
		}
		if decryptCtx.MessageSize > 0 {
			fields = append(fields, payloads.DisplayField{Label: "Message Size", Value: fmt.Sprintf("%d bytes", decryptCtx.MessageSize)})
		}
	}

	// Build GPG decrypt payload using the generated e2ee-payloads request type.
	icon := "lock.open"
	historyTitle := "GPG Decryption"
	display := &payloads.DisplaySchema{
		Title:        "Decrypt message?",
		HistoryTitle: &historyTitle,
		Icon:         &icon,
		Fields:       fields,
	}

	// PKESK-based decryption: the approver unwraps the session key from the
	// PKESK packet using the on-device ECDH subkey selected by DeviceKeyId.
	// EncryptedData is required by the schema but unused on this path, so
	// pass an empty byte slice.
	var pkeskVal payloads.PkeskData
	if pkesk != nil {
		pkeskVal = *pkesk
	}
	payload := payloads.MailboxGpgDecryptRequestPayloadV1{
		DeviceKeyId:   key.Hex(),
		Display:       display,
		EncryptedData: []byte{},
		Pkesk:         pkeskVal,
		SourceInfo:    processInfo.ToSourceInfo(),
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	// Send request using builder (handles encryption, submission, polling)
	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey(key.IOSKeyID, key.Hex()).
		SendAndDecrypt(ctx, payload)
	if err != nil {
		return nil, err
	}

	// Parse the JSON response
	var gpgResponse client.GPGDecryptResponse
	if err := json.Unmarshal(decrypted, &gpgResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !gpgResponse.IsSuccess() {
		return nil, gpgResponse.Error()
	}

	return &gpgResponse, nil
}
