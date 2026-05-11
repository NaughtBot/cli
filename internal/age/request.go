package age

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/log"
	"github.com/naughtbot/cli/internal/shared/sysinfo"
	"github.com/naughtbot/cli/internal/shared/transport"
	"github.com/naughtbot/cli/internal/shared/util"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

var ageLog = log.New("age")

const (
	// RequestTypeAgeUnwrap is the request type for age decryption
	RequestTypeAgeUnwrap = "age_unwrap"
)

// UnwrapResponse is a flat helper view over the discriminated
// MailboxAgeUnwrapResponsePayloadV1 union. The success branch populates
// FileKey; the failure branch populates ErrorCode + ErrorMessage. JSON tags
// match the new e2ee-payloads snake_case wire format so this helper can be
// unmarshalled from raw response bytes directly.
type UnwrapResponse struct {
	FileKey      *[]byte `json:"file_key,omitempty"`
	ErrorCode    *int    `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

// IsSuccess returns true if the response contains a file key
func (r *UnwrapResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.FileKey != nil && len(*r.FileKey) > 0
}

// GetFileKey returns the file key bytes, or nil if not present.
func (r *UnwrapResponse) GetFileKey() []byte {
	if r.FileKey == nil {
		return nil
	}
	return *r.FileKey
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *UnwrapResponse) GetErrorCode() *int { return r.ErrorCode }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *UnwrapResponse) GetErrorMessage() string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// Error returns an error for unsuccessful responses
func (r *UnwrapResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	errCode := r.GetErrorCode()
	if errCode != nil {
		return fmt.Errorf("age unwrap failed (code %d): %s", *errCode, r.GetErrorMessage())
	}
	return fmt.Errorf("age unwrap failed: no file key returned")
}

// RequestUnwrap sends an age unwrap request to iOS and waits for the response.
// This is the main entry point for the identity's UnwrapFunc.
func RequestUnwrap(cfg *config.Config, key *config.KeyMetadata, ephemeralPublic, wrappedFileKey, recipientPublic []byte, fileName string, fileSize int64) ([]byte, error) {
	ctx := context.Background()

	// Collect process info (matching GPG pattern)
	processInfo := sysinfo.GetProcessInfo()

	// Build display fields for Age unwrap approval UI
	lockIcon := "lock.open"
	fields := []payloads.DisplayField{
		{Label: "Key", Value: key.Label, Icon: &lockIcon},
		{Label: "Key ID", Value: truncateHex(key.Hex()), Monospace: util.Ptr(true)},
	}
	if fileName != "" {
		fields = append(fields, payloads.DisplayField{Label: "File", Value: fileName, Monospace: util.Ptr(true)})
	}
	if fileSize > 0 {
		fields = append(fields, payloads.DisplayField{Label: "Size", Value: fmt.Sprintf("%d bytes", fileSize)})
	}
	icon := "lock.open"
	historyTitle := "Age Decryption"
	display := &payloads.DisplaySchema{
		Title:        "Decrypt file?",
		HistoryTitle: &historyTitle,
		Icon:         &icon,
		Fields:       fields,
	}

	// Build the request payload using the generated e2ee-payloads type.
	payload := payloads.MailboxAgeUnwrapRequestPayloadV1{
		EphemeralPublicHex: hex.EncodeToString(ephemeralPublic),
		WrappedFileKey:     wrappedFileKey,
		RecipientPublicHex: hex.EncodeToString(recipientPublic),
		Display:            display,
		SourceInfo:         processInfo.ToSourceInfo(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	ageLog.Debug("sending age unwrap request")

	ageLog.Debug("waiting for iOS approval...")
	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	result, err := transport.NewRequestBuilder(cfg).
		WithKey("", key.Hex()).
		WithTimeout(config.DefaultSigningTimeout).
		WithExpiration(int(config.DefaultSigningTimeout.Seconds())).
		Send(ctx, json.RawMessage(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	switch result.Response.Status {
	case "responded":
	case "expired":
		return nil, fmt.Errorf("request expired")
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}

	decrypted, err := result.Decrypt()
	if err != nil {
		return nil, err
	}

	// Parse response
	var response UnwrapResponse
	if err := json.Unmarshal(decrypted, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.IsSuccess() {
		return nil, response.Error()
	}

	ageLog.Debug("age unwrap successful")
	return response.GetFileKey(), nil
}

// MakeUnwrapFunc creates an UnwrapFunc for use with Identity
func MakeUnwrapFunc(cfg *config.Config, key *config.KeyMetadata, fileName string, fileSize int64) func(ephemeralPublic, wrappedKey, recipientPublic []byte) ([]byte, error) {
	return func(ephemeralPublic, wrappedKey, recipientPublic []byte) ([]byte, error) {
		return RequestUnwrap(cfg, key, ephemeralPublic, wrappedKey, recipientPublic, fileName, fileSize)
	}
}

// EnrollAgeKey sends an enrollment request to generate an age key on iOS
func EnrollAgeKey(cfg *config.Config, label string) (*config.KeyMetadata, error) {
	ctx := context.Background()

	// Build enrollment payload with DisplaySchema
	processInfo := sysinfo.GetProcessInfo()

	icon := "key.fill"
	historyTitle := "Age Key Enrolled"
	subtitle := "Age encryption key enrollment"
	payload := payloads.MailboxEnrollRequestPayloadV1{
		Purpose:    payloads.Age,
		Label:      &label,
		SourceInfo: processInfo.ToSourceInfo(),
		Display: &payloads.DisplaySchema{
			Title:        "Enroll Age Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       []payloads.DisplayField{},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	ageLog.Debug("sending age key enrollment request")

	ageLog.Debug("waiting for iOS approval...")
	fmt.Fprintf(os.Stderr, "Approve key generation on iOS device...\n")

	decrypted, err := transport.SendAndDecryptEnrollment(
		ctx,
		cfg,
		json.RawMessage(payloadBytes),
		config.DefaultSigningTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}

	response, err := transport.ParseEnrollResponse(decrypted)
	if err != nil {
		return nil, err
	}

	if response.PublicKeyHex == "" {
		return nil, fmt.Errorf("response missing public key")
	}
	publicKey, err := hex.DecodeString(response.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: expected 32, got %d", len(publicKey))
	}

	// Create recipient string
	recipient := &Recipient{PublicKey: publicKey}
	recipientStr := recipient.String()

	// Create key metadata.
	// The new MailboxEnrollResponseApprovedV1.DeviceKeyId replaces the legacy
	// IosKeyId field, and is always populated (non-optional in the new schema).
	keyMeta := &config.KeyMetadata{
		IOSKeyID:     response.DeviceKeyId,
		Label:        label,
		PublicKey:    publicKey,
		Algorithm:    "X25519",
		Purpose:      config.KeyPurposeAge,
		CreatedAt:    time.Now(),
		AgeRecipient: recipientStr,
	}

	ageLog.Debug("age key enrolled: %s", recipientStr)
	return keyMeta, nil
}

// truncateHex returns a shortened version of a hex string for display.
func truncateHex(hexStr string) string {
	if len(hexStr) > 16 {
		return hexStr[:8] + "..." + hexStr[len(hexStr)-8:]
	}
	return hexStr
}
