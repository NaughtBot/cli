package client

import (
	"fmt"

	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// signingError converts an error code and message into a descriptive error.
// The noun parameter describes the request type (e.g., "signing", "decryption").
// Returns nil if errCode is nil (caller should handle no-code case).
func signingError(errCode *int, errMsg, noun string) error {
	if errCode == nil {
		return nil
	}
	code := payloads.SigningErrorCode(*errCode)
	switch code {
	case payloads.SigningErrorCodeN1: // rejected
		return fmt.Errorf("%s request rejected: %s", noun, errMsg)
	case payloads.SigningErrorCodeN2: // timeout
		return ErrExpired
	case payloads.SigningErrorCodeN3: // key not found
		return fmt.Errorf("key not found: %s", errMsg)
	case payloads.SigningErrorCodeN4: // invalid payload
		return fmt.Errorf("invalid payload: %s", errMsg)
	case payloads.SigningErrorCodeN5: // attestation failed
		return fmt.Errorf("attestation failed: %s", errMsg)
	case payloads.SigningErrorCodeN6: // internal error
		return fmt.Errorf("internal error: %s", errMsg)
	default:
		return fmt.Errorf("unknown error (code %d): %s", *errCode, errMsg)
	}
}

// SigningResponse is a flat helper view over the discriminated
// MailboxSshSignResponsePayloadV1 / MailboxSshAuthResponsePayloadV1 /
// MailboxPkcs11SignResponsePayloadV1 unions in `github.com/naughtbot/e2ee-payloads/go`.
//
// The generated union types wrap an unexported `union json.RawMessage` so they
// cannot be JSON-unmarshalled in one shot from the approver-decrypted
// plaintext — callers would otherwise have to peek at the wire bytes, pick a
// branch, and re-unmarshal. This flat helper preserves the snake_case wire
// field names (`signature`, `error_code`, `error_message`) exactly as the
// generated success / failure branches emit them and turns the union routing
// into a single struct + IsSuccess/Error methods.
//
// This is NOT a parallel schema definition — the JSON tags trace 1:1 to the
// generated `MailboxSshSignResponseSuccessV1.Signature` /
// `MailboxSshSignResponseFailureV1.{ErrorCode, ErrorMessage}` fields. The
// helper goes away once a future e2ee-payloads release exposes top-level
// `As<Branch>` methods that can decode directly from the raw response bytes.
type SigningResponse struct {
	Signature    *[]byte `json:"signature,omitempty"`
	ErrorCode    *int    `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

// IsSuccess returns true if the response contains a signature
func (r *SigningResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.Signature != nil && len(*r.Signature) > 0
}

// GetSignature returns the signature bytes, or nil if not present.
func (r *SigningResponse) GetSignature() []byte {
	if r.Signature == nil {
		return nil
	}
	return *r.Signature
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *SigningResponse) GetErrorCode() *int { return r.ErrorCode }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *SigningResponse) GetErrorMessage() string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// Error returns an error for unsuccessful responses
func (r *SigningResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "signing"); err != nil {
		return err
	}
	return ErrRejected
}

// GPGSignResponse is a flat helper view over the discriminated
// MailboxGpgSignResponsePayloadV1 union.
type GPGSignResponse struct {
	ArmoredSignature *string `json:"armored_signature,omitempty"`
	ErrorCode        *int    `json:"error_code,omitempty"`
	ErrorMessage     *string `json:"error_message,omitempty"`
}

// IsSuccess returns true if the response contains an armored signature
func (r *GPGSignResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.ArmoredSignature != nil && *r.ArmoredSignature != ""
}

// GetArmoredSignature returns the armored signature, or empty string if not present.
func (r *GPGSignResponse) GetArmoredSignature() string {
	if r.ArmoredSignature == nil {
		return ""
	}
	return *r.ArmoredSignature
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *GPGSignResponse) GetErrorCode() *int { return r.ErrorCode }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *GPGSignResponse) GetErrorMessage() string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// Error returns an error for unsuccessful responses
func (r *GPGSignResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "signing"); err != nil {
		return err
	}
	return ErrRejected
}

// GPGDecryptResponse is a flat helper view over the discriminated
// MailboxGpgDecryptResponsePayloadV1 union.
type GPGDecryptResponse struct {
	SessionKey   *[]byte `json:"session_key,omitempty"`
	Algorithm    *int32  `json:"algorithm,omitempty"`
	ErrorCode    *int    `json:"error_code,omitempty"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

// IsSuccess returns true if the response contains a session key
func (r *GPGDecryptResponse) IsSuccess() bool {
	return r.ErrorCode == nil && r.SessionKey != nil && len(*r.SessionKey) > 0
}

// GetSessionKey returns the session key bytes, or nil if not present.
func (r *GPGDecryptResponse) GetSessionKey() []byte {
	if r.SessionKey == nil {
		return nil
	}
	return *r.SessionKey
}

// GetAlgorithm returns the algorithm byte, or 0 if not present.
func (r *GPGDecryptResponse) GetAlgorithm() byte {
	if r.Algorithm == nil {
		return 0
	}
	return byte(*r.Algorithm)
}

// GetErrorCode returns the error code as int, or nil if not present.
func (r *GPGDecryptResponse) GetErrorCode() *int { return r.ErrorCode }

// GetErrorMessage returns the error message, or empty string if not present.
func (r *GPGDecryptResponse) GetErrorMessage() string {
	if r.ErrorMessage == nil {
		return ""
	}
	return *r.ErrorMessage
}

// Error returns an error for unsuccessful responses
func (r *GPGDecryptResponse) Error() error {
	if r.IsSuccess() {
		return nil
	}
	if err := signingError(r.GetErrorCode(), r.GetErrorMessage(), "decryption"); err != nil {
		return err
	}
	return ErrRejected
}
