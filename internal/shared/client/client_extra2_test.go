package client

import (
	"testing"
)

func TestSigningResponse_Error_WithErrorCode(t *testing.T) {
	code := 3
	msg := "key not found"
	sig := []byte("sig")
	sr := &SigningResponse{
		ErrorCode:    &code,
		ErrorMessage: &msg,
		Signature:    &sig,
	}

	err := sr.Error()
	if err == nil {
		t.Fatal("expected error")
	}
	// Just verify the error message contains meaningful content
	if err.Error() == "" {
		t.Error("Error() string should not be empty")
	}
}

func TestSigningResponse_Error_Success(t *testing.T) {
	sig := []byte("signature")
	sr := &SigningResponse{
		Signature: &sig,
	}

	err := sr.Error()
	if err != nil {
		t.Errorf("expected nil error for success, got: %v", err)
	}
}

func TestGPGSignResponse_Error(t *testing.T) {
	// Success case
	armored := "armored"
	r := &GPGSignResponse{ArmoredSignature: &armored}
	if err := r.Error(); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	// Error code case
	code := 2
	msg := "rejected"
	r2 := &GPGSignResponse{ErrorCode: &code, ErrorMessage: &msg}
	if err := r2.Error(); err == nil {
		t.Error("expected error")
	}

	// Rejected case (no error code, no signature)
	r3 := &GPGSignResponse{}
	if err := r3.Error(); err != ErrRejected {
		t.Errorf("expected ErrRejected, got: %v", err)
	}
}

func TestGPGDecryptResponse_Error(t *testing.T) {
	// Success case
	key := []byte("key")
	r := &GPGDecryptResponse{SessionKey: &key}
	if err := r.Error(); err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	// Error code case
	code := 2
	msg := "no matching key"
	r2 := &GPGDecryptResponse{ErrorCode: &code, ErrorMessage: &msg}
	if err := r2.Error(); err == nil {
		t.Error("expected error")
	}

	// Rejected case
	r3 := &GPGDecryptResponse{}
	if err := r3.Error(); err != ErrRejected {
		t.Errorf("expected ErrRejected, got: %v", err)
	}
}

func TestGPGDecryptResponse_GetSessionKey(t *testing.T) {
	key := []byte("session-key-data")
	r := &GPGDecryptResponse{SessionKey: &key}
	got := r.GetSessionKey()
	if string(got) != "session-key-data" {
		t.Errorf("GetSessionKey() = %q, want session-key-data", got)
	}

	// Nil case
	r2 := &GPGDecryptResponse{}
	if got := r2.GetSessionKey(); got != nil {
		t.Errorf("GetSessionKey() on nil = %v, want nil", got)
	}
}

func TestSigningResponse_GetErrorCode(t *testing.T) {
	// With error code
	code := 5
	sr := &SigningResponse{ErrorCode: &code}
	got := sr.GetErrorCode()
	if got == nil || *got != 5 {
		t.Errorf("GetErrorCode() = %v, want 5", got)
	}

	// Without error code
	sr2 := &SigningResponse{}
	if got := sr2.GetErrorCode(); got != nil {
		t.Errorf("GetErrorCode() on nil = %v, want nil", got)
	}
}

func TestSigningResponse_GetErrorMessage(t *testing.T) {
	msg := "test error"
	sr := &SigningResponse{ErrorMessage: &msg}
	got := sr.GetErrorMessage()
	if got != "test error" {
		t.Errorf("GetErrorMessage() = %q, want 'test error'", got)
	}

	sr2 := &SigningResponse{}
	if got := sr2.GetErrorMessage(); got != "" {
		t.Errorf("GetErrorMessage() on nil = %q, want empty", got)
	}
}

func TestGPGSignResponse_GetErrorCode(t *testing.T) {
	code := 3
	r := &GPGSignResponse{ErrorCode: &code}
	got := r.GetErrorCode()
	if got == nil || *got != 3 {
		t.Errorf("GetErrorCode() = %v, want 3", got)
	}
}

func TestGPGSignResponse_GetErrorMessage(t *testing.T) {
	msg := "gpg error"
	r := &GPGSignResponse{ErrorMessage: &msg}
	got := r.GetErrorMessage()
	if got != "gpg error" {
		t.Errorf("GetErrorMessage() = %q, want 'gpg error'", got)
	}
}

func TestGPGDecryptResponse_GetErrorCode(t *testing.T) {
	code := 7
	r := &GPGDecryptResponse{ErrorCode: &code}
	got := r.GetErrorCode()
	if got == nil || *got != 7 {
		t.Errorf("GetErrorCode() = %v, want 7", got)
	}
}

func TestGPGDecryptResponse_GetErrorMessage(t *testing.T) {
	msg := "decrypt error"
	r := &GPGDecryptResponse{ErrorMessage: &msg}
	got := r.GetErrorMessage()
	if got != "decrypt error" {
		t.Errorf("GetErrorMessage() = %q, want 'decrypt error'", got)
	}
}

func TestNewClient_EmptyURL(t *testing.T) {
	_, err := NewClient("", "device-1")
	if err == nil {
		t.Error("NewClient with empty URL should error")
	}
}
