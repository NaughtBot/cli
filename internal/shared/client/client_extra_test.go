package client

import (
	"context"
	"errors"
	"testing"
	"time"

	protocol "github.com/naughtbot/cli/internal/protocol"
)

func TestNewClient_ValidURL(t *testing.T) {
	c, err := NewClient("http://localhost:8080", "device-123")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if c.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %q, want http://localhost:8080", c.baseURL)
	}
	if c.deviceID != "device-123" {
		t.Errorf("deviceID = %q, want device-123", c.deviceID)
	}
}

func TestClient_SetAccessToken(t *testing.T) {
	c, _ := NewClient("http://localhost:8080", "device-123")
	c.SetAccessToken("my-token")
	if c.accessToken != "my-token" {
		t.Errorf("accessToken = %q, want my-token", c.accessToken)
	}
}

func TestSigningResponse_IsSuccess(t *testing.T) {
	sig := []byte("signature")

	tests := []struct {
		name string
		resp SigningResponse
		want bool
	}{
		{"success", SigningResponse{protocol.SignatureResponse{Signature: &sig}}, true},
		{"no signature", SigningResponse{protocol.SignatureResponse{}}, false},
		{"empty signature", SigningResponse{protocol.SignatureResponse{Signature: ptr([]byte{})}}, false},
		{"error code present", SigningResponse{protocol.SignatureResponse{
			ErrorCode: ptrCode(1),
			Signature: &sig,
		}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningResponse_GetSignature(t *testing.T) {
	sig := []byte("my-sig")
	sr := &SigningResponse{protocol.SignatureResponse{Signature: &sig}}
	if got := sr.GetSignature(); string(got) != "my-sig" {
		t.Errorf("GetSignature() = %q, want my-sig", got)
	}

	sr2 := &SigningResponse{}
	if got := sr2.GetSignature(); got != nil {
		t.Errorf("GetSignature() on nil = %v, want nil", got)
	}
}

func TestSigningResponse_Error_NoErrorCode(t *testing.T) {
	// No error code, no signature → rejected
	sr := &SigningResponse{}
	err := sr.Error()
	if err != ErrRejected {
		t.Errorf("Error() = %v, want ErrRejected", err)
	}
}

func TestGPGSignResponse_IsSuccess(t *testing.T) {
	armored := "armored-sig"

	tests := []struct {
		name string
		resp GPGSignResponse
		want bool
	}{
		{"success", GPGSignResponse{protocol.GpgSignatureResponse{ArmoredSignature: &armored}}, true},
		{"empty signature", GPGSignResponse{protocol.GpgSignatureResponse{ArmoredSignature: ptr2("")}}, false},
		{"no signature", GPGSignResponse{protocol.GpgSignatureResponse{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGPGSignResponse_GetArmoredSignature(t *testing.T) {
	armored := "-----BEGIN PGP SIGNATURE-----"
	r := &GPGSignResponse{protocol.GpgSignatureResponse{ArmoredSignature: &armored}}
	if got := r.GetArmoredSignature(); got != armored {
		t.Errorf("GetArmoredSignature() = %q, want %q", got, armored)
	}

	r2 := &GPGSignResponse{}
	if got := r2.GetArmoredSignature(); got != "" {
		t.Errorf("GetArmoredSignature() on nil = %q, want empty", got)
	}
}

func TestGPGDecryptResponse_IsSuccess(t *testing.T) {
	key := []byte("session-key")

	tests := []struct {
		name string
		resp GPGDecryptResponse
		want bool
	}{
		{"success", GPGDecryptResponse{protocol.GpgDecryptResponse{SessionKey: &key}}, true},
		{"no key", GPGDecryptResponse{protocol.GpgDecryptResponse{}}, false},
		{"empty key", GPGDecryptResponse{protocol.GpgDecryptResponse{SessionKey: ptr([]byte{})}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.resp.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGPGDecryptResponse_GetAlgorithm(t *testing.T) {
	algo := int32(9) // AES256
	r := &GPGDecryptResponse{protocol.GpgDecryptResponse{Algorithm: &algo}}
	if got := r.GetAlgorithm(); got != 9 {
		t.Errorf("GetAlgorithm() = %d, want 9", got)
	}

	r2 := &GPGDecryptResponse{}
	if got := r2.GetAlgorithm(); got != 0 {
		t.Errorf("GetAlgorithm() on nil = %d, want 0", got)
	}
}

func TestDefaultPollConfig(t *testing.T) {
	cfg := DefaultPollConfig()
	if cfg.InitialInterval <= 0 {
		t.Error("InitialInterval should be positive")
	}
	if cfg.MaxInterval <= cfg.InitialInterval {
		t.Error("MaxInterval should be greater than InitialInterval")
	}
	if cfg.Multiplier <= 1 {
		t.Error("Multiplier should be greater than 1")
	}
}

func TestUserAgent(t *testing.T) {
	ua := userAgent()
	if ua == "" {
		t.Error("userAgent() should not be empty")
	}
	if !containsAt(ua, "oobsign-cli/") {
		t.Errorf("userAgent() = %q, want prefix oobsign-cli/", ua)
	}
}

func TestPoll_CancelsDuringTransientErrorBackoff(t *testing.T) {
	cfg := PollConfig{
		InitialInterval: 200 * time.Millisecond,
		MaxInterval:     200 * time.Millisecond,
		Multiplier:      1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := poll(ctx, time.Second, cfg,
		func(context.Context) (string, error) {
			return "", errors.New("temporary failure")
		},
		func(string) (bool, error) {
			return false, nil
		},
	)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if elapsed >= cfg.InitialInterval {
		t.Fatalf("expected cancellation before full backoff elapsed, took %v", elapsed)
	}
}

// Helpers
func ptr(v []byte) *[]byte  { return &v }
func ptr2(v string) *string { return &v }
func ptrCode(v int) *protocol.AckAgentCommonSigningErrorCode {
	c := protocol.AckAgentCommonSigningErrorCode(v)
	return &c
}
