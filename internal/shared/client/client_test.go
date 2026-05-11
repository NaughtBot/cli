package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authapi "github.com/clarifiedlabs/ackagent-monorepo/ackagent-api/go/auth"
	protocol "github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/protocol"
)

func TestNewClient_InvalidURL(t *testing.T) {
	// NewClient should return an error for invalid URLs instead of silently leaving
	// API clients nil (which would cause panics on first use).
	_, err := NewClient("://invalid", "test-device")
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}

// TestNewClient_HTTPClientTimeoutExceedsLongPollCap is a regression test for
// the SSH e2e failure where the shared http.Client had a 10s Timeout while
// the relay's long-poll cap is 25s and the CLI's long-poll request param is
// 30s. The mismatch caused the first exchange GET to die with
// "Client.Timeout exceeded while awaiting headers" exactly as the relay was
// writing the responded body, and the enrollment/sign CLI paths to fail with
// "timeout waiting for exchange response" even when the iOS approver had
// already POSTed /respond successfully.
func TestNewClient_HTTPClientTimeoutExceedsLongPollCap(t *testing.T) {
	c, err := NewClient("http://127.0.0.1:8080", "test-device")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Relay cap is 25s; CLI long-poll request param is 30s. The
	// http.Client.Timeout must comfortably exceed the larger so that a
	// long-poll held to its full duration does not race against the
	// transport-level timeout.
	const minTimeout = 35 * time.Second
	if c.httpClient.Timeout < minTimeout {
		t.Errorf(
			"httpClient.Timeout = %s, want >= %s (must exceed relay long-poll cap + margin)",
			c.httpClient.Timeout, minTimeout,
		)
	}
}

func TestGetErrorCode(t *testing.T) {
	// nil code returns nil
	if got := getErrorCode(nil); got != nil {
		t.Errorf("getErrorCode(nil) = %v, want nil", got)
	}

	// non-nil code returns pointer to int
	code := protocol.AckAgentCommonSigningErrorCode(3)
	got := getErrorCode(&code)
	if got == nil {
		t.Fatal("getErrorCode(&3) = nil, want non-nil")
	}
	if *got != 3 {
		t.Errorf("getErrorCode(&3) = %d, want 3", *got)
	}
}

func TestGetErrorMessage(t *testing.T) {
	if got := getErrorMessage(nil); got != "" {
		t.Errorf("getErrorMessage(nil) = %q, want empty", got)
	}

	msg := "test error"
	if got := getErrorMessage(&msg); got != "test error" {
		t.Errorf("getErrorMessage(&msg) = %q, want %q", got, msg)
	}
}

func TestSigningError_AllCodes(t *testing.T) {
	tests := []struct {
		code    int
		wantNil bool
		wantSub string // substring expected in error message
	}{
		{1, false, "rejected"},
		{2, false, "expired"},
		{3, false, "unsupported algorithm"},
		{4, false, "invalid requester"},
		{5, false, "key not found"},
		{6, false, "internal error"},
		{99, false, "unknown error"},
	}

	for _, tt := range tests {
		code := tt.code
		err := signingError(&code, "details", "signing")
		if err == nil {
			t.Errorf("signingError(%d) = nil, want error", tt.code)
			continue
		}
		if tt.wantSub != "" {
			if got := err.Error(); !contains(got, tt.wantSub) {
				t.Errorf("signingError(%d) = %q, want substring %q", tt.code, got, tt.wantSub)
			}
		}
	}

	// nil code returns nil
	if err := signingError(nil, "msg", "signing"); err != nil {
		t.Errorf("signingError(nil) = %v, want nil", err)
	}
}

func TestResponseWrappers_Error(t *testing.T) {
	// SigningResponse with error code
	code := protocol.AckAgentCommonSigningErrorCode(1)
	msg := "user declined"
	sr := &SigningResponse{protocol.SignatureResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if sr.IsSuccess() {
		t.Error("SigningResponse with error code should not be success")
	}
	if err := sr.Error(); err == nil {
		t.Error("SigningResponse.Error() should return error")
	}

	// GPGSignResponse with error code
	gr := &GPGSignResponse{protocol.GpgSignatureResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if gr.IsSuccess() {
		t.Error("GPGSignResponse with error code should not be success")
	}
	if err := gr.Error(); err == nil {
		t.Error("GPGSignResponse.Error() should return error")
	}

	// GPGDecryptResponse with error code
	dr := &GPGDecryptResponse{protocol.GpgDecryptResponse{ErrorCode: &code, ErrorMessage: &msg}}
	if dr.IsSuccess() {
		t.Error("GPGDecryptResponse with error code should not be success")
	}
	if err := dr.Error(); err == nil {
		t.Error("GPGDecryptResponse.Error() should return error")
	}
}

func TestGetApprovalProofConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/approval-proofs/config" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authapi.ApprovalProofConfigResponse{
			AttestationVersion: "approval-attestation/v1",
			ProofVersion:       "approval-attested-key-proof/v1",
			CircuitIdHex:       "abc123",
			ActiveKeyId:        "issuer-key-1",
			IssuerKeys: []authapi.ApprovalProofIssuerKey{
				{
					KeyId:        "issuer-key-1",
					PublicKeyHex: "02112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
				},
			},
			PolicyVersion:              7,
			AttestationLifetimeSeconds: 3600,
		})
	}))
	defer server.Close()

	c, err := NewClient(server.URL, "test-device")
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	cfg, err := c.GetApprovalProofConfig(context.Background())
	if err != nil {
		t.Fatalf("GetApprovalProofConfig failed: %v", err)
	}
	if cfg.PolicyVersion != 7 {
		t.Fatalf("unexpected policy version: %d", cfg.PolicyVersion)
	}
	if len(cfg.IssuerKeys) != 1 || cfg.IssuerKeys[0].KeyId != "issuer-key-1" {
		t.Fatalf("unexpected issuer keys: %#v", cfg.IssuerKeys)
	}
}

// contains checks if s contains substr (avoids importing strings for a single test helper).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
