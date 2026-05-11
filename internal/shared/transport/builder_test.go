//go:build legacy_api

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	authapi "github.com/naughtbot/api/auth"
	"github.com/google/uuid"
	"github.com/naughtbot/cli/internal/approval"
	"github.com/naughtbot/cli/internal/shared/config"
)

type issuerURLVariant struct {
	uppercaseHost bool
	defaultPort   bool
	trailingDot   bool
	path          string
	trailingSlash bool
}

func deriveIssuerURL(t *testing.T, base string, variant issuerURLVariant) string {
	t.Helper()

	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", base, err)
	}

	host := parsed.Hostname()
	if variant.uppercaseHost {
		host = strings.ToUpper(host)
	}
	if variant.trailingDot {
		host += "."
	}

	port := parsed.Port()
	if variant.defaultPort {
		port = defaultPortForScheme(parsed.Scheme)
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else {
		parsed.Host = host
	}

	if variant.path != "" {
		parsed.Path = variant.path
	}
	if variant.trailingSlash {
		if parsed.Path == "" {
			parsed.Path = "/"
		} else if !strings.HasSuffix(parsed.Path, "/") {
			parsed.Path += "/"
		}
	}

	return parsed.String()
}

func TestMarshalPayloadWithApprovalChallenge_InsertsExplicitChallenge(t *testing.T) {
	requestID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	payloadBytes, challenge, err := marshalPayloadWithApprovalChallenge(map[string]any{
		"type": "custom",
		"data": "value",
	}, requestID)
	if err != nil {
		t.Fatalf("marshalPayloadWithApprovalChallenge: %v", err)
	}

	if challenge.Version != approval.ApprovalChallengeVersion {
		t.Fatalf("unexpected challenge version: %q", challenge.Version)
	}
	if challenge.Nonce != requestID.String() {
		t.Fatalf("unexpected nonce: %q", challenge.Nonce)
	}
	if challenge.RequestID != requestID.String() {
		t.Fatalf("unexpected request ID: %q", challenge.RequestID)
	}

	var payloadObject map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadObject); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	challengeObject, ok := payloadObject["approvalChallenge"].(map[string]any)
	if !ok {
		t.Fatalf("approvalChallenge missing from payload: %#v", payloadObject)
	}
	if challengeObject["requestId"] != requestID.String() {
		t.Fatalf("unexpected requestId in payload challenge: %#v", challengeObject)
	}
}

func TestMarshalPayloadWithApprovalChallenge_UsesPayloadNonceWhenPresent(t *testing.T) {
	requestID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	_, challenge, err := marshalPayloadWithApprovalChallenge(map[string]any{
		"type":  "captcha",
		"nonce": "nonce-123",
	}, requestID)
	if err != nil {
		t.Fatalf("marshalPayloadWithApprovalChallenge: %v", err)
	}

	if challenge.Nonce != "nonce-123" {
		t.Fatalf("unexpected nonce: %q", challenge.Nonce)
	}
}

func TestMarshalPayloadWithApprovalChallenge_RespectsExplicitChallenge(t *testing.T) {
	requestID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	explicit := approval.ApprovalChallenge{
		Version:       approval.ApprovalChallengeVersion,
		Nonce:         "nonce-123",
		RequestID:     requestID.String(),
		PlaintextHash: "sha256:abc123",
	}

	payloadBytes, challenge, err := marshalPayloadWithApprovalChallenge(map[string]any{
		"type":              "custom",
		"approvalChallenge": explicit,
	}, requestID)
	if err != nil {
		t.Fatalf("marshalPayloadWithApprovalChallenge: %v", err)
	}
	if challenge != explicit {
		t.Fatalf("unexpected explicit challenge: %#v", challenge)
	}

	var payloadObject map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadObject); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	challengeObject, ok := payloadObject["approvalChallenge"].(map[string]any)
	if !ok {
		t.Fatalf("approvalChallenge missing from payload: %#v", payloadObject)
	}
	if challengeObject["plaintextHash"] != explicit.PlaintextHash {
		t.Fatalf("unexpected plaintextHash in payload challenge: %#v", challengeObject)
	}
}

func TestMarshalPayloadWithApprovalChallenge_RejectsMismatchedExplicitRequestID(t *testing.T) {
	requestID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	_, _, err := marshalPayloadWithApprovalChallenge(map[string]any{
		"type": "custom",
		"approvalChallenge": approval.ApprovalChallenge{
			Version:       approval.ApprovalChallengeVersion,
			Nonce:         "nonce-123",
			RequestID:     "different-request-id",
			PlaintextHash: "sha256:abc123",
		},
	}, requestID)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestValidateApprovalProofCircuitPinning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuerURL    string
		circuitIDHex string
		wantErr      bool
	}{
		{
			name:         "production rejects empty circuit pin",
			issuerURL:    config.Production.IssuerURL,
			circuitIDHex: " \t",
			wantErr:      true,
		},
		{
			name:         "production trailing slash rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Production.IssuerURL, issuerURLVariant{trailingSlash: true}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "sandbox uppercase host rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Sandbox.IssuerURL, issuerURLVariant{uppercaseHost: true, trailingSlash: true}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "production default https port rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Production.IssuerURL, issuerURLVariant{defaultPort: true}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "production trailing dot host rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Production.IssuerURL, issuerURLVariant{trailingDot: true}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "production base path rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Production.IssuerURL, issuerURLVariant{path: "/some/basepath"}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "production dot path rejects empty circuit pin",
			issuerURL:    deriveIssuerURL(t, config.Production.IssuerURL, issuerURLVariant{path: "/."}),
			circuitIDHex: "",
			wantErr:      true,
		},
		{
			name:         "production allows pinned circuit",
			issuerURL:    config.Production.IssuerURL,
			circuitIDHex: "abc123",
		},
		{
			name:         "localdev allows empty circuit pin",
			issuerURL:    config.LocalDev.IssuerURL,
			circuitIDHex: "",
		},
		{
			name:         "custom issuer allows empty circuit pin",
			issuerURL:    "https://issuer.example.com",
			circuitIDHex: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateApprovalProofCircuitPinning(tt.issuerURL, tt.circuitIDHex)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("validateApprovalProofCircuitPinning() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("validateApprovalProofCircuitPinning() returned nil error")
			}
			if !errors.Is(err, ErrApprovalProofCircuitPinningRequired) {
				t.Fatalf("validateApprovalProofCircuitPinning() error = %v, want errors.Is(_, ErrApprovalProofCircuitPinningRequired)", err)
			}
		})
	}
}

func TestApprovalProofVerifier_RejectsEmptyCircuitPinForManagedIssuers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/approval-proofs/config" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authapi.ApprovalProofConfigResponse{
			AttestationVersion: "approval-attestation/v1",
			ProofVersion:       "approval-attested-key-proof/v1",
			CircuitIdHex:       "",
			ActiveKeyId:        "issuer-key-1",
			IssuerKeys: []authapi.ApprovalProofIssuerKey{
				{
					KeyId:        "issuer-key-1",
					PublicKeyHex: "02112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
				},
			},
			PolicyVersion: 7,
		})
	}))
	defer server.Close()

	originalProdURL := config.Production.IssuerURL
	config.Production.IssuerURL = server.URL
	defer func() {
		config.Production.IssuerURL = originalProdURL
	}()

	cfg := &config.Config{
		DeviceID:      "test-device",
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				IssuerURL: server.URL,
				UserAccount: &config.UserAccount{
					RequesterID: "requester-123",
				},
			},
		},
	}

	builder := &RequestBuilder{cfg: cfg}
	_, err := builder.approvalProofVerifier(context.Background(), "unused-token")
	if err == nil {
		t.Fatal("approvalProofVerifier() returned nil error")
	}
	if !errors.Is(err, ErrApprovalProofCircuitPinningRequired) {
		t.Fatalf("approvalProofVerifier() error = %v, want errors.Is(_, ErrApprovalProofCircuitPinningRequired)", err)
	}
}

func TestLoadApprovalProofConfig_RefetchesInvalidManagedCache(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/approval-proofs/config" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
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
			PolicyVersion: 7,
		})
	}))
	defer server.Close()

	originalProdURL := config.Production.IssuerURL
	config.Production.IssuerURL = server.URL
	defer func() {
		config.Production.IssuerURL = originalProdURL
	}()

	cfg := &config.Config{
		DeviceID:      "test-device",
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				IssuerURL: server.URL,
				ApprovalProofConfig: &config.ApprovalProofVerifierConfig{
					PolicyVersion: 1,
					CircuitIDHex:  "",
					IssuerKeys: []config.ApprovalProofIssuerKey{
						{KeyID: "stale-key", PublicKeyHex: "stale"},
					},
				},
			},
		},
	}

	builder := &RequestBuilder{cfg: cfg}
	proofConfig, err := builder.loadApprovalProofConfig(context.Background(), "unused-token")
	if err != nil {
		t.Fatalf("loadApprovalProofConfig() error = %v", err)
	}
	if proofConfig.CircuitIDHex != "abc123" {
		t.Fatalf("loadApprovalProofConfig() CircuitIDHex = %q, want %q", proofConfig.CircuitIDHex, "abc123")
	}
	if cfg.Profiles[config.DefaultProfileName].ApprovalProofConfig.CircuitIDHex != "abc123" {
		t.Fatalf("cached CircuitIDHex = %q, want %q", cfg.Profiles[config.DefaultProfileName].ApprovalProofConfig.CircuitIDHex, "abc123")
	}
}

func TestLoadApprovalProofConfig_DoesNotPersistInvalidManagedFetch(t *testing.T) {
	tmpDir := t.TempDir()
	config.SetConfigDir(tmpDir)
	defer config.ResetConfigDir()

	var circuitIDHexMu sync.RWMutex
	circuitIDHex := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/approval-proofs/config" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		circuitIDHexMu.RLock()
		currentCircuitIDHex := circuitIDHex
		circuitIDHexMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authapi.ApprovalProofConfigResponse{
			AttestationVersion: "approval-attestation/v1",
			ProofVersion:       "approval-attested-key-proof/v1",
			CircuitIdHex:       currentCircuitIDHex,
			ActiveKeyId:        "issuer-key-1",
			IssuerKeys: []authapi.ApprovalProofIssuerKey{
				{
					KeyId:        "issuer-key-1",
					PublicKeyHex: "02112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
				},
			},
			PolicyVersion: 7,
		})
	}))
	defer server.Close()

	originalProdURL := config.Production.IssuerURL
	config.Production.IssuerURL = server.URL
	defer func() {
		config.Production.IssuerURL = originalProdURL
	}()

	cfg := &config.Config{
		DeviceID:      "test-device",
		ActiveProfile: config.DefaultProfileName,
		Profiles: map[string]*config.ProfileConfig{
			config.DefaultProfileName: {
				IssuerURL: server.URL,
			},
		},
	}

	builder := &RequestBuilder{cfg: cfg}
	_, err := builder.loadApprovalProofConfig(context.Background(), "unused-token")
	if !errors.Is(err, ErrApprovalProofCircuitPinningRequired) {
		t.Fatalf("loadApprovalProofConfig() error = %v, want errors.Is(_, ErrApprovalProofCircuitPinningRequired)", err)
	}
	if cfg.Profiles[config.DefaultProfileName].ApprovalProofConfig != nil {
		t.Fatal("invalid managed config should not be cached")
	}

	circuitIDHexMu.Lock()
	circuitIDHex = "abc123"
	circuitIDHexMu.Unlock()
	proofConfig, err := builder.loadApprovalProofConfig(context.Background(), "unused-token")
	if err != nil {
		t.Fatalf("loadApprovalProofConfig() retry error = %v", err)
	}
	if proofConfig.CircuitIDHex != "abc123" {
		t.Fatalf("loadApprovalProofConfig() retry CircuitIDHex = %q, want %q", proofConfig.CircuitIDHex, "abc123")
	}
}
