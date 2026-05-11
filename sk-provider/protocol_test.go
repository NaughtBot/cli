package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/naughtbot/cli/internal/shared/client"
	sharedtestdata "github.com/naughtbot/cli/internal/shared/testdata"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// ProtocolTestVectors matches the structure of data/protocol_test_vectors.json
type ProtocolTestVectors struct {
	Description string       `json:"description"`
	SSHSK       SSHSKVectors `json:"ssh_sk"`
	TestKey     TestKey      `json:"test_key"`
}

type SSHSKVectors struct {
	Description         string                    `json:"description"`
	MessageConstruction []MessageConstructionCase `json:"message_construction"`
	EnrollResponse      ResponseContract          `json:"enroll_response"`
	SignResponse        ResponseContract          `json:"sign_response"`
}

type MessageConstructionCase struct {
	Description           string `json:"description"`
	Application           string `json:"application"`
	ApplicationHashHex    string `json:"application_hash_hex"`
	DataHex               string `json:"data_hex"`
	DataHashHex           string `json:"data_hash_hex"`
	Flags                 uint8  `json:"flags"`
	Counter               uint32 `json:"counter"`
	ExpectedMessageHex    string `json:"expected_message_hex"`
	ExpectedMessageLength int    `json:"expected_message_length"`
}

type ResponseContract struct {
	Description    string            `json:"description"`
	RequiredFields []string          `json:"required_fields"`
	OptionalFields []string          `json:"optional_fields,omitempty"`
	Examples       []ResponseExample `json:"examples"`
}

type ResponseExample struct {
	Description string                 `json:"description"`
	JSON        map[string]interface{} `json:"json"`
}

type TestKey struct {
	Description              string `json:"description"`
	PrivateKeyDHex           string `json:"private_key_d_hex"`
	PublicKeyXHex            string `json:"public_key_x_hex"`
	PublicKeyYHex            string `json:"public_key_y_hex"`
	PublicKeyUncompressedHex string `json:"public_key_uncompressed_hex"`
}

func loadProtocolVectors(t *testing.T) *ProtocolTestVectors {
	t.Helper()

	path := sharedtestdata.Path(t, "protocol_test_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read protocol test vectors: %v", err)
	}

	var vectors ProtocolTestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse protocol test vectors: %v", err)
	}

	return &vectors
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", s, err)
	}
	return b
}

// BuildSSHSKMessage constructs the SSH SK protocol message that gets signed.
// Format: SHA256(application) || flags || counter (big-endian) || SHA256(data)
func BuildSSHSKMessage(application string, data []byte, flags uint8, counter uint32) []byte {
	var msg bytes.Buffer

	// 1. SHA256(application) - 32 bytes
	appHash := sha256.Sum256([]byte(application))
	msg.Write(appHash[:])

	// 2. flags - 1 byte
	msg.WriteByte(flags)

	// 3. counter - 4 bytes big-endian
	binary.Write(&msg, binary.BigEndian, counter)

	// 4. SHA256(data) - 32 bytes
	dataHash := sha256.Sum256(data)
	msg.Write(dataHash[:])

	return msg.Bytes()
}

// TestSSHSKMessageConstruction verifies the SSH SK message format is correct.
// This test ensures both Go and iOS agree on the exact message format.
func TestSSHSKMessageConstruction(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			data := mustDecodeHex(t, tc.DataHex)
			msg := BuildSSHSKMessage(tc.Application, data, tc.Flags, tc.Counter)

			// Verify length is always 69 bytes (32 + 1 + 4 + 32)
			if len(msg) != 69 {
				t.Errorf("message length: got %d, want 69", len(msg))
			}

			if tc.ExpectedMessageLength != 0 && len(msg) != tc.ExpectedMessageLength {
				t.Errorf("message length mismatch: got %d, want %d", len(msg), tc.ExpectedMessageLength)
			}

			// Verify against expected message
			expectedMsg := mustDecodeHex(t, tc.ExpectedMessageHex)
			if !bytes.Equal(msg, expectedMsg) {
				t.Errorf("message mismatch:\ngot:  %s\nwant: %s", hex.EncodeToString(msg), tc.ExpectedMessageHex)
			}
		})
	}
}

// TestSSHSKMessageComponents verifies individual components of the message.
func TestSSHSKMessageComponents(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, tc := range vectors.SSHSK.MessageConstruction {
		t.Run(tc.Description, func(t *testing.T) {
			// Verify application hash
			appHash := sha256.Sum256([]byte(tc.Application))
			expectedAppHash := mustDecodeHex(t, tc.ApplicationHashHex)
			if !bytes.Equal(appHash[:], expectedAppHash) {
				t.Errorf("application hash mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(appHash[:]), tc.ApplicationHashHex)
			}

			// Verify data hash
			data := mustDecodeHex(t, tc.DataHex)
			dataHash := sha256.Sum256(data)
			expectedDataHash := mustDecodeHex(t, tc.DataHashHex)
			if !bytes.Equal(dataHash[:], expectedDataHash) {
				t.Errorf("data hash mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(dataHash[:]), tc.DataHashHex)
			}
		})
	}
}

// TestEnrollResponseParsing verifies sk_provider can parse iOS enrollment
// response JSON against the e2ee-payloads approved-enroll branch.
func TestEnrollResponseParsing(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, example := range vectors.SSHSK.EnrollResponse.Examples {
		t.Run(example.Description, func(t *testing.T) {
			// Marshal the example JSON
			jsonData, err := json.Marshal(example.JSON)
			if err != nil {
				t.Fatalf("failed to marshal example JSON: %v", err)
			}

			// Parse into the e2ee-payloads approved-enroll branch.
			var resp payloads.MailboxEnrollResponseApprovedV1
			if err := json.Unmarshal(jsonData, &resp); err != nil {
				t.Fatalf("failed to parse approved enrollment response: %v", err)
			}

			// Verify required fields. PublicKeyHex must be 130 hex chars (65
			// bytes uncompressed P-256) for the legacy test vectors.
			if len(resp.PublicKeyHex) != 130 {
				t.Errorf("publicKeyHex length: got %d, want 130 hex chars (65 bytes uncompressed P-256)", len(resp.PublicKeyHex))
			}
			if resp.DeviceKeyId == "" {
				t.Error("device_key_id is empty")
			}
		})
	}
}

// TestSignResponseParsing verifies sk_provider can parse iOS SSH sign
// response JSON against the flat client.SigningResponse helper.
func TestSignResponseParsing(t *testing.T) {
	vectors := loadProtocolVectors(t)

	for _, example := range vectors.SSHSK.SignResponse.Examples {
		t.Run(example.Description, func(t *testing.T) {
			// Marshal the example JSON
			jsonData, err := json.Marshal(example.JSON)
			if err != nil {
				t.Fatalf("failed to marshal example JSON: %v", err)
			}

			// Parse into the flat SigningResponse helper that mirrors the
			// MailboxSshAuthResponseSuccessV1 / Failure union.
			var resp client.SigningResponse
			if err := json.Unmarshal(jsonData, &resp); err != nil {
				t.Fatalf("failed to parse SigningResponse: %v", err)
			}

			if !resp.IsSuccess() {
				t.Fatalf("expected success response, got error: %v", resp.Error())
			}
			if len(resp.GetSignature()) != 64 {
				t.Errorf("signature length: want 64, got %d", len(resp.GetSignature()))
			}
		})
	}
}

// TestEnrollResponseRoundtrip verifies encoding/decoding preserves all fields.
func TestEnrollResponseRoundtrip(t *testing.T) {
	deviceKeyID := "test-key-id"
	publicKeyBytes := make([]byte, 64)
	signature := make([]byte, 64)

	// Fill with recognizable patterns
	for i := range publicKeyBytes {
		publicKeyBytes[i] = byte(i)
	}
	for i := range signature {
		signature[i] = byte(i + 100)
	}

	publicKeyHex := hex.EncodeToString(publicKeyBytes)
	original := payloads.MailboxEnrollResponseApprovedV1{
		Status:          payloads.Approved,
		PublicKeyHex:    publicKeyHex,
		DeviceKeyId:     deviceKeyID,
		SubkeySignature: &signature,
	}

	// Encode
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Decode
	var decoded payloads.MailboxEnrollResponseApprovedV1
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify all fields
	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %q, want %q", decoded.Status, original.Status)
	}
	if decoded.PublicKeyHex != publicKeyHex {
		t.Error("PublicKeyHex mismatch")
	}
	if decoded.DeviceKeyId != deviceKeyID {
		t.Errorf("DeviceKeyId mismatch")
	}
	if decoded.SubkeySignature == nil || !bytes.Equal(*decoded.SubkeySignature, signature) {
		t.Error("SubkeySignature mismatch")
	}
}

// TestSignResponseRoundtrip verifies encoding/decoding preserves all fields.
func TestSignResponseRoundtrip(t *testing.T) {
	signature := make([]byte, 64)
	for i := range signature {
		signature[i] = byte(i)
	}

	original := client.SigningResponse{
		Signature: &signature,
	}

	// Encode
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Decode
	var decoded client.SigningResponse
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !decoded.IsSuccess() {
		t.Error("expected success after roundtrip")
	}
	if !bytes.Equal(decoded.GetSignature(), signature) {
		t.Error("Signature mismatch")
	}
}

// TestMessageLengthIsAlways69Bytes is a sanity check for the protocol.
func TestMessageLengthIsAlways69Bytes(t *testing.T) {
	testCases := []struct {
		application string
		data        []byte
		flags       uint8
		counter     uint32
	}{
		{"ssh:", nil, 1, 1},
		{"ssh:", []byte("hello"), 1, 1},
		{"ssh://github.com", []byte("data"), 5, 100},
		{"ssh://very-long-application-name.example.com", make([]byte, 1000), 255, 0xFFFFFFFF},
	}

	for _, tc := range testCases {
		msg := BuildSSHSKMessage(tc.application, tc.data, tc.flags, tc.counter)
		if len(msg) != 69 {
			t.Errorf("message for app=%q data_len=%d: got %d bytes, want 69",
				tc.application, len(tc.data), len(msg))
		}
	}
}
