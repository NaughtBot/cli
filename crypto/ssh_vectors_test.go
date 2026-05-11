package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	sharedtestdata "github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/testdata"
)

// SSHTestVectors matches the ssh_vectors structure in data/crypto_test_vectors.json
type SSHTestVectors struct {
	SSHVectors SSHVectors `json:"ssh_vectors"`
}

type SSHVectors struct {
	Description     string             `json:"description"`
	KeyMaterial     SSHKeyMaterial     `json:"key_material"`
	PublicKeyFormat SSHPublicKeyFormat `json:"public_key_format"`
	KeyHandle       SSHKeyHandleVec    `json:"key_handle"`
	SignatureCases  []SSHSignatureCase `json:"signature_cases"`
}

type SSHKeyMaterial struct {
	PrivateKeyDHex string `json:"private_key_d_hex"`
	PublicKeyXHex  string `json:"public_key_x_hex"`
	PublicKeyYHex  string `json:"public_key_y_hex"`
}

type SSHPublicKeyFormat struct {
	KeyType            string `json:"key_type"`
	CurveName          string `json:"curve_name"`
	Application        string `json:"application"`
	BlobHex            string `json:"blob_hex"`
	FingerprintSHA256  string `json:"fingerprint_sha256"`
	AuthorizedKeysLine string `json:"authorized_keys_line"`
}

type SSHKeyHandleVec struct {
	MagicHex          string                 `json:"magic_hex"`
	JSONPayload       map[string]interface{} `json:"json_payload"`
	CompleteHandleHex string                 `json:"complete_handle_hex"`
}

type SSHSignatureCase struct {
	Description     string `json:"description"`
	DataToSignHex   string `json:"data_to_sign_hex"`
	SignatureRHex   string `json:"signature_r_hex"`
	SignatureSHex   string `json:"signature_s_hex"`
	RawSignatureHex string `json:"raw_signature_hex"`
}

func loadSSHVectors(t *testing.T) *SSHTestVectors {
	t.Helper()

	path := sharedtestdata.Path(t, "crypto_test_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}

	var vectors SSHTestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse test vectors: %v", err)
	}
	if vectors.SSHVectors.PublicKeyFormat.KeyType == "" ||
		vectors.SSHVectors.PublicKeyFormat.BlobHex == "" ||
		vectors.SSHVectors.KeyHandle.MagicHex == "" {
		t.Fatal("ssh_vectors fixture missing or incomplete in data/crypto_test_vectors.json")
	}

	return &vectors
}

func mustDecodeSSHHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return b
}

// TestSSHVectorsKeyHandleMagic validates the key handle magic bytes
func TestSSHVectorsKeyHandleMagic(t *testing.T) {
	vectors := loadSSHVectors(t)
	kh := vectors.SSHVectors.KeyHandle
	handleBytes := mustDecodeSSHHex(t, kh.CompleteHandleHex)
	magicBytes := mustDecodeSSHHex(t, kh.MagicHex)

	if len(handleBytes) < 8 {
		t.Fatal("key handle too short")
	}

	if !bytes.Equal(handleBytes[:4], magicBytes) {
		t.Errorf("magic bytes mismatch:\ngot:  %x\nwant: %x", handleBytes[:4], magicBytes)
	}

	if got := binary.LittleEndian.Uint32(magicBytes); got != 0x41505052 {
		t.Errorf("magic value mismatch: got 0x%08x, want 0x41505052", got)
	}
}

// TestSSHVectorsKeyHandleFormat validates key handle structure
func TestSSHVectorsKeyHandleFormat(t *testing.T) {
	vectors := loadSSHVectors(t)
	kh := vectors.SSHVectors.KeyHandle

	handleBytes := mustDecodeSSHHex(t, kh.CompleteHandleHex)

	// Key handle format: [4-byte magic][4-byte length][JSON data]
	if len(handleBytes) < 8 {
		t.Fatal("key handle too short")
	}

	// Check magic (little-endian)
	magic := binary.LittleEndian.Uint32(handleBytes[0:4])
	expectedMagic := uint32(0x41505052) // "APPR"
	if magic != expectedMagic {
		t.Errorf("magic mismatch: got 0x%08x, want 0x%08x", magic, expectedMagic)
	}

	// Check length
	length := binary.LittleEndian.Uint32(handleBytes[4:8])
	if int(length) != len(handleBytes)-8 {
		t.Errorf("length mismatch: got %d, want %d", length, len(handleBytes)-8)
	}

	// Parse JSON
	var payload map[string]interface{}
	if err := json.Unmarshal(handleBytes[8:], &payload); err != nil {
		t.Fatalf("failed to parse key handle JSON: %v", err)
	}

	// Verify key fields
	if payload["k"] != kh.JSONPayload["k"] {
		t.Errorf("ios_key_id mismatch: got %v, want %v", payload["k"], kh.JSONPayload["k"])
	}
	if payload["d"] != kh.JSONPayload["d"] {
		t.Errorf("ios_device_id mismatch: got %v, want %v", payload["d"], kh.JSONPayload["d"])
	}
	if payload["a"] != kh.JSONPayload["a"] {
		t.Errorf("application mismatch: got %v, want %v", payload["a"], kh.JSONPayload["a"])
	}
}

// TestSSHVectorsFingerprint validates SSH fingerprint computation
func TestSSHVectorsFingerprint(t *testing.T) {
	vectors := loadSSHVectors(t)
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Compute fingerprint from the public key blob
	blob := mustDecodeSSHHex(t, pkf.BlobHex)
	hash := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])

	if fingerprint != pkf.FingerprintSHA256 {
		t.Errorf("fingerprint mismatch:\ngot:  %s\nwant: %s", fingerprint, pkf.FingerprintSHA256)
	}
}

// TestSSHVectorsPublicKeyBlob validates SSH public key blob format
func TestSSHVectorsPublicKeyBlob(t *testing.T) {
	vectors := loadSSHVectors(t)
	km := vectors.SSHVectors.KeyMaterial
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build the public key blob
	x := mustDecodeSSHHex(t, km.PublicKeyXHex)
	y := mustDecodeSSHHex(t, km.PublicKeyYHex)

	blob := buildSSHPublicKeyBlob(pkf.KeyType, pkf.CurveName, x, y, pkf.Application)
	blobHex := hex.EncodeToString(blob)

	if blobHex != pkf.BlobHex {
		t.Errorf("blob mismatch:\ngot:  %s\nwant: %s", blobHex, pkf.BlobHex)
	}
}

// TestSSHVectorsSignatureFormat validates raw signature format (r || s)
func TestSSHVectorsSignatureFormat(t *testing.T) {
	vectors := loadSSHVectors(t)

	for _, tc := range vectors.SSHVectors.SignatureCases {
		t.Run(tc.Description, func(t *testing.T) {
			// Verify raw signature is r || s concatenated
			sigR := mustDecodeSSHHex(t, tc.SignatureRHex)
			sigS := mustDecodeSSHHex(t, tc.SignatureSHex)
			expectedRaw := append(sigR, sigS...)
			rawSig := mustDecodeSSHHex(t, tc.RawSignatureHex)

			if hex.EncodeToString(rawSig) != hex.EncodeToString(expectedRaw) {
				t.Errorf("raw signature mismatch:\ngot:  %s\nwant: %s",
					hex.EncodeToString(rawSig), hex.EncodeToString(expectedRaw))
			}

			// Verify each component is 32 bytes (P-256)
			if len(sigR) != 32 {
				t.Errorf("signature R length: got %d, want 32", len(sigR))
			}
			if len(sigS) != 32 {
				t.Errorf("signature S length: got %d, want 32", len(sigS))
			}
		})
	}
}

// TestSSHVectorsAuthorizedKeysFormat validates authorized_keys line format
func TestSSHVectorsAuthorizedKeysFormat(t *testing.T) {
	vectors := loadSSHVectors(t)
	pkf := vectors.SSHVectors.PublicKeyFormat

	// Build authorized_keys line
	blob := mustDecodeSSHHex(t, pkf.BlobHex)
	authLine := pkf.KeyType + " " + base64.StdEncoding.EncodeToString(blob) + " test-key"

	if authLine != pkf.AuthorizedKeysLine {
		t.Errorf("authorized_keys line mismatch:\ngot:  %s\nwant: %s", authLine, pkf.AuthorizedKeysLine)
	}
}

// Helper function to build SSH public key blob
func buildSSHPublicKeyBlob(keyType, curveName string, x, y []byte, application string) []byte {
	result := make([]byte, 0, 256)

	// Key type string
	result = appendSSHString(result, []byte(keyType))

	// Curve name
	result = appendSSHString(result, []byte(curveName))

	// EC point (04 || X || Y)
	point := append([]byte{0x04}, x...)
	point = append(point, y...)
	result = appendSSHString(result, point)

	// Application
	result = appendSSHString(result, []byte(application))

	return result
}

func appendSSHString(b, s []byte) []byte {
	length := uint32(len(s))
	b = append(b, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	return append(b, s...)
}
