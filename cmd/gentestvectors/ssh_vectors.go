package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func generateSSHVectors(privateKey *ecdsa.PrivateKey) SSHVectors {
	pubKeyX := padTo32(privateKey.X.Bytes())
	pubKeyY := padTo32(privateKey.Y.Bytes())

	keyType := "sk-ecdsa-sha2-nistp256@openssh.com"
	curveName := "nistp256"
	application := "ssh:"

	blob := buildSSHPublicKeyBlob(keyType, curveName, pubKeyX, pubKeyY, application)

	hash := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])

	authKeysLine := keyType + " " + base64.StdEncoding.EncodeToString(blob) + " test-key"

	keyHandleJSON := map[string]interface{}{
		"v": 1,
		"k": "test-ios-key-id",
		"d": "test-device-id",
		"a": application,
		"t": int64(1700000000),
	}
	keyHandleBytes := buildKeyHandle(keyHandleJSON)

	dataToSign := mustDecodeHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	r, s := signDeterministic(privateKey, dataToSign)
	rBytes := padTo32(r.Bytes())
	sBytes := padTo32(s.Bytes())

	return SSHVectors{
		Description: "SSH SK-ECDSA P-256 test vectors for OpenSSH security key provider",
		KeyMaterial: SSHKeyMaterial{
			Description:    "P-256 ECDSA key pair (same as GPG for consistency)",
			PrivateKeyDHex: hex.EncodeToString(privateKey.D.Bytes()),
			PublicKeyXHex:  hex.EncodeToString(pubKeyX),
			PublicKeyYHex:  hex.EncodeToString(pubKeyY),
		},
		PublicKeyFormat: SSHPublicKeyFormat{
			KeyType:            keyType,
			CurveName:          curveName,
			Application:        application,
			BlobHex:            hex.EncodeToString(blob),
			FingerprintSHA256:  fingerprint,
			AuthorizedKeysLine: authKeysLine,
		},
		KeyHandle: SSHKeyHandle{
			MagicHex:          hex.EncodeToString(keyHandleBytes[:4]),
			JSONPayload:       keyHandleJSON,
			CompleteHandleHex: hex.EncodeToString(keyHandleBytes),
		},
		SignatureCases: []SSHSignatureCase{
			{
				Description:     "SSH authentication (signing SHA256 hash)",
				DataToSignHex:   hex.EncodeToString(dataToSign),
				SignatureRHex:   hex.EncodeToString(rBytes),
				SignatureSHex:   hex.EncodeToString(sBytes),
				RawSignatureHex: hex.EncodeToString(append(rBytes, sBytes...)),
			},
		},
	}
}

func buildSSHPublicKeyBlob(keyType, curveName string, x, y []byte, application string) []byte {
	result := make([]byte, 0, 256)

	result = appendSSHString(result, []byte(keyType))
	result = appendSSHString(result, []byte(curveName))

	point := append([]byte{0x04}, x...)
	point = append(point, y...)
	result = appendSSHString(result, point)

	result = appendSSHString(result, []byte(application))

	return result
}

func buildKeyHandle(payload map[string]interface{}) []byte {
	jsonBytes := mustMarshalJSON(payload)

	magic := uint32(0x41505052)
	length := uint32(len(jsonBytes))

	result := make([]byte, 8+len(jsonBytes))
	binary.LittleEndian.PutUint32(result[0:4], magic)
	binary.LittleEndian.PutUint32(result[4:8], length)
	copy(result[8:], jsonBytes)

	return result
}

func mustMarshalJSON(v any) []byte {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal ssh vector payload: %v", err))
	}
	return jsonBytes
}
