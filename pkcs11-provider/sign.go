package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;
typedef unsigned long CK_ULONG;
typedef CK_ULONG* CK_ULONG_PTR;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef void* CK_VOID_PTR;

// Return values
#define CKR_OK                              0x00000000
#define CKR_ARGUMENTS_BAD                   0x00000007
#define CKR_DATA_INVALID                    0x00000020
#define CKR_DATA_LEN_RANGE                  0x00000021
#define CKR_KEY_HANDLE_INVALID              0x00000060
#define CKR_KEY_TYPE_INCONSISTENT           0x00000063
#define CKR_MECHANISM_INVALID               0x00000070
#define CKR_OPERATION_ACTIVE                0x00000090
#define CKR_OPERATION_NOT_INITIALIZED       0x00000091
#define CKR_SESSION_HANDLE_INVALID          0x000000B3
#define CKR_BUFFER_TOO_SMALL                0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED        0x00000190
#define CKR_FUNCTION_FAILED                 0x00000006
#define CKR_USER_NOT_LOGGED_IN              0x00000101

// Mechanisms
#define CKM_ECDSA                           0x00001041
#define CKM_ECDSA_SHA256                    0x00001044

// Mechanism structure
typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM* CK_MECHANISM_PTR;
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/transport"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// signInit initializes a signing operation
func signInit(sessionHandle C.CK_SESSION_HANDLE, mechanism C.CK_MECHANISM_PTR, keyHandle C.CK_OBJECT_HANDLE) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx != nil {
		return C.CKR_OPERATION_ACTIVE
	}

	if mechanism == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// Validate mechanism. The e2ee-payloads `pkcs11_sign` schema only
	// expresses the hash-then-sign path, so we reject `CKM_ECDSA`
	// (sign-pre-hashed-digest) at SignInit rather than letting callers
	// initialise and then fail at C_Sign / C_SignFinal time. Callers
	// should use `CKM_ECDSA_SHA256` (sign-after-hashing) instead.
	mech := mechanism.mechanism
	if mech == C.CKM_ECDSA {
		logError("Unsupported mechanism CKM_ECDSA: the e2ee-payloads pkcs11_sign schema only supports CKM_ECDSA_SHA256 (sign-after-hashing); the approver hashes raw_data with SHA-256 itself")
		return C.CKR_MECHANISM_INVALID
	}
	if mech != C.CKM_ECDSA_SHA256 {
		logError("Unsupported mechanism: %s", ckmToString(mech))
		return C.CKR_MECHANISM_INVALID
	}

	// Get the key
	key := sess.getKey(keyHandle)
	if key == nil {
		return C.CKR_KEY_HANDLE_INVALID
	}

	// Create signing context
	sess.signCtx = &signContext{
		mechanism: mech,
		keyHandle: keyHandle,
		key:       key.metadata,
		data:      nil,
	}

	logDebug("SignInit: mechanism=%s key=%s", ckmToString(mech), key.metadata.Label)
	return C.CKR_OK
}

// sign performs the signing operation
func sign(sessionHandle C.CK_SESSION_HANDLE, data C.CK_BYTE_PTR, dataLen C.CK_ULONG, signature C.CK_BYTE_PTR, signatureLen C.CK_ULONG_PTR) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx == nil {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	if signatureLen == nil {
		return C.CKR_ARGUMENTS_BAD
	}

	// If signature is nil, just return the required length
	if signature == nil {
		*signatureLen = C.CK_ULONG(p256SignatureLen)
		return C.CKR_OK
	}

	// Check buffer size
	if *signatureLen < C.CK_ULONG(p256SignatureLen) {
		*signatureLen = C.CK_ULONG(p256SignatureLen)
		return C.CKR_BUFFER_TOO_SMALL
	}

	// Get the data to sign
	var dataBytes []byte
	if dataLen > 0 && data != nil {
		dataBytes = C.GoBytes(unsafe.Pointer(data), C.int(dataLen))
	}

	// If there's accumulated data from SignUpdate, use that
	if len(sess.signCtx.data) > 0 {
		dataBytes = append(sess.signCtx.data, dataBytes...)
	}

	// The e2ee-payloads `MailboxPkcs11SignRequestPayloadV1.raw_data` contract
	// is "raw data to sign (preimage); approver computes SHA-256 and signs the
	// resulting digest", so we send the preimage as-is. CKM_ECDSA
	// (sign-pre-hashed-digest) callers are already rejected at SignInit.
	preimage := dataBytes
	sig, err := performSigning(sess.cfg, sess.signCtx.key, preimage, ckmToString(sess.signCtx.mechanism))
	if err != nil {
		logError("Signing failed: %v", err)
		sess.signCtx = nil
		return C.CKR_FUNCTION_FAILED
	}

	// Copy signature to output buffer
	for i := 0; i < len(sig) && i < p256SignatureLen; i++ {
		*(*C.CK_BYTE)(unsafe.Pointer(uintptr(unsafe.Pointer(signature)) + uintptr(i))) = C.CK_BYTE(sig[i])
	}
	*signatureLen = C.CK_ULONG(len(sig))

	// Clear signing context
	sess.signCtx = nil

	logDebug("Sign: success, %d bytes", len(sig))
	return C.CKR_OK
}

// signUpdate accumulates data for multi-part signing
func signUpdate(sessionHandle C.CK_SESSION_HANDLE, data C.CK_BYTE_PTR, dataLen C.CK_ULONG) C.CK_RV {
	sess, rv := sessions.getSession(sessionHandle)
	if rv != C.CKR_OK {
		return rv
	}

	if sess.signCtx == nil {
		return C.CKR_OPERATION_NOT_INITIALIZED
	}

	if dataLen > 0 && data != nil {
		sess.signCtx.data = append(sess.signCtx.data, C.GoBytes(unsafe.Pointer(data), C.int(dataLen))...)
	}

	logDebug("SignUpdate: accumulated %d bytes", len(sess.signCtx.data))
	return C.CKR_OK
}

// signFinal completes multi-part signing
func signFinal(sessionHandle C.CK_SESSION_HANDLE, signature C.CK_BYTE_PTR, signatureLen C.CK_ULONG_PTR) C.CK_RV {
	// SignFinal is equivalent to Sign with no additional data
	return sign(sessionHandle, nil, 0, signature, signatureLen)
}

// performSigning sends a signing request via the mailbox transport and
// returns the signature bytes from the decrypted response. The preimage is
// the raw data to sign; the approver computes SHA-256 over it per the
// e2ee-payloads `pkcs11_sign` contract.
func performSigning(cfg *config.Config, key *config.KeyMetadata, preimage []byte, mechanism string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultSigningTimeout)
	defer cancel()

	// Build display + payload using generated e2ee-payloads types.
	// DeviceKeyId is the on-device key handle returned during enrollment
	// (stored as IOSKeyID); key.Hex() is the public-key bytes used for
	// CKA_ID and display fields only.
	display, sourceInfo := collectSigningDisplay(key, mechanism, len(preimage))
	payload := &payloads.MailboxPkcs11SignRequestPayloadV1{
		DeviceKeyId: key.IOSKeyID,
		Display:     display,
		RawData:     preimage,
		SourceInfo:  sourceInfo,
	}

	fmt.Fprintf(os.Stderr, "Waiting for approval on iOS device...\n")

	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey("", key.Hex()).
		WithTimeout(config.DefaultSigningTimeout).
		SendAndDecrypt(ctx, payload)
	if err != nil {
		return nil, err
	}

	var signResponse client.SigningResponse
	if err := json.Unmarshal(decrypted, &signResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	if !signResponse.IsSuccess() {
		return nil, signResponse.Error()
	}
	signature := signResponse.GetSignature()
	if len(signature) != p256SignatureLen {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", p256SignatureLen, len(signature))
	}
	return signature, nil
}
