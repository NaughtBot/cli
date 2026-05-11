package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/naughtbot/cli/crypto"
	"github.com/naughtbot/cli/internal/shared/client"
	"github.com/naughtbot/cli/internal/shared/config"
	"github.com/naughtbot/cli/internal/shared/transport"
	"github.com/naughtbot/cli/internal/shared/util"
	"github.com/google/uuid"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

const (
	sshAlgECDSA   = 0
	sshAlgEd25519 = 1

	sshErrGeneral        = -1
	sshErrUnsupported    = -2
	sshErrDeviceNotFound = -4
)

type enrollResult struct {
	publicKey       []byte
	keyHandle       []byte
	signature       []byte
	attestationCert []byte
}

type signResult struct {
	signature []byte
	counter   uint32
}

func executeEnroll(alg uint32, challengeBytes []byte, app string, flags uint8) (*enrollResult, int) {
	logDebug("executeEnroll: alg=%d app=%s challenge_len=%d flags=0x%02x", alg, app, len(challengeBytes), flags)
	if alg != sshAlgECDSA && alg != sshAlgEd25519 {
		logError("unsupported algorithm: %d", alg)
		return nil, sshErrUnsupported
	}

	cfg, err := config.Load()
	if err != nil {
		logError("failed to load config: %v", err)
		return nil, sshErrGeneral
	}
	if !cfg.IsLoggedIn() {
		logError("not logged in - run 'nb login' first")
		return nil, sshErrDeviceNotFound
	}
	logDebug("executeEnroll: config loaded active_profile=%s devices=%d",
		cfg.ActiveProfile, len(cfg.UserAccount().Devices))

	// Pre-generate request ID so it can be passed through to the transport
	// as clientRequestId/AAD.
	requestID := uuid.New()
	processInfo := getProcessInfo()

	algorithm := config.AlgorithmP256
	algDisplayName := "ECDSA P-256"
	if alg == sshAlgEd25519 {
		algorithm = config.AlgorithmEd25519
		algDisplayName = "Ed25519"
	}
	fields := []payloads.DisplayField{
		{Label: "Algorithm", Value: algDisplayName},
		{Label: "Application", Value: app, Monospace: util.Ptr(true)},
	}

	icon := "key.fill"
	historyTitle := "SSH Key Enrolled"
	subtitle := "SSH key enrollment"
	label := app
	req := payloads.MailboxEnrollRequestPayloadV1{
		Purpose:    payloads.Ssh,
		Label:      &label,
		Algorithm:  &algorithm,
		SourceInfo: processInfo.ToSourceInfo(),
		Display: &payloads.DisplaySchema{
			Title:        "Enroll SSH Key?",
			HistoryTitle: &historyTitle,
			Subtitle:     &subtitle,
			Icon:         &icon,
			Fields:       fields,
		},
	}

	ctx := context.Background()
	logDebug("sending enrollment request to backend")

	// Enrollment relies on key-level attestation (the Attestation field
	// on the approved-enroll response), not BBS+ anonymous attestation,
	// so we use DecryptWithoutAttestation via RequestResult.
	result, err := transport.NewRequestBuilder(cfg).
		WithClientRequestID(requestID).
		WithTimeout(config.DefaultSSHTimeout).
		WithExpiration(300).
		Send(ctx, req)
	if err != nil {
		logError("enrollment request failed: %v", err)
		return nil, sshErrGeneral
	}
	switch result.Response.Status {
	case "expired":
		logError("enrollment request expired")
		return nil, sshErrGeneral
	case "responded":
		// fall through
	default:
		logError("enrollment unexpected status: %s", result.Response.Status)
		return nil, sshErrGeneral
	}
	decrypted, err := result.DecryptWithoutAttestation()
	if err != nil {
		logError("failed to decrypt response: %v", err)
		return nil, sshErrGeneral
	}

	enrollResp, err := transport.ParseEnrollResponse(decrypted)
	if err != nil {
		logError("enrollment response: %v", err)
		return nil, sshErrGeneral
	}

	iosKeyID := enrollResp.DeviceKeyId
	if iosKeyID == "" {
		logError("missing iOS key ID in response")
		return nil, sshErrGeneral
	}
	if enrollResp.PublicKeyHex == "" {
		logError("missing public key in response")
		return nil, sshErrGeneral
	}
	publicKey, err := hex.DecodeString(enrollResp.PublicKeyHex)
	if err != nil {
		logError("invalid hex public key: %v", err)
		return nil, sshErrGeneral
	}
	logDebug("executeEnroll: approved ios_key_id=%s pub_len=%d request_id=%s",
		iosKeyID, len(publicKey), requestID.String())

	keyHandle := buildKeyHandle(iosKeyID, cfg.UserAccount().UserID, app)

	cfg.AddKey(config.KeyMetadata{
		IOSKeyID:  iosKeyID,
		Label:     app,
		PublicKey: publicKey,
		Algorithm: algorithm,
		Purpose:   config.KeyPurposeSSH,
		CreatedAt: time.Now(),
	})
	cfg.Save()

	sshPublicKey := publicKey
	if alg == sshAlgECDSA && len(publicKey) == int(crypto.PublicKeySize) {
		decompressed, err := crypto.DecompressPublicKey(publicKey)
		if err != nil {
			logError("failed to decompress public key: %v", err)
			return nil, sshErrGeneral
		}
		sshPublicKey = decompressed
	}

	var signature []byte
	if enrollResp.SubkeySignature != nil {
		signature = *enrollResp.SubkeySignature
	}

	var attestationCert []byte
	if enrollResp.Attestation != nil {
		att, err := json.Marshal(enrollResp.Attestation)
		if err == nil {
			attestationCert = att
		}
	}

	return &enrollResult{
		publicKey:       sshPublicKey,
		keyHandle:       keyHandle,
		signature:       signature,
		attestationCert: attestationCert,
	}, 0
}

func executeSign(alg uint32, dataBytes []byte, app string, keyHandleBytes []byte, flags uint8) (*signResult, int) {
	logDebug("executeSign: alg=%d app=%s data_len=%d key_handle_len=%d flags=0x%02x",
		alg, app, len(dataBytes), len(keyHandleBytes), flags)
	if alg != sshAlgECDSA && alg != sshAlgEd25519 {
		logError("unsupported algorithm: %d", alg)
		return nil, sshErrUnsupported
	}

	keyHandleData, err := parseKeyHandle(keyHandleBytes)
	if err != nil {
		logError("invalid key handle: %v", err)
		return nil, sshErrGeneral
	}
	logDebug("executeSign: parsed key handle ios_key_id=%s app=%s",
		keyHandleData.IOSKeyID, keyHandleData.Application)

	cfg, err := config.Load()
	if err != nil {
		logError("failed to load config: %v", err)
		return nil, sshErrGeneral
	}

	_, profileName, err := cfg.FindKeyAcrossProfiles(keyHandleData.IOSKeyID)
	if err == nil {
		if err := cfg.SetWorkingProfile(profileName); err != nil {
			logDebug("failed to set profile '%s': %v", profileName, err)
		} else {
			logDebug("using profile '%s' for key %s", profileName, keyHandleData.IOSKeyID)
		}
	} else {
		logDebug("key %s not found in any profile, using active profile", keyHandleData.IOSKeyID)
	}

	logDebug("config loaded: issuer=%s, relay=%s", cfg.IssuerURL(), cfg.RelayURL())
	if !cfg.IsLoggedIn() {
		logError("not logged in")
		return nil, sshErrDeviceNotFound
	}

	// Pre-generate request ID so the payload's wire-level clientRequestId
	// stays in sync with the AEAD associated data.
	requestID := uuid.New()
	processInfo := getProcessInfo()
	logDebug("ssh command: %s", processInfo.Command)
	logDebug("process chain: %v", processInfo.ProcessChain)

	// Look up the signing key for the device key id in the handle.
	signingPublicKey := ""
	for _, k := range cfg.KeysForPurpose(config.KeyPurposeSSH) {
		if k.IOSKeyID == keyHandleData.IOSKeyID {
			signingPublicKey = k.Hex()
			break
		}
	}

	fields := []payloads.DisplayField{
		{Label: "Application", Value: app, Monospace: util.Ptr(true)},
	}

	icon := "terminal"
	historyTitle := "SSH Signature"
	flags32 := int32(flags)
	application := app
	req := payloads.MailboxSshAuthRequestPayloadV1{
		Application: &application,
		DeviceKeyId: keyHandleData.IOSKeyID,
		RawData:     dataBytes,
		Flags:       &flags32,
		SourceInfo:  processInfo.ToSourceInfo(),
		Display: &payloads.DisplaySchema{
			Title:        "Authorize SSH?",
			HistoryTitle: &historyTitle,
			Icon:         &icon,
			Fields:       fields,
		},
	}

	ctx := context.Background()
	logDebug("sending sign request to backend")

	// SSH signing uses full BBS+ anonymous attestation verification.
	decrypted, err := transport.NewRequestBuilder(cfg).
		WithKey(keyHandleData.IOSKeyID, signingPublicKey).
		WithClientRequestID(requestID).
		WithTimeout(config.DefaultSSHTimeout).
		WithExpiration(60).
		SendAndDecrypt(ctx, req)
	if err != nil {
		logError("sign request failed: %v", err)
		return nil, sshErrGeneral
	}

	var signResp client.SigningResponse
	if err := json.Unmarshal(decrypted, &signResp); err != nil {
		logError("failed to parse response: %v", err)
		return nil, sshErrGeneral
	}
	if !signResp.IsSuccess() {
		logError("signing rejected: %v", signResp.Error())
		return nil, sshErrGeneral
	}

	signature := signResp.GetSignature()
	if len(signature) != 64 {
		logError("invalid signature length: %d", len(signature))
		return nil, sshErrGeneral
	}
	logDebug("executeSign: signed successfully ios_key_id=%s request_id=%s sig_len=%d",
		keyHandleData.IOSKeyID, requestID.String(), len(signature))

	// The new e2ee-payloads schema does not carry a counter field; emit 0.
	return &signResult{signature: signature, counter: 0}, 0
}
