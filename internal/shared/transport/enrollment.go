package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/naughtbot/cli/internal/shared/config"
	payloads "github.com/naughtbot/e2ee-payloads/go"
)

// SendAndDecryptEnrollment sends an enrollment request and decrypts the response.
// Enrollment flows skip BBS+ attestation verification by design — they rely on
// the key-level attestation in MailboxEnrollResponseApprovedV1.Attestation, not
// the per-request Longfellow approval proof — and so MUST NOT block on the
// `/approval-proofs/config` fetch (which is stubbed during the
// mailbox-DPoP rewire window).
func SendAndDecryptEnrollment(ctx context.Context, cfg *config.Config, payload any, timeout time.Duration) ([]byte, error) {
	result, err := NewRequestBuilder(cfg).
		WithSkipApprovalProofVerifier().
		WithTimeout(timeout).
		WithExpiration(int(timeout.Seconds())).
		WithTimestamp(time.Now().UnixMilli()).
		Send(ctx, payload)
	if err != nil {
		return nil, err
	}

	switch result.Response.Status {
	case "responded":
		return result.DecryptWithoutAttestation()
	case "expired":
		return nil, fmt.Errorf("enrollment request expired")
	default:
		return nil, fmt.Errorf("unexpected status: %s", result.Response.Status)
	}
}

// ParseEnrollResponse parses and validates a common enrollment response payload.
//
// The wire shape is the e2ee-payloads MailboxEnrollResponsePayloadV1 union,
// discriminated on the `status` field (`approved` or `rejected`). On the
// rejected branch this returns a descriptive error built from `error_code`
// and `error_message`; on the approved branch this returns the parsed
// MailboxEnrollResponseApprovedV1 struct so callers can read the freshly
// minted key material.
func ParseEnrollResponse(decrypted []byte) (*payloads.MailboxEnrollResponseApprovedV1, error) {
	// Peek at the discriminator so we can route into the correct branch.
	var disc struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(decrypted, &disc); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	switch disc.Status {
	case string(payloads.Approved):
		var approved payloads.MailboxEnrollResponseApprovedV1
		if err := json.Unmarshal(decrypted, &approved); err != nil {
			return nil, fmt.Errorf("failed to parse approved enrollment response: %w", err)
		}
		return &approved, nil
	case string(payloads.Rejected):
		var rejected payloads.MailboxEnrollResponseRejectedV1
		if err := json.Unmarshal(decrypted, &rejected); err != nil {
			return nil, fmt.Errorf("failed to parse rejected enrollment response: %w", err)
		}
		errMsg := "unknown error"
		if rejected.ErrorMessage != nil {
			errMsg = *rejected.ErrorMessage
		}
		return nil, fmt.Errorf("enrollment failed: %s (code %d)", errMsg, rejected.ErrorCode)
	default:
		return nil, fmt.Errorf("enrollment response missing or unknown status: %q", disc.Status)
	}
}
