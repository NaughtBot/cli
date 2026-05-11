// Package crypto: attestation policy types used by device sync and
// platform-specific attestation verification (iOS App Attest, Android Key
// Attestation). The BBS+ anonymous-attestation path that previously owned
// these lived in bbs_verify.go, which is now gone — these types remain as
// the lingua franca between the sync layer and the platform verifiers.
package crypto

import (
	"errors"
	"fmt"
)

// ErrAttestationPolicyViolation indicates the attestation type does not meet the required security policy.
var ErrAttestationPolicyViolation = errors.New("attestation policy violation: hardware attestation required")

// AttestationPolicy defines the minimum attestation security level required
// for signing operations.
type AttestationPolicy string

const (
	// AttestationPolicyAny accepts both hardware-backed and software attestation types.
	AttestationPolicyAny AttestationPolicy = "any"
	// AttestationPolicyHardware rejects software-only attestation and requires
	// a hardware-backed attestation type (Secure Enclave, TEE, or StrongBox).
	AttestationPolicyHardware AttestationPolicy = "hardware"
)

// AttestationSecurityType represents the unified security type across platforms.
type AttestationSecurityType string

const (
	AttestationIOSSecureEnclave AttestationSecurityType = "ios_secure_enclave"
	AttestationAndroidTEE       AttestationSecurityType = "android_tee"
	AttestationAndroidStrongBox AttestationSecurityType = "android_strongbox"
	AttestationSoftware         AttestationSecurityType = "software"
)

// IsHardwareBacked reports whether the attestation type is considered
// hardware-backed for policy purposes.
func (t AttestationSecurityType) IsHardwareBacked() bool {
	switch t {
	case AttestationIOSSecureEnclave, AttestationAndroidTEE, AttestationAndroidStrongBox:
		return true
	default:
		return false
	}
}

// CheckAttestationPolicy validates that the given attestation type satisfies the
// required policy. Returns nil if the policy is met, or ErrAttestationPolicyViolation
// otherwise.
func CheckAttestationPolicy(policy AttestationPolicy, attestationType string) error {
	switch policy {
	case AttestationPolicyAny:
		return nil
	case AttestationPolicyHardware:
		if !AttestationSecurityType(attestationType).IsHardwareBacked() {
			return fmt.Errorf("%w: got %q", ErrAttestationPolicyViolation, attestationType)
		}
		return nil
	default:
		return fmt.Errorf("unknown attestation policy: %q", policy)
	}
}
