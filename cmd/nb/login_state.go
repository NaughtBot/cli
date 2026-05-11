package main

import (
	"errors"

	"github.com/naughtbot/cli/internal/shared/config"
)

// clearActiveProfileLoginState resets the per-profile login state on the
// active profile. It is used both during normal logout and as a rollback when
// a login attempt fails partway through.
//
// Lives in an ungated file so it is available in default builds even while
// the broader login command is gated behind `legacy_api` for WS3.2.
func clearActiveProfileLoginState(cfg *config.Config) error {
	profile, err := cfg.GetActiveProfile()
	if err != nil {
		return err
	}

	profile.ClearUserAccount()
	profile.Keys = nil
	return nil
}

// validatedApproverDeviceCount returns the number of approver devices that
// were persisted on the active profile, requiring at least one to confirm
// the login succeeded end-to-end.
func validatedApproverDeviceCount(cfg *config.Config) (int, error) {
	account := cfg.UserAccount()
	if account == nil {
		return 0, errors.New("login failed: no user account state was created")
	}

	deviceCount := len(account.Devices)
	if deviceCount == 0 {
		return 0, errors.New("login failed: no approver devices passed attestation verification")
	}

	return deviceCount, nil
}
