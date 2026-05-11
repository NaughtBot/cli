package main

import "github.com/spf13/cobra"

// loginCmd is a placeholder while the requester pairing flow against the new
// github.com/naughtbot/api/auth surface is being designed. The legacy
// `/api/v1/requester-sessions` + QR-code flow that the previous CLI shipped no
// longer exists in the regenerated auth API — the replacement requires a new
// pairing-based design (LinkStart/LinkCheck/LinkFinalize for phone-to-phone
// pairing, plus a CLI-specific pairing surface that auth does not yet
// expose). Re-enabling this command is tracked separately; see
// NaughtBot/cli#12 follow-ups.
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with NaughtBot via QR code",
	Long: "Authenticate with NaughtBot via QR code.\n\n" +
		"NOTE: this command is temporarily disabled while the QR-code login " +
		"flow is being rewired against github.com/naughtbot/api/auth pairing " +
		"endpoints (see NaughtBot/cli#12 follow-up).",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errLoginNotImplemented
	},
}

var errLoginNotImplemented = stubErr("login: not yet rewired to NaughtBot/api/auth pairing surface")

type stubErr string

func (e stubErr) Error() string { return string(e) }
