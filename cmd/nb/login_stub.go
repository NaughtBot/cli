//go:build !legacy_api

package main

import "github.com/spf13/cobra"

// loginCmd is a stub command while WS3.3 reworks the QR-code requester
// session flow against the new NaughtBot/api/auth pairing surface. The
// implementation lives in login.go behind the `legacy_api` build tag.
//
// TODO(WS3.3): replace this stub with the rewired login flow.
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with NaughtBot via QR code",
	Long: "Authenticate with NaughtBot via QR code.\n\n" +
		"NOTE: this command is temporarily disabled while the CLI rebrand " +
		"is in progress (see NaughtBot/cli#3, WS3.3). It will be re-enabled " +
		"once the login flow is rewired against github.com/naughtbot/api/auth.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errLoginNotImplemented
	},
}

var errLoginNotImplemented = stubErr("login: not yet rewired to NaughtBot/api/auth (WS3.3)")

type stubErr string

func (e stubErr) Error() string { return string(e) }
