package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// loginCmd is a placeholder while the requester pairing flow against the new
// github.com/naughtbot/api/auth surface is being designed. The legacy
// `/api/v1/requester-sessions` + QR-code flow that the previous CLI shipped no
// longer exists in the regenerated auth API — the replacement requires a new
// pairing-based design (LinkStart/LinkCheck/LinkFinalize for phone-to-phone
// pairing, plus a CLI-specific pairing surface that auth does not yet
// expose). Re-enabling this command is tracked separately; see
// NaughtBot/cli#12 follow-ups.
//
// The `--logout` flag is preserved across the rewire because it is a
// local-only operation (clearing the active profile's user account /
// keys state) and does not depend on the legacy QR-code API. Users with
// existing profiles can therefore still log out and re-pair once the
// new login lands.
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with NaughtBot via QR code (or pass --logout to clear local credentials)",
	Long: "Authenticate with NaughtBot via QR code.\n\n" +
		"NOTE: the interactive QR-code login path is temporarily disabled " +
		"while the flow is being rewired against github.com/naughtbot/api/auth " +
		"pairing endpoints (see NaughtBot/cli#12 follow-up). The `--logout` " +
		"sub-mode below remains available because it does not require the " +
		"legacy auth surface.",
	RunE: runLogin,
}

var (
	loginLogoutFlag bool
	loginYesFlag    bool
)

func init() {
	loginCmd.Flags().BoolVar(&loginLogoutFlag, "logout", false, "Clear local credentials and enrolled keys for the active profile")
	loginCmd.Flags().BoolVarP(&loginYesFlag, "yes", "y", false, "Skip interactive confirmation (for --logout)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	if loginLogoutFlag {
		// Apply the root persistent --profile / NB_PROFILE override so
		// `nb --profile other login --logout` clears the requested
		// profile's state, not the global active profile.
		cfg := loadConfigWithProfile(profile)
		profileName := cfg.EffectiveProfile()

		if !loginYesFlag {
			fmt.Fprintf(cmd.ErrOrStderr(),
				"This will permanently clear all credentials and enrolled keys for profile %q. Continue? [y/N]: ",
				profileName)
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			line = strings.ToLower(strings.TrimSpace(line))
			if line != "y" && line != "yes" {
				fmt.Fprintln(cmd.OutOrStdout(), "Logout cancelled.")
				return nil
			}
		}

		if err := clearActiveProfileLoginState(cfg); err != nil {
			return fmt.Errorf("logout: failed to clear profile login state: %w", err)
		}
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("logout: failed to persist config: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(),
			"Local credentials and enrolled keys cleared for profile %q.\n", profileName)
		return nil
	}
	return errLoginNotImplemented
}

var errLoginNotImplemented = stubErr("login: not yet rewired to NaughtBot/api/auth pairing surface")

type stubErr string

func (e stubErr) Error() string { return string(e) }
