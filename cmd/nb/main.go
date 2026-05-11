// oobsign is a unified CLI for OOBSign desktop operations.
// It provides subcommands for login, GPG signing, and more.
//
// Usage:
//
//	oobsign login   # OAuth login and SAS verification
//	oobsign gpg     # GPG-compatible signing
//	oobsign version # Show version
//	oobsign help    # Show help
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/config"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/log"
	"github.com/clarifiedlabs/ackagent-monorepo/oobsign-cli/internal/shared/version"
)

// Global flags accessible to all subcommands via persistent flags
var (
	cfgDir   string
	profile  string
	logLevel string
)

var rootCmd = &cobra.Command{
	Use:     "oobsign",
	Short:   "OOBSign CLI for hardware-backed signing",
	Version: version.Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Get values from Viper (merges flag > env > default)
		cfgDir = viper.GetString("config-dir")
		profile = viper.GetString("profile")
		logLevel = viper.GetString("log-level")

		// Apply config dir override first (before any config loading)
		if cfgDir != "" {
			config.SetConfigDir(cfgDir)
		}

		// Apply log level from flag/env (overrides InitFromEnv defaults)
		if logLevel != "" {
			log.SetLevelFromString(logLevel)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Default action: show help
		cmd.Help()
	},
}

func init() {
	rootCmd.SetVersionTemplate("{{.Version}}\n")

	// Persistent flags - available to ALL subcommands
	rootCmd.PersistentFlags().StringVarP(&cfgDir, "config-dir", "c", "", "Use alternative config directory")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "Use specified profile (overrides active)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "Set log level: debug, info, warn, error")

	// Bind flags to Viper with OOBSIGN_ prefix for env vars
	// This enables: OOBSIGN_CONFIG_DIR, OOBSIGN_PROFILE, OOBSIGN_LOG_LEVEL
	viper.SetEnvPrefix("OOBSIGN")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_")) // config-dir -> CONFIG_DIR
	viper.AutomaticEnv()

	// Bind each persistent flag so Viper merges flag > env > default
	bindPersistentFlag := func(key string) {
		flag := rootCmd.PersistentFlags().Lookup(key)
		if flag == nil {
			die("Error binding persistent flag %q to Viper: flag not found", key)
		}
		if err := viper.BindPFlag(key, flag); err != nil {
			die("Error binding persistent flag %q to Viper: %v", key, err)
		}
	}

	bindPersistentFlag("config-dir")
	bindPersistentFlag("profile")
	bindPersistentFlag("log-level")

	// Add subcommands
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(gpgCmd)
	rootCmd.AddCommand(ageCmd)
	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(profileCmd)
}

func main() {
	// Initialize log level from environment
	log.InitFromEnv()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// die prints an error message to stderr and exits with code 1.
func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// loadConfigOrDie loads the config file and applies profile override if set.
func loadConfigOrDie() *config.Config {
	return loadConfigWithProfile("")
}

// loadConfigWithProfile loads config and applies the given profile override.
// If profile is empty, it uses the active profile.
func loadConfigWithProfile(profileOverride string) *config.Config {
	cfg, err := config.Load()
	if err != nil {
		die("Error loading config: %v", err)
	}

	if profileOverride != "" {
		if err := cfg.SetWorkingProfile(profileOverride); err != nil {
			die("Error: profile %q not found", profileOverride)
		}
	}

	return cfg
}
