package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/naughtbot/cli/internal/shared/config"
)

func TestProfileCommand_Registered(t *testing.T) {
	found := false
	for _, sub := range rootCmd.Commands() {
		if sub.Use == "profile" {
			found = true
			break
		}
	}
	assert.True(t, found, "profile command should be registered as a subcommand of root")
}

func TestProfileCommand_Subcommands(t *testing.T) {
	expectedSubcommands := []string{
		"list",
		"use <name>",
		"show [name]",
		"rename <old> <new>",
		"delete <name>",
	}

	for _, use := range expectedSubcommands {
		t.Run(use, func(t *testing.T) {
			found := false
			for _, sub := range profileCmd.Commands() {
				if sub.Use == use {
					found = true
					break
				}
			}
			assert.True(t, found, "profile should have %q subcommand", use)
		})
	}
}

func TestProfileCommand_SubcommandCount(t *testing.T) {
	assert.Len(t, profileCmd.Commands(), 5, "profile should have exactly 5 subcommands")
}

func TestProfileListCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileListCmd.Aliases, "ls", "profile list should have 'ls' alias")
}

func TestProfileUseCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileUseCmd.Aliases, "switch", "profile use should have 'switch' alias")
}

func TestProfileRenameCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileRenameCmd.Aliases, "mv", "profile rename should have 'mv' alias")
}

func TestProfileDeleteCommand_Aliases(t *testing.T) {
	assert.Contains(t, profileDeleteCmd.Aliases, "rm", "profile delete should have 'rm' alias")
}

func TestProfileUseCommand_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, profileUseCmd.Args, "profile use should have args validation")
}

func TestProfileRenameCommand_RequiresTwoArgs(t *testing.T) {
	assert.NotNil(t, profileRenameCmd.Args, "profile rename should have args validation")
}

func TestProfileDeleteCommand_RequiresOneArg(t *testing.T) {
	assert.NotNil(t, profileDeleteCmd.Args, "profile delete should have args validation")
}

func TestProfileDeleteCommand_YesFlag(t *testing.T) {
	f := profileDeleteCmd.Flags().Lookup("yes")
	require.NotNil(t, f, "profile delete should have a --yes flag")
	assert.Equal(t, "false", f.DefValue)
}

func TestTruncateFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		// 40 chars, last 16 = "34567890ABCDEF12"
		{"long fingerprint", "ABCDEF1234567890ABCDEF1234567890ABCDEF12", "...34567890ABCDEF12"},
		{"exactly 16 chars", "1234567890123456", "1234567890123456"},
		{"short fingerprint", "ABCD", "ABCD"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateFingerprint(tt.input)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestConfirmAction(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		want         bool
		wantCanceled bool
	}{
		{name: "yes", input: "yes\n", want: true},
		{name: "short yes", input: "y\n", want: true},
		{name: "no", input: "no\n", want: false, wantCanceled: true},
		{name: "eof", input: "", want: false, wantCanceled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			got := confirmAction(bytes.NewBufferString(tt.input), &output, "Delete profile? [y/N] ")
			assert.Equal(t, tt.want, got)
			assert.Contains(t, output.String(), "Delete profile? [y/N] ")
			if tt.wantCanceled {
				assert.Contains(t, output.String(), "Cancelled.")
			} else {
				assert.NotContains(t, output.String(), "Cancelled.")
			}
		})
	}
}

func TestFormatProfileListEntry_LoggedInProfile(t *testing.T) {
	cfg := &config.Config{
		ActiveProfile: "default",
		Profiles: map[string]*config.ProfileConfig{
			"default": {
				UserAccount: &config.UserAccount{
					SASVerified: true,
					Devices: []config.UserDevice{
						{DeviceName: "Secure Enclave iPhone"},
					},
				},
			},
		},
	}

	assert.Equal(t, "  default (active) [logged in]", formatProfileListEntry(cfg, "default"))
}

func TestFormatProfileListEntry_InvalidProfile(t *testing.T) {
	cfg := &config.Config{
		Profiles: map[string]*config.ProfileConfig{
			"broken": nil,
		},
	}

	assert.Equal(t, "  broken [error: invalid profile data]", formatProfileListEntry(cfg, "broken"))
}
