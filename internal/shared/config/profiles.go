package config

import (
	"fmt"
	"os"
	"sort"
)

// Profile Management Methods

// SetWorkingProfile sets the profile to use for operations (overrides active)
// This is typically set via --profile flag or NB_PROFILE env var
func (c *Config) SetWorkingProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	cfgLog.Debug("using profile override: %s (config file active: %s)", name, c.ActiveProfile)
	c.workingProfile = name
	return nil
}

// EffectiveProfile returns the profile name that should be used for operations
// Returns workingProfile if set, otherwise ActiveProfile
func (c *Config) EffectiveProfile() string {
	if c.workingProfile != "" {
		return c.workingProfile
	}
	return c.ActiveProfile
}

// ListProfiles returns all profile names sorted alphabetically
func (c *Config) ListProfiles() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetProfile returns the specified profile, or the active profile if name is empty
func (c *Config) GetProfile(name string) (*ProfileConfig, error) {
	if name == "" {
		name = c.ActiveProfile
	}
	if name == "" {
		return nil, ErrNoActiveProfile
	}
	profile, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	return profile, nil
}

// GetActiveProfile returns the effective profile (working profile if set, otherwise active)
func (c *Config) GetActiveProfile() (*ProfileConfig, error) {
	return c.GetProfile(c.EffectiveProfile())
}

// SetActiveProfile switches the active profile
func (c *Config) SetActiveProfile(name string) error {
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	c.ActiveProfile = name
	return nil
}

// CreateProfile creates a new profile with the given name
func (c *Config) CreateProfile(name, relayURL, issuerURL string) error {
	if err := ValidateProfileName(name); err != nil {
		return err
	}
	if _, ok := c.Profiles[name]; ok {
		return fmt.Errorf("%w: %s", ErrProfileExists, name)
	}
	c.Profiles[name] = &ProfileConfig{
		RelayURL:  relayURL,
		IssuerURL: issuerURL,
		Keys:      []KeyMetadata{},
	}
	return nil
}

// DeleteProfile removes a profile, its file, and its keyring credentials
func (c *Config) DeleteProfile(name string) error {
	profile, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, name)
	}
	if len(c.Profiles) <= 1 {
		return ErrCannotDeleteLast
	}

	// Clean up keyring entries
	if profile.UserAccount != nil {
		if profile.UserAccount.TokenRef != "" {
			_ = deletePrivateKey(profile.UserAccount.TokenRef)
		}
		if profile.UserAccount.RefreshTokenRef != "" {
			_ = deletePrivateKey(profile.UserAccount.RefreshTokenRef)
		}
		if profile.UserAccount.IdentityPrivateKeyRef != "" {
			_ = deletePrivateKey(profile.UserAccount.IdentityPrivateKeyRef)
		}
	}

	// Delete the profile file
	if err := deleteProfileFile(name); err != nil && !os.IsNotExist(err) {
		cfgLog.Warn("failed to delete profile file %s: %v", name, err)
	}

	delete(c.Profiles, name)

	// If we deleted the active profile, switch to another
	if c.ActiveProfile == name {
		for newName := range c.Profiles {
			c.ActiveProfile = newName
			break
		}
	}

	return nil
}

// RenameProfile renames a profile, updating keyring keys
func (c *Config) RenameProfile(oldName, newName string) error {
	if oldName == newName {
		return nil
	}
	if err := ValidateProfileName(newName); err != nil {
		return err
	}
	profile, ok := c.Profiles[oldName]
	if !ok {
		return fmt.Errorf("%w: %s", ErrProfileNotFound, oldName)
	}
	if _, ok := c.Profiles[newName]; ok {
		return fmt.Errorf("%w: %s", ErrProfileExists, newName)
	}

	// Migrate keyring keys if there's a user account
	if profile.UserAccount != nil {
		userID := profile.UserAccount.UserID

		// Migrate access token
		if profile.UserAccount.TokenRef != "" {
			newRef := keyringKey(newName, "access-token", userID)
			if err := migrateKeyringKey(profile.UserAccount.TokenRef, newRef); err == nil {
				profile.UserAccount.TokenRef = newRef
			}
		}

		// Migrate refresh token
		if profile.UserAccount.RefreshTokenRef != "" {
			newRef := keyringKey(newName, "refresh-token", userID)
			if err := migrateKeyringKey(profile.UserAccount.RefreshTokenRef, newRef); err == nil {
				profile.UserAccount.RefreshTokenRef = newRef
			}
		}

		// Migrate identity key
		if profile.UserAccount.IdentityPrivateKeyRef != "" {
			newRef := keyringKey(newName, "identity-private", userID)
			if err := migrateKeyringKey(profile.UserAccount.IdentityPrivateKeyRef, newRef); err == nil {
				profile.UserAccount.IdentityPrivateKeyRef = newRef
			}
		}
	}

	// Move profile to new name in memory
	c.Profiles[newName] = profile
	delete(c.Profiles, oldName)

	// Rename the profile file: save new file, delete old file
	if err := saveProfileFile(newName, profile); err != nil {
		// Rollback in-memory change
		c.Profiles[oldName] = profile
		delete(c.Profiles, newName)
		return fmt.Errorf("failed to save renamed profile: %w", err)
	}
	if err := deleteProfileFile(oldName); err != nil && !os.IsNotExist(err) {
		cfgLog.Warn("failed to delete old profile file %s: %v", oldName, err)
	}

	// Update active profile if it was renamed
	if c.ActiveProfile == oldName {
		c.ActiveProfile = newName
	}

	return nil
}

// IsLoggedIn returns true if the active profile is logged into a user account with verified SAS
func (c *Config) IsLoggedIn() bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return false
	}
	return profile.IsLoggedIn()
}

// Convenience accessors for active profile fields

// RelayURL returns the backend URL for the active profile
func (c *Config) RelayURL() string {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return ""
	}
	return profile.RelayURL
}

// IssuerURL returns the OIDC issuer URL for the active profile
func (c *Config) IssuerURL() string {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return ""
	}
	return profile.IssuerURL
}

// UserAccount returns the user account for the active profile
func (c *Config) UserAccount() *UserAccount {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.UserAccount
}
