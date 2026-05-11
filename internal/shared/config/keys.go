package config

// Key management methods for active profile

// FindKey looks up a key by ID, public key hex, or label in the active profile.
func (c *Config) FindKey(query string) (*KeyMetadata, error) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil, err
	}
	return profile.FindKey(query)
}

// FindKey looks up a key by ID, public key hex, or label in this profile
func (p *ProfileConfig) FindKey(query string) (*KeyMetadata, error) {
	for i := range p.Keys {
		k := &p.Keys[i]
		keyHex := k.Hex()
		if k.IOSKeyID == query || keyHex == query || k.Label == query {
			return k, nil
		}
		// Also check if query is a suffix of public key hex (e.g., last 8 chars)
		if len(query) < len(keyHex) && keyHex[len(keyHex)-len(query):] == query {
			return k, nil
		}
	}
	return nil, ErrKeyNotFound
}

// AddKey adds or updates a key in the active profile.
func (c *Config) AddKey(key KeyMetadata) {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return
	}
	profile.AddKey(key)
}

// AddKey adds or updates a key in this profile
func (p *ProfileConfig) AddKey(key KeyMetadata) {
	addKeyToSlice(&p.Keys, key)
}

// RemoveKey removes a key from the active profile.
func (c *Config) RemoveKey(iosKeyID string) bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return false
	}
	return profile.RemoveKey(iosKeyID)
}

// RemoveKey removes a key from this profile
func (p *ProfileConfig) RemoveKey(iosKeyID string) bool {
	for i := range p.Keys {
		if p.Keys[i].IOSKeyID == iosKeyID {
			p.Keys = append(p.Keys[:i], p.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// FindKeyByPurpose finds a key by its purpose (ssh or gpg) in this profile
func (p *ProfileConfig) FindKeyByPurpose(purpose KeyPurpose) *KeyMetadata {
	for i := range p.Keys {
		if p.Keys[i].Purpose == purpose {
			return &p.Keys[i]
		}
	}
	return nil
}

// FindKeyByPurpose finds a key by its purpose (ssh or gpg) in the active profile.
func (c *Config) FindKeyByPurpose(purpose KeyPurpose) *KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.FindKeyByPurpose(purpose)
}

// KeysForPurpose returns all keys with the given purpose in this profile
func (p *ProfileConfig) KeysForPurpose(purpose KeyPurpose) []KeyMetadata {
	var result []KeyMetadata
	for _, k := range p.Keys {
		if k.Purpose == purpose {
			result = append(result, k)
		}
	}
	return result
}

// KeysForPurpose returns all keys with the given purpose in the active profile.
func (c *Config) KeysForPurpose(purpose KeyPurpose) []KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.KeysForPurpose(purpose)
}

// IsLabelUnique checks if a label is unique among keys of the given purpose in this profile
func (p *ProfileConfig) IsLabelUnique(purpose KeyPurpose, label string) bool {
	for _, k := range p.Keys {
		if k.Purpose == purpose && k.Label == label {
			return false
		}
	}
	return true
}

// IsLabelUnique checks if a label is unique among keys of the given purpose in the active profile.
func (c *Config) IsLabelUnique(purpose KeyPurpose, label string) bool {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return true // No profile means no keys, so label is unique
	}
	return profile.IsLabelUnique(purpose, label)
}

// Keys returns the keys for the active profile.
func (c *Config) Keys() []KeyMetadata {
	profile, err := c.GetActiveProfile()
	if err != nil {
		return nil
	}
	return profile.Keys
}

// FindKeyAcrossProfiles searches all profiles for a key by iOS Key ID.
// Returns the key, the profile name, and any error.
// This is useful for SSH sk-provider which needs to find the correct
// profile for a key regardless of which profile is currently active.
func (c *Config) FindKeyAcrossProfiles(iosKeyID string) (*KeyMetadata, string, error) {
	for name, profile := range c.Profiles {
		for i := range profile.Keys {
			if profile.Keys[i].IOSKeyID == iosKeyID {
				return &profile.Keys[i], name, nil
			}
		}
	}
	return nil, "", ErrKeyNotFound
}

// addKeyToSlice adds or updates a key in a key slice.
// When IOSKeyID is non-empty, deduplicates by IOSKeyID.
// When IOSKeyID is empty, deduplicates by matching public key + purpose
// to avoid overwriting unrelated keys that also have empty IOSKeyID.
func addKeyToSlice(keys *[]KeyMetadata, key KeyMetadata) {
	for i := range *keys {
		if (*keys)[i].IOSKeyID != "" && (*keys)[i].IOSKeyID == key.IOSKeyID {
			(*keys)[i] = key
			return
		}
		if (*keys)[i].IOSKeyID == "" && key.IOSKeyID == "" &&
			(*keys)[i].Hex() == key.Hex() && (*keys)[i].Purpose == key.Purpose {
			(*keys)[i] = key
			return
		}
	}
	*keys = append(*keys, key)
}
