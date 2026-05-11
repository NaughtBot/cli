package client

// contains checks if s contains substr without importing strings.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

// containsAt is a tiny substring search used by tests across both default
// and `legacy_api` builds. Kept ungated so it can be shared between
// client_extra_test.go (default build) and client_test.go (legacy_api build).
func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
