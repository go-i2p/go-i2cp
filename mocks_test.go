package go_i2cp

// mocks_test.go - Shared test helpers, mocks, and stubs used across multiple test files.

// containsSubstring checks if string s contains the substring substr.
// This is a shared test helper used across multiple test files.
func containsSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// setupTestClient creates a minimal client for testing message handlers.
func setupTestClient() *Client {
	return &Client{
		router:   RouterInfo{},
		sessions: make(map[uint16]*Session),
	}
}
