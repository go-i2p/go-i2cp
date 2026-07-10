package go_i2cp

import "testing"

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

// newTestSession creates a fully-initialized Client (via NewClient(nil)) and a
// Session with empty callbacks. This is a shared helper for unit tests (and
// benchmarks, via testing.TB) that only need a bare Session and don't care
// about custom client/session callbacks or wiring.
func newTestSession(t testing.TB) *Session {
	t.Helper()
	client := NewClient(nil)
	return NewSession(client, SessionCallbacks{})
}

// setupTestClient creates a minimal client for testing message handlers.
func setupTestClient() *Client {
	return &Client{
		router:   RouterInfo{},
		sessions: make(map[uint16]*Session),
	}
}
