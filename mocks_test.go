package go_i2cp

import "testing"

// mocks_test.go - Shared test helpers, mocks, and stubs used across multiple test files.

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
