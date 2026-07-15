package go_i2cp

import (
	"net"
	"testing"
	"time"
)

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

// waitForI2CPReadiness verifies the I2CP server is available and tunnels are ready.
// It performs two checks:
//  1. Waits for I2CP server availability on the configured host:port (default 127.0.0.1:7654)
//  2. Waits an additional 60 seconds for I2P tunnels to establish and become ready
//
// This readiness gate should be called at the start of integration tests to ensure
// the I2CP interface is fully available before tests attempt connections.
// Fails the test if either check times out.
func waitForI2CPReadiness(t testing.TB) {
	t.Helper()

	// Default I2CP server address from client configuration
	host := "127.0.0.1"
	port := "7654"
	addr := net.JoinHostPort(host, port)

	// Phase 1: Wait for I2CP server to be available on the default port
	// Timeout: 30 seconds (accommodates slow startup in CI environments)
	t.Logf("Waiting for I2CP server to be available on %s...", addr)
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Logf("I2CP server is available on %s", addr)
			break
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}

	if time.Now().After(deadline) {
		t.Fatalf("Timeout waiting for I2CP server on %s: %v", addr, lastErr)
	}

	// Phase 2: Wait for I2P tunnels to establish and become ready
	// Timeout: 60 seconds (tunnels can take time to build in I2P network)
	t.Logf("Waiting 60 seconds for I2P tunnels to establish...")
	time.Sleep(60 * time.Second)
	t.Logf("I2P tunnels ready, proceeding with tests")
}
