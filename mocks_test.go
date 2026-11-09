package go_i2cp

import (
	"net"
	"os"
	"sync"
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

// Default grace period given to a freshly started router to build its tunnels.
const defaultTunnelGrace = 60 * time.Second

// tunnelGraceOnce guards the grace period so a test binary pays it at most once.
var tunnelGraceOnce sync.Once

// tunnelGracePeriod returns how long to wait for tunnels to establish on the
// first readiness gate of a process. Configure with GO_I2CP_TUNNEL_GRACE
// (Go duration syntax, e.g. "10s"; "0" disables the wait entirely).
// `go test -short` also disables it.
func tunnelGracePeriod() time.Duration {
	if testing.Short() {
		return 0
	}
	if raw := os.Getenv("GO_I2CP_TUNNEL_GRACE"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	}
	return defaultTunnelGrace
}

// waitForI2CPReadiness verifies the I2CP server is available and tunnels are ready.
// It performs two checks:
//  1. Waits for I2CP server availability on the configured host:port (default 127.0.0.1:7654)
//  2. Waits for I2P tunnels to establish and become ready (default 60 seconds)
//
// This readiness gate should be called at the start of integration tests to ensure
// the I2CP interface is fully available before tests attempt connections.
// Fails the test if either check times out.
//
// Check 1 runs on every call and is fast. Check 2 is paid only once per test binary:
// all integration tests in the package share the same long-lived router, so the
// tunnels built during the first grace period are still up for every later test.
// Re-waiting per test multiplied a fixed cost by the number of call sites and blew
// past the `go test` timeout. Shorten it with GO_I2CP_TUNNEL_GRACE or skip it with -short.
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
	available := false

	for !available && time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			available = true
			break
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}

	if !available {
		t.Fatalf("Timeout waiting for I2CP server on %s: %v", addr, lastErr)
	}
	t.Logf("I2CP server is available on %s", addr)

	// Phase 2: Wait for I2P tunnels to establish and become ready.
	// Tunnels can take time to build in the I2P network, so this is a grace
	// period rather than a pollable condition; once per process (see above).
	tunnelGraceOnce.Do(func() {
		grace := tunnelGracePeriod()
		if grace <= 0 {
			t.Log("Skipping I2P tunnel grace period")
			return
		}
		t.Logf("Waiting %v for I2P tunnels to establish...", grace)
		time.Sleep(grace)
		t.Logf("I2P tunnels ready, proceeding with tests")
	})
}
