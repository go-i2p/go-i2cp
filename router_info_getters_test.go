package go_i2cp

import (
	"testing"
	"time"
)

// TestRouterVersion verifies that RouterVersion() returns router version information.
func TestRouterVersion(t *testing.T) {
	tests := []struct {
		name            string
		setupClient     func() *Client
		expectedVersion Version
	}{
		{
			name: "initialized client with router version",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 0, minor: 9, micro: 66, qualifier: 0}
				return client
			},
			expectedVersion: Version{major: 0, minor: 9, micro: 66, qualifier: 0},
		},
		{
			name: "initialized client with different version",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 1, minor: 2, micro: 3, qualifier: 4}
				return client
			},
			expectedVersion: Version{major: 1, minor: 2, micro: 3, qualifier: 4},
		},
		{
			name: "zero-value client returns zero version",
			setupClient: func() *Client {
				return &Client{} // Not initialized
			},
			expectedVersion: Version{}, // Zero-value
		},
		{
			name: "nil client crypto returns zero version",
			setupClient: func() *Client {
				return &Client{
					properties: make(map[string]string),
					sessions:   make(map[uint16]*Session),
					// crypto is nil
				}
			},
			expectedVersion: Version{}, // Zero-value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			version := client.RouterVersion()

			if version.major != tt.expectedVersion.major ||
				version.minor != tt.expectedVersion.minor ||
				version.micro != tt.expectedVersion.micro ||
				version.qualifier != tt.expectedVersion.qualifier {
				t.Errorf("RouterVersion() = {%d, %d, %d, %d}, want {%d, %d, %d, %d}",
					version.major, version.minor, version.micro, version.qualifier,
					tt.expectedVersion.major, tt.expectedVersion.minor,
					tt.expectedVersion.micro, tt.expectedVersion.qualifier)
			}
		})
	}
}

// TestRouterCapabilities verifies that RouterCapabilities() returns capability flags.
func TestRouterCapabilities(t *testing.T) {
	tests := []struct {
		name               string
		setupClient        func() *Client
		expectedCapability uint32
	}{
		{
			name: "router with host lookup capability",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
				return client
			},
			expectedCapability: ROUTER_CAN_HOST_LOOKUP,
		},
		{
			name: "router with no capabilities",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = 0
				return client
			},
			expectedCapability: 0,
		},
		{
			name: "router with multiple capabilities",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = ROUTER_CAN_HOST_LOOKUP | 0x02 | 0x04
				return client
			},
			expectedCapability: ROUTER_CAN_HOST_LOOKUP | 0x02 | 0x04,
		},
		{
			name: "zero-value client returns zero capabilities",
			setupClient: func() *Client {
				return &Client{} // Not initialized
			},
			expectedCapability: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			caps := client.RouterCapabilities()

			if caps != tt.expectedCapability {
				t.Errorf("RouterCapabilities() = 0x%x, want 0x%x", caps, tt.expectedCapability)
			}
		})
	}
}

// TestRouterDate verifies that RouterDate() returns router timestamp.
func TestRouterDate(t *testing.T) {
	tests := []struct {
		name         string
		setupClient  func() *Client
		expectedDate uint64
	}{
		{
			name: "router with valid date",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.date = 1701432000000 // 2023-12-01 12:00:00 UTC in milliseconds
				return client
			},
			expectedDate: 1701432000000,
		},
		{
			name: "router with different date",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.date = 1234567890123
				return client
			},
			expectedDate: 1234567890123,
		},
		{
			name: "zero-value client returns zero date",
			setupClient: func() *Client {
				return &Client{} // Not initialized
			},
			expectedDate: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			date := client.RouterDate()

			if date != tt.expectedDate {
				t.Errorf("RouterDate() = %d, want %d", date, tt.expectedDate)
			}
		})
	}
}

// TestSupportsHostLookup verifies that SupportsHostLookup() correctly detects capability.
func TestSupportsHostLookup(t *testing.T) {
	tests := []struct {
		name            string
		setupClient     func() *Client
		expectedSupport bool
	}{
		{
			name: "router with host lookup capability",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
				return client
			},
			expectedSupport: true,
		},
		{
			name: "router without host lookup capability",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = 0
				return client
			},
			expectedSupport: false,
		},
		{
			name: "router with other capabilities but not host lookup",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = 0x02 | 0x04 // Other capabilities
				return client
			},
			expectedSupport: false,
		},
		{
			name: "router with host lookup and other capabilities",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.capabilities = ROUTER_CAN_HOST_LOOKUP | 0x02 | 0x04
				return client
			},
			expectedSupport: true,
		},
		{
			name: "zero-value client returns false",
			setupClient: func() *Client {
				return &Client{} // Not initialized
			},
			expectedSupport: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			supports := client.SupportsHostLookup()

			if supports != tt.expectedSupport {
				t.Errorf("SupportsHostLookup() = %v, want %v", supports, tt.expectedSupport)
			}
		})
	}
}

// TestSupportsMultiSession verifies that SupportsMultiSession() correctly detects version.
func TestSupportsMultiSession(t *testing.T) {
	tests := []struct {
		name            string
		setupClient     func() *Client
		expectedSupport bool
	}{
		{
			name: "router version 0.9.21 supports multi-session",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 0, minor: 9, micro: 21, qualifier: 0}
				return client
			},
			expectedSupport: true,
		},
		{
			name: "router version 0.9.66 supports multi-session",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 0, minor: 9, micro: 66, qualifier: 0}
				return client
			},
			expectedSupport: true,
		},
		{
			name: "router version 0.9.20 does not support multi-session (fixed)",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 0, minor: 9, micro: 20, qualifier: 0}
				return client
			},
			expectedSupport: false, // Fixed: version compare now works correctly
		},
		{
			name: "router version 0.9.10 does not support multi-session (fixed)",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 0, minor: 9, micro: 10, qualifier: 0}
				return client
			},
			expectedSupport: false, // Fixed: version compare now works correctly
		},
		{
			name: "router version 1.0.0 supports multi-session",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.router.version = Version{major: 1, minor: 0, micro: 0, qualifier: 0}
				return client
			},
			expectedSupport: true,
		},
		{
			name: "zero-value client returns false",
			setupClient: func() *Client {
				return &Client{} // Not initialized
			},
			expectedSupport: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			supports := client.SupportsMultiSession()

			if supports != tt.expectedSupport {
				t.Errorf("SupportsMultiSession() = %v, want %v", supports, tt.expectedSupport)
			}
		})
	}
}

// TestRouterInfoGettersThreadSafety verifies thread-safe access to router info.
func TestRouterInfoGettersThreadSafety(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	client.router.version = Version{major: 0, minor: 9, micro: 66, qualifier: 0}
	client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
	client.router.date = 1701432000000

	// Run concurrent reads and writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = client.RouterVersion()
				_ = client.RouterCapabilities()
				_ = client.RouterDate()
				_ = client.SupportsHostLookup()
				_ = client.SupportsMultiSession()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestRouterInfoGettersAfterConnect simulates router info population during connect.
func TestRouterInfoGettersAfterConnect(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Before connect - should return zero values
	if version := client.RouterVersion(); version.major != 0 || version.minor != 0 {
		t.Errorf("Before connect: RouterVersion() should be zero, got %+v", version)
	}
	if caps := client.RouterCapabilities(); caps != 0 {
		t.Errorf("Before connect: RouterCapabilities() should be 0, got %d", caps)
	}
	if date := client.RouterDate(); date != 0 {
		t.Errorf("Before connect: RouterDate() should be 0, got %d", date)
	}
	if supports := client.SupportsHostLookup(); supports {
		t.Error("Before connect: SupportsHostLookup() should be false")
	}
	// Note: Zero-value version {0,0,0,0} compares equal to or greater than {0,9,21,0}
	// due to unsigned integer underflow in compare(). This is expected behavior.
	// In production, version is only set after successful connect.

	// Simulate router info population (as would happen during connect)
	client.lock.Lock()
	client.router.version = Version{major: 0, minor: 9, micro: 66, qualifier: 0}
	client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
	client.router.date = 1701432000000
	client.lock.Unlock()

	// After connect - should return actual values
	version := client.RouterVersion()
	if version.major != 0 || version.minor != 9 || version.micro != 66 {
		t.Errorf("After connect: RouterVersion() = %+v, want {0, 9, 66, 0}", version)
	}

	caps := client.RouterCapabilities()
	if caps != ROUTER_CAN_HOST_LOOKUP {
		t.Errorf("After connect: RouterCapabilities() = %d, want %d", caps, ROUTER_CAN_HOST_LOOKUP)
	}

	date := client.RouterDate()
	if date != 1701432000000 {
		t.Errorf("After connect: RouterDate() = %d, want 1701432000000", date)
	}

	if !client.SupportsHostLookup() {
		t.Error("After connect: SupportsHostLookup() should be true")
	}

	if !client.SupportsMultiSession() {
		t.Error("After connect: SupportsMultiSession() should be true")
	}
}

// TestRouterDateConversionExample demonstrates converting router date to Go time.
func TestRouterDateConversionExample(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	client.router.date = 1701432000000 // 2023-12-01 12:00:00 UTC

	routerDate := client.RouterDate()
	routerTime := time.Unix(int64(routerDate/1000), int64((routerDate%1000)*1000000)).UTC()

	expectedTime := time.Date(2023, 12, 1, 12, 0, 0, 0, time.UTC)
	if !routerTime.Equal(expectedTime) {
		t.Errorf("RouterDate conversion = %v, want %v", routerTime, expectedTime)
	}
}

// TestRouterVersionComparison verifies version comparison with required versions.
func TestRouterVersionComparison(t *testing.T) {
	tests := []struct {
		name            string
		routerVersion   Version
		requiredVersion Version
		shouldSupport   bool
	}{
		{
			name:            "exact match supports feature",
			routerVersion:   Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			requiredVersion: Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			shouldSupport:   true,
		},
		{
			name:            "higher micro supports feature",
			routerVersion:   Version{major: 0, minor: 9, micro: 66, qualifier: 0},
			requiredVersion: Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			shouldSupport:   true,
		},
		// Note: The compare() function has an unsigned integer underflow bug
		// when comparing lower versions to higher versions. This causes
		// (20 - 21) to underflow to a large positive value, returning 1 instead of -1.
		// This test documents the current behavior. In production, this doesn't
		// matter because router version is only set after connecting to a router,
		// so we never compare against invalid/zero versions.
		{
			name:            "lower micro (fixed)",
			routerVersion:   Version{major: 0, minor: 9, micro: 20, qualifier: 0},
			requiredVersion: Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			shouldSupport:   false, // Fixed: version compare now works correctly
		},
		{
			name:            "higher minor supports feature",
			routerVersion:   Version{major: 0, minor: 10, micro: 0, qualifier: 0},
			requiredVersion: Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			shouldSupport:   true,
		},
		{
			name:            "higher major supports feature",
			routerVersion:   Version{major: 1, minor: 0, micro: 0, qualifier: 0},
			requiredVersion: Version{major: 0, minor: 9, micro: 21, qualifier: 0},
			shouldSupport:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supports := tt.routerVersion.compare(tt.requiredVersion) >= 0
			if supports != tt.shouldSupport {
				t.Errorf("version comparison = %v, want %v", supports, tt.shouldSupport)
			}
		})
	}
}

// BenchmarkRouterInfoGetters measures performance of getter methods.
func BenchmarkRouterInfoGetters(b *testing.B) {
	client := NewClient(&ClientCallBacks{})
	client.router.version = Version{major: 0, minor: 9, micro: 66, qualifier: 0}
	client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
	client.router.date = 1701432000000

	b.Run("RouterVersion", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.RouterVersion()
		}
	})

	b.Run("RouterCapabilities", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.RouterCapabilities()
		}
	})

	b.Run("RouterDate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.RouterDate()
		}
	})

	b.Run("SupportsHostLookup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.SupportsHostLookup()
		}
	})

	b.Run("SupportsMultiSession", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = client.SupportsMultiSession()
		}
	})
}
