package go_i2cp

import (
	"testing"
)

// TestSessionConfig verifies that Config() returns session configuration.
func TestSessionConfig(t *testing.T) {
	tests := []struct {
		name         string
		setupSession func() *Session
		expectNil    bool
	}{
		{
			name: "properly initialized session has config",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				return NewSession(client, SessionCallbacks{})
			},
			expectNil: false,
		},
		{
			name: "zero-value session returns nil",
			setupSession: func() *Session {
				return &Session{} // Not initialized
			},
			expectNil: true,
		},
		{
			name: "session with custom config",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				// Config should already be created by NewSession
				return session
			},
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()
			config := session.Config()

			if tt.expectNil {
				if config != nil {
					t.Errorf("Config() = %v, want nil", config)
				}
			} else {
				if config == nil {
					t.Error("Config() = nil, want non-nil")
				}
			}
		})
	}
}

// TestGetTunnelQuantity verifies tunnel quantity getter.
func TestGetTunnelQuantity(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     func() *Session
		inbound          bool
		expectedQuantity int
	}{
		{
			name: "session with inbound quantity set",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "5")
				return session
			},
			inbound:          true,
			expectedQuantity: 5,
		},
		{
			name: "session with outbound quantity set",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")
				return session
			},
			inbound:          false,
			expectedQuantity: 3,
		},
		{
			name: "session with no quantity set returns 0",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				return NewSession(client, SessionCallbacks{})
			},
			inbound:          true,
			expectedQuantity: 0,
		},
		{
			name: "zero-value session returns 0",
			setupSession: func() *Session {
				return &Session{} // Not initialized
			},
			inbound:          true,
			expectedQuantity: 0,
		},
		{
			name: "session with different inbound and outbound quantities",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "7")
				session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")
				return session
			},
			inbound:          true,
			expectedQuantity: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()
			quantity := session.GetTunnelQuantity(tt.inbound)

			if quantity != tt.expectedQuantity {
				t.Errorf("GetTunnelQuantity(%v) = %d, want %d",
					tt.inbound, quantity, tt.expectedQuantity)
			}
		})
	}
}

// TestGetTunnelLength verifies tunnel length getter.
func TestGetTunnelLength(t *testing.T) {
	tests := []struct {
		name           string
		setupSession   func() *Session
		inbound        bool
		expectedLength int
	}{
		{
			name: "session with inbound length set",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "4")
				return session
			},
			inbound:        true,
			expectedLength: 4,
		},
		{
			name: "session with outbound length set",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "2")
				return session
			},
			inbound:        false,
			expectedLength: 2,
		},
		{
			name: "session with no length set returns 0",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				return NewSession(client, SessionCallbacks{})
			},
			inbound:        true,
			expectedLength: 0,
		},
		{
			name: "zero-value session returns 0",
			setupSession: func() *Session {
				return &Session{} // Not initialized
			},
			inbound:        false,
			expectedLength: 0,
		},
		{
			name: "session with high anonymity length (3 hops)",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")
				session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")
				return session
			},
			inbound:        true,
			expectedLength: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()
			length := session.GetTunnelLength(tt.inbound)

			if length != tt.expectedLength {
				t.Errorf("GetTunnelLength(%v) = %d, want %d",
					tt.inbound, length, tt.expectedLength)
			}
		})
	}
}

// TestGetProperty verifies general property getter.
func TestGetProperty(t *testing.T) {
	tests := []struct {
		name          string
		setupSession  func() *Session
		property      SessionConfigProperty
		expectedValue string
	}{
		{
			name: "get fast receive property",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
				return session
			},
			property:      SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE,
			expectedValue: "true",
		},
		{
			name: "get gzip property",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_GZIP, "false")
				return session
			},
			property:      SESSION_CONFIG_PROP_I2CP_GZIP,
			expectedValue: "false",
		},
		{
			name: "get inbound nickname",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_NICKNAME, "my-tunnel")
				return session
			},
			property:      SESSION_CONFIG_PROP_INBOUND_NICKNAME,
			expectedValue: "my-tunnel",
		},
		{
			name: "get unset property returns empty string",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				return NewSession(client, SessionCallbacks{})
			},
			property:      SESSION_CONFIG_PROP_I2CP_USERNAME,
			expectedValue: "",
		},
		{
			name: "zero-value session returns empty string",
			setupSession: func() *Session {
				return &Session{} // Not initialized
			},
			property:      SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE,
			expectedValue: "",
		},
		{
			name: "get crypto tags to send",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND, "40")
				return session
			},
			property:      SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND,
			expectedValue: "40",
		},
		{
			name: "get outbound priority",
			setupSession: func() *Session {
				client := NewClient(&ClientCallBacks{})
				session := NewSession(client, SessionCallbacks{})
				session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_PRIORITY, "10")
				return session
			},
			property:      SESSION_CONFIG_PROP_OUTBOUND_PRIORITY,
			expectedValue: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tt.setupSession()
			value := session.GetProperty(tt.property)

			if value != tt.expectedValue {
				t.Errorf("GetProperty(%v) = %q, want %q",
					tt.property, value, tt.expectedValue)
			}
		})
	}
}

// TestGetPropertyInvalidRange verifies bounds checking for property index.
func TestGetPropertyInvalidRange(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})

	tests := []struct {
		name     string
		property SessionConfigProperty
	}{
		{
			name:     "negative property index",
			property: SessionConfigProperty(-1),
		},
		{
			name:     "property index beyond range",
			property: NR_OF_SESSION_CONFIG_PROPERTIES,
		},
		{
			name:     "property index way beyond range",
			property: SessionConfigProperty(1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := session.GetProperty(tt.property)
			if value != "" {
				t.Errorf("GetProperty(%v) = %q, want empty string for invalid index",
					tt.property, value)
			}
		})
	}
}

// TestSessionConfigGettersThreadSafety verifies thread-safe config access.
func TestSessionConfigGettersThreadSafety(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})

	// Set some initial values
	session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "5")
	session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "2")
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")

	// Run concurrent reads
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(idx int) {
			switch idx % 5 {
			case 0:
				_ = session.Config()
			case 1:
				_ = session.GetTunnelQuantity(true)
			case 2:
				_ = session.GetTunnelLength(false)
			case 3:
				_ = session.GetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE)
			case 4:
				_ = session.GetTunnelQuantity(false)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestTunnelConfigurationScenarios tests realistic tunnel configurations.
func TestTunnelConfigurationScenarios(t *testing.T) {
	tests := []struct {
		name                string
		inboundQuantity     string
		inboundLength       string
		outboundQuantity    string
		outboundLength      string
		expectedInboundQty  int
		expectedInboundLen  int
		expectedOutboundQty int
		expectedOutboundLen int
		description         string
	}{
		{
			name:                "high anonymity configuration",
			inboundQuantity:     "5",
			inboundLength:       "3",
			outboundQuantity:    "5",
			outboundLength:      "3",
			expectedInboundQty:  5,
			expectedInboundLen:  3,
			expectedOutboundQty: 5,
			expectedOutboundLen: 3,
			description:         "Maximum anonymity with 5 tunnels of 3 hops each",
		},
		{
			name:                "low latency configuration",
			inboundQuantity:     "2",
			inboundLength:       "1",
			outboundQuantity:    "2",
			outboundLength:      "1",
			expectedInboundQty:  2,
			expectedInboundLen:  1,
			expectedOutboundQty: 2,
			expectedOutboundLen: 1,
			description:         "Low latency with 2 tunnels of 1 hop each",
		},
		{
			name:                "balanced configuration (default)",
			inboundQuantity:     "3",
			inboundLength:       "3",
			outboundQuantity:    "3",
			outboundLength:      "3",
			expectedInboundQty:  3,
			expectedInboundLen:  3,
			expectedOutboundQty: 3,
			expectedOutboundLen: 3,
			description:         "Balanced anonymity/performance",
		},
		{
			name:                "asymmetric configuration",
			inboundQuantity:     "4",
			inboundLength:       "2",
			outboundQuantity:    "2",
			outboundLength:      "3",
			expectedInboundQty:  4,
			expectedInboundLen:  2,
			expectedOutboundQty: 2,
			expectedOutboundLen: 3,
			description:         "More inbound capacity, fewer outbound tunnels",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(&ClientCallBacks{})
			session := NewSession(client, SessionCallbacks{})

			// Configure tunnel settings
			session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, tt.inboundQuantity)
			session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, tt.inboundLength)
			session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, tt.outboundQuantity)
			session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, tt.outboundLength)

			// Verify inbound configuration
			if qty := session.GetTunnelQuantity(true); qty != tt.expectedInboundQty {
				t.Errorf("inbound quantity = %d, want %d", qty, tt.expectedInboundQty)
			}
			if len := session.GetTunnelLength(true); len != tt.expectedInboundLen {
				t.Errorf("inbound length = %d, want %d", len, tt.expectedInboundLen)
			}

			// Verify outbound configuration
			if qty := session.GetTunnelQuantity(false); qty != tt.expectedOutboundQty {
				t.Errorf("outbound quantity = %d, want %d", qty, tt.expectedOutboundQty)
			}
			if len := session.GetTunnelLength(false); len != tt.expectedOutboundLen {
				t.Errorf("outbound length = %d, want %d", len, tt.expectedOutboundLen)
			}

			t.Logf("Configuration: %s", tt.description)
		})
	}
}

// TestAllSessionConfigProperties verifies we can get/set all defined properties.
func TestAllSessionConfigProperties(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})

	// Test all valid property constants
	properties := []SessionConfigProperty{
		SESSION_CONFIG_PROP_CRYPTO_LOW_TAG_THRESHOLD,
		SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND,
		SESSION_CONFIG_PROP_I2CP_DONT_PUBLISH_LEASE_SET,
		SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE,
		SESSION_CONFIG_PROP_I2CP_GZIP,
		SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY,
		SESSION_CONFIG_PROP_I2CP_PASSWORD,
		SESSION_CONFIG_PROP_I2CP_USERNAME,
		SESSION_CONFIG_PROP_INBOUND_ALLOW_ZERO_HOP,
		SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY,
		SESSION_CONFIG_PROP_INBOUND_IP_RESTRICTION,
		SESSION_CONFIG_PROP_INBOUND_LENGTH,
		SESSION_CONFIG_PROP_INBOUND_LENGTH_VARIANCE,
		SESSION_CONFIG_PROP_INBOUND_NICKNAME,
		SESSION_CONFIG_PROP_INBOUND_QUANTITY,
		SESSION_CONFIG_PROP_OUTBOUND_ALLOW_ZERO_HOP,
		SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY,
		SESSION_CONFIG_PROP_OUTBOUND_IP_RESTRICTION,
		SESSION_CONFIG_PROP_OUTBOUND_LENGTH,
		SESSION_CONFIG_PROP_OUTBOUND_LENGTH_VARIANCE,
		SESSION_CONFIG_PROP_OUTBOUND_NICKNAME,
		SESSION_CONFIG_PROP_OUTBOUND_PRIORITY,
		SESSION_CONFIG_PROP_OUTBOUND_QUANTITY,
	}

	// Set a test value for each property
	for _, prop := range properties {
		testValue := "test-value"
		session.config.SetProperty(prop, testValue)

		// Verify we can read it back
		value := session.GetProperty(prop)
		if value != testValue {
			t.Errorf("Property %v: got %q, want %q", prop, value, testValue)
		}
	}
}

// BenchmarkSessionConfigGetters measures performance of config getter methods.
func BenchmarkSessionConfigGetters(b *testing.B) {
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})
	session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")

	b.Run("Config", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = session.Config()
		}
	})

	b.Run("GetTunnelQuantity", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = session.GetTunnelQuantity(true)
		}
	})

	b.Run("GetTunnelLength", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = session.GetTunnelLength(false)
		}
	})

	b.Run("GetProperty", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = session.GetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE)
		}
	})
}
