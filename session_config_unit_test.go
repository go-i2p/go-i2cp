package go_i2cp

import (
	"os"
	"path/filepath"
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

// --- merged from session_config_properties_test.go ---

// TestWriteMappingDeterministic verifies that calling writeMappingToMessage multiple times
// produces identical byte output
func TestWriteMappingDeterministic(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, "4")
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	// Write properties multiple times
	stream1 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream1); err != nil {
		t.Fatalf("Failed to write mapping (attempt 1): %v", err)
	}

	stream2 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream2); err != nil {
		t.Fatalf("Failed to write mapping (attempt 2): %v", err)
	}

	stream3 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream3); err != nil {
		t.Fatalf("Failed to write mapping (attempt 3): %v", err)
	}

	// Compare bytes
	bytes1 := stream1.Bytes()
	bytes2 := stream2.Bytes()
	bytes3 := stream3.Bytes()

	t.Logf("Attempt 1: %d bytes: %x", len(bytes1), bytes1)
	t.Logf("Attempt 2: %d bytes: %x", len(bytes2), bytes2)
	t.Logf("Attempt 3: %d bytes: %x", len(bytes3), bytes3)

	if string(bytes1) != string(bytes2) {
		t.Fatal("Properties bytes differ between attempt 1 and 2!")
	}

	if string(bytes1) != string(bytes3) {
		t.Fatal("Properties bytes differ between attempt 1 and 3!")
	}

	t.Log("All attempts produced identical bytes ✓")
}

// --- merged from session_config_signature_test.go ---

// TestSessionConfigSignatureGeneration verifies that CreateSession signature
// is generated correctly per I2CP specification
func TestSessionConfigSignatureGeneration(t *testing.T) {
	crypto := NewCrypto()

	// Create a destination with DSA keypair
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Create session config
	config := &SessionConfig{
		destination: dest,
	}

	// Set some properties
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")

	// Generate the CreateSession message
	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	// Verify message was generated
	if stream.Len() == 0 {
		t.Fatal("CreateSession message is empty")
	}

	t.Logf("CreateSession message length: %d bytes", stream.Len())

	// Parse the message to extract signature
	parseStream := NewStream(stream.Bytes())

	// Read destination (skip - we'll use the original dest for verification)
	_, err = NewDestinationFromMessage(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to read destination from message: %v", err)
	}

	// Read properties mapping
	_, err = parseStream.ReadMapping()
	if err != nil {
		t.Fatalf("Failed to read properties mapping: %v", err)
	}

	// Read creation date
	creationDate, err := parseStream.ReadUint64()
	if err != nil {
		t.Fatalf("Failed to read creation date: %v", err)
	}
	t.Logf("Creation date: %d (ms since epoch)", creationDate)

	// Signature follows directly (no type prefix)
	// Java I2P determines signature type from Destination's signing key type in certificate
	// Signature length depends on type: Ed25519 = 64 bytes, DSA = 40 bytes
	// Our destination uses Ed25519, so expect 64-byte signature
	signature := make([]byte, 64)
	n, err := parseStream.Read(signature)
	if err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}
	if n != 64 {
		t.Fatalf("Signature length incorrect: got %d bytes, expected 64", n)
	}

	t.Logf("Signature: %x", signature)

	// Verify signature by reconstructing the data that was signed
	// CRITICAL: Must use WriteToMessage (padded format), NOT WriteForSignature!
	// Java I2P router reads destination with Destination.create() which extracts padding,
	// then writeBytes() reconstructs: pubKey + _padding + signingKey.writeTruncatedBytes() + cert
	// This produces the SAME bytes as our WriteToMessage format.
	dataToVerify := NewStream(make([]byte, 0, 512))
	dest.WriteToMessage(dataToVerify)

	// Rebuild properties mapping
	m := make(map[string]string)
	for i := 0; i < int(NR_OF_SESSION_CONFIG_PROPERTIES); i++ {
		if config.properties[i] == "" {
			continue
		}
		option := config.configOptLookup(SessionConfigProperty(i))
		if option == "" {
			continue
		}
		m[option] = config.properties[i]
	}
	dataToVerify.WriteMapping(m)
	dataToVerify.WriteUint64(creationDate)

	t.Logf("Data to verify length: %d bytes", dataToVerify.Len())
	t.Logf("Data to verify (first 64 bytes): %x", dataToVerify.Bytes()[:min64(64, dataToVerify.Len())])

	// Verify Ed25519 signature using the destination's public key
	if dest.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available")
	}

	verified := dest.sgk.ed25519KeyPair.Verify(dataToVerify.Bytes(), signature)
	if !verified {
		t.Fatal("Signature verification failed")
	}

	t.Log("Signature verification succeeded")
}

func min64(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSessionConfigSignatureFormat verifies the signature has correct format
func TestSessionConfigSignatureFormat(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	// The message should end with: 64-byte Ed25519 signature (no type prefix)
	// Java I2P determines signature type from the Destination's signing key certificate
	messageBytes := stream.Bytes()
	if len(messageBytes) < 64 {
		t.Fatalf("Message too short to contain signature: %d bytes", len(messageBytes))
	}

	// Last 64 bytes: signature only (no type prefix)
	signature := messageBytes[len(messageBytes)-64:]

	// Signature should not be all zeros
	allZeros := true
	for _, b := range signature {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Fatal("Signature is all zeros - signing failed")
	}

	t.Logf("Signature (64 bytes): %x", signature)
}

// TestSessionConfigSignatureWithoutProperties verifies signing works with empty properties
func TestSessionConfigSignatureWithoutProperties(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Config with no properties set
	config := &SessionConfig{
		destination: dest,
	}

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	if stream.Len() == 0 {
		t.Fatal("Message generation failed")
	}

	t.Logf("Message with no properties: %d bytes", stream.Len())

	// Should still have valid Ed25519 signature (2 bytes type + 64 bytes signature)
	messageBytes := stream.Bytes()
	if len(messageBytes) < 66 {
		t.Fatalf("Message too short for signature: %d bytes", len(messageBytes))
	}

	signature := messageBytes[len(messageBytes)-64:]

	// Verify signature is not all zeros
	allZeros := true
	for _, b := range signature {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Fatal("Signature is all zeros")
	}
}

// TestCreateSessionMessageSize verifies the message size is reasonable
func TestCreateSessionMessageSize(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}

	// Add typical properties
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	messageSize := stream.Len()

	// Expected size breakdown:
	// - Destination: 387 bytes (256 pubkey + 128 signing pubkey + 3 cert)
	// - Properties mapping: variable (typically 50-200 bytes)
	// - Creation date: 8 bytes
	// - Signature type: 2 bytes
	// - Ed25519 signature: 64 bytes
	// Total: ~511-661 bytes

	if messageSize < 450 {
		t.Fatalf("Message too small: %d bytes (expected 450+)", messageSize)
	}

	if messageSize > 1000 {
		t.Fatalf("Message too large: %d bytes (expected <1000)", messageSize)
	}

	t.Logf("Message size: %d bytes (within expected range)", messageSize)
}

// --- merged from session_config_util_test.go ---

// TestNewSessionConfig tests the simple NewSessionConfig constructor
func TestNewSessionConfig(t *testing.T) {
	t.Run("creates valid config with auto-generated destination", func(t *testing.T) {
		config, err := NewSessionConfig()
		if err != nil {
			t.Fatalf("NewSessionConfig() failed: %v", err)
		}

		if config == nil {
			t.Fatal("Expected non-nil config, got nil")
		}

		if config.destination == nil {
			t.Error("Expected destination to be auto-created, got nil")
		}

		// Verify destination has valid base64 and base32 representations
		if config.destination.b64 == "" {
			t.Error("Expected destination to have base64 representation")
		}

		if config.destination.b32 == "" {
			t.Error("Expected destination to have base32 representation")
		}
	})

	t.Run("creates different destinations each time", func(t *testing.T) {
		config1, err := NewSessionConfig()
		if err != nil {
			t.Fatalf("NewSessionConfig() failed: %v", err)
		}

		config2, err := NewSessionConfig()
		if err != nil {
			t.Fatalf("NewSessionConfig() failed: %v", err)
		}

		if config1.destination.b64 == config2.destination.b64 {
			t.Error("Expected different destinations, got same")
		}
	})

	t.Run("config is ready for immediate use", func(t *testing.T) {
		config, err := NewSessionConfig()
		if err != nil {
			t.Fatalf("NewSessionConfig() failed: %v", err)
		}

		// Should be able to write to message without panicking
		stream := NewStream(make([]byte, 0, 1024))
		crypto := NewCrypto()

		// This should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("config.writeToMessage() panicked: %v", r)
			}
		}()

		config.writeToMessage(stream, crypto, nil)

		if stream.Len() == 0 {
			t.Error("Expected non-empty stream after writeToMessage")
		}
	})
}

// TestSessionConfig_propFromString tests the private propFromString method
func TestSessionConfig_propFromString(t *testing.T) {
	config := SessionConfig{}

	tests := []struct {
		name     string
		propName string
		want     SessionConfigProperty
	}{
		{
			name:     "valid property - inbound.quantity",
			propName: "inbound.quantity",
			want:     SESSION_CONFIG_PROP_INBOUND_QUANTITY,
		},
		{
			name:     "valid property - outbound.quantity",
			propName: "outbound.quantity",
			want:     SESSION_CONFIG_PROP_OUTBOUND_QUANTITY,
		},
		{
			name:     "valid property - inbound.length",
			propName: "inbound.length",
			want:     SESSION_CONFIG_PROP_INBOUND_LENGTH,
		},
		{
			name:     "valid property - outbound.length",
			propName: "outbound.length",
			want:     SESSION_CONFIG_PROP_OUTBOUND_LENGTH,
		},
		{
			name:     "invalid property",
			propName: "nonexistent.property",
			want:     SessionConfigProperty(-1),
		},
		{
			name:     "empty string",
			propName: "",
			want:     SessionConfigProperty(-1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.propFromString(tt.propName)
			if got != tt.want {
				t.Errorf("propFromString(%q) = %v, want %v", tt.propName, got, tt.want)
			}
		})
	}
}

// TestNewSessionConfigFromDestinationFile tests loading session config from destination file
func TestNewSessionConfigFromDestinationFile(t *testing.T) {
	crypto := NewCrypto()

	t.Run("nonexistent file creates new destination", func(t *testing.T) {
		// Use temp file that doesn't exist
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "nonexistent.dat")

		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have created a new destination
		if config.destination == nil {
			t.Error("Expected destination to be created, got nil")
		}

		// Should have written the file
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Error("Expected destination file to be created")
		}
	})

	t.Run("valid destination file", func(t *testing.T) {
		// Create a valid destination file
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "test.dat")

		// Create and save a destination
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}
		err = dest.WriteToFile(filename)
		if err != nil {
			t.Fatalf("Failed to write destination file: %v", err)
		}

		// Load it back
		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have loaded the destination
		if config.destination == nil {
			t.Error("Expected destination to be loaded, got nil")
		}

		// Verify it matches (compare base64)
		if config.destination.b64 != dest.b64 {
			t.Error("Loaded destination doesn't match original")
		}
	})

	t.Run("empty filename", func(t *testing.T) {
		config := NewSessionConfigFromDestinationFile("", crypto)

		// Should have created a new destination
		if config.destination == nil {
			t.Error("Expected destination to be created, got nil")
		}

		// Should NOT have tried to write a file
		if _, err := os.Stat(""); err == nil {
			t.Error("Should not have created a file with empty name")
		}
	})

	t.Run("corrupted file creates new destination", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "corrupted.dat")

		// Write invalid data
		err := os.WriteFile(filename, []byte("invalid destination data"), 0o644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have created a new destination (not loaded corrupted one)
		if config.destination == nil {
			t.Error("Expected new destination to be created, got nil")
		}
	})
}

// TestNewDestinationFromFile tests loading a destination from file
func TestNewDestinationFromFile(t *testing.T) {
	crypto := NewCrypto()

	t.Run("valid destination file", func(t *testing.T) {
		// Create a destination and save it
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "test_dest.dat")

		originalDest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		err = originalDest.WriteToFile(filename)
		if err != nil {
			t.Fatalf("Failed to write destination: %v", err)
		}

		// Open and read it back
		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		loadedDest, err := NewDestinationFromFile(file, crypto)
		if err != nil {
			t.Fatalf("NewDestinationFromFile failed: %v", err)
		}

		// Verify they match
		if loadedDest.b64 != originalDest.b64 {
			t.Error("Loaded destination doesn't match original")
		}
	})

	t.Run("invalid file data", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "invalid.dat")

		// Write invalid data
		err := os.WriteFile(filename, []byte("not a valid destination"), 0o644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		_, err = NewDestinationFromFile(file, crypto)
		if err == nil {
			t.Error("Expected error for invalid destination data, got nil")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "empty.dat")

		// Create empty file
		err := os.WriteFile(filename, []byte{}, 0o644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		_, err = NewDestinationFromFile(file, crypto)
		if err == nil {
			t.Error("Expected error for empty file, got nil")
		}
	})
}
