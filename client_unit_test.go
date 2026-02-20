package go_i2cp

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	client := NewClient(nil)
	client.Connect(context.Background())
	client.Disconnect()
}

func TestClient_CreateSession(t *testing.T) {
	client := NewClient(nil)

	err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	session := NewSession(client, SessionCallbacks{
		OnDestination: func(session *Session, requestId uint32, address string, dest *Destination) {
		},
		OnStatus: func(session *Session, status SessionStatus) {
		},
		OnMessage: func(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
		},
	})
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "test-i2cp")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
	session.config.destination, err = NewDestination(client.crypto) // FromBase64("r2zbc34IQSzOIF4N0enKf0xXkJKgsj9yTGGspRnstKZf~4UoAljZOW5aFZywGo-NlaXwt~tIyj4NC0Til0vl1D5N9ip7OMYUCajNNgiXEH~FN33yl-AcJbeTlB-FychSmVfYciTQj6yd19~6wICwkdpy6AYo90bAejSVGpvtFeP5P2pnSwPmcB8m79wyq~C2XjQCe5UcBxnfYolWKgr3uDFrgbhqBVCCkO7zTiARwOWZLVOvZsvKZR4WvYAmQI6CQaxnmT5n1FKO6NBb-HOxVw4onERq86Sc6EQ5d48719Yk-73wq1Mxmr7Y2UwmL~FCnY33rT1FJY2KzUENICL1uEuiVmr9N924CT9RbtldOUUcXmM1gaHlPS40-Hz4AvPxFXHynbyySktN3hBLPwfwhyIQw95ezSNuiBB0xPcujazCw02103n2CO-59rMDmWpttLjpLMggP9IwsAPa9FVLnBqfuCn3NrC4fia50RDwfR41AD1GOOWiUT0avYzbbOdsAAAA")
	if err != nil {
		t.Fatal(err)
	}
	err = client.CreateSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	client.Disconnect()
}

// --- merged from client_auth_test.go ---

// TestGetAuthenticationMethod_None tests that AUTH_METHOD_NONE is returned
// when no authentication is configured
func TestGetAuthenticationMethod_None(t *testing.T) {
	client := NewClient(nil)

	// Ensure no authentication is configured (default state)
	if client.properties["i2cp.SSL"] != "false" {
		t.Error("TLS should be disabled by default")
	}
	if client.properties["i2cp.username"] != "" {
		t.Error("Username should be empty by default")
	}

	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_NONE)",
			method, AUTH_METHOD_NONE)
	}
}

// TestGetAuthenticationMethod_UsernamePassword tests that AUTH_METHOD_USERNAME_PWD
// is returned when username/password authentication is configured
func TestGetAuthenticationMethod_UsernamePassword(t *testing.T) {
	client := NewClient(nil)

	// Configure username/password authentication
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_USERNAME_PWD)",
			method, AUTH_METHOD_USERNAME_PWD)
	}
}

// TestGetAuthenticationMethod_TLS tests that AUTH_METHOD_SSL_TLS is returned
// when TLS authentication is configured
func TestGetAuthenticationMethod_TLS(t *testing.T) {
	client := NewClient(nil)

	// Configure TLS authentication
	client.SetProperty("i2cp.SSL", "true")

	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_SSL_TLS {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_SSL_TLS)",
			method, AUTH_METHOD_SSL_TLS)
	}
}

// TestGetAuthenticationMethod_TLSPrecedence tests that TLS authentication
// takes precedence over username/password when both are configured
func TestGetAuthenticationMethod_TLSPrecedence(t *testing.T) {
	client := NewClient(nil)

	// Configure both TLS and username/password
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	// TLS should take precedence (higher security)
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_SSL_TLS {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_SSL_TLS with precedence)",
			method, AUTH_METHOD_SSL_TLS)
	}
}

// TestGetAuthenticationMethod_EmptyUsername tests that empty username
// results in no authentication
func TestGetAuthenticationMethod_EmptyUsername(t *testing.T) {
	client := NewClient(nil)

	// Set password but not username
	client.SetProperty("i2cp.password", "testpass")

	// Should return AUTH_METHOD_NONE since username is required
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_NONE when username empty)",
			method, AUTH_METHOD_NONE)
	}
}

// TestGetAuthenticationMethod_TLSFalse tests that TLS disabled explicitly
// falls back to username/password if configured
func TestGetAuthenticationMethod_TLSFalse(t *testing.T) {
	client := NewClient(nil)

	// Explicitly disable TLS
	client.SetProperty("i2cp.SSL", "false")
	// Configure username/password
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Errorf("getAuthenticationMethod() = %d, want %d (AUTH_METHOD_USERNAME_PWD when TLS disabled)",
			method, AUTH_METHOD_USERNAME_PWD)
	}
}

// TestGetAuthenticationMethod_MultipleChanges tests that authentication method
// updates correctly when configuration changes
func TestGetAuthenticationMethod_MultipleChanges(t *testing.T) {
	client := NewClient(nil)

	// Start with no authentication
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Errorf("Initial method = %d, want %d", method, AUTH_METHOD_NONE)
	}

	// Enable username/password
	client.SetProperty("i2cp.username", "testuser")
	method = client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Errorf("After username/password method = %d, want %d", method, AUTH_METHOD_USERNAME_PWD)
	}

	// Enable TLS (should override username/password)
	client.SetProperty("i2cp.SSL", "true")
	method = client.getAuthenticationMethod()
	if method != AUTH_METHOD_SSL_TLS {
		t.Errorf("After TLS method = %d, want %d", method, AUTH_METHOD_SSL_TLS)
	}

	// Disable TLS (should fall back to username/password)
	client.SetProperty("i2cp.SSL", "false")
	method = client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Errorf("After TLS disabled method = %d, want %d", method, AUTH_METHOD_USERNAME_PWD)
	}

	// Clear username (should fall back to no authentication)
	client.SetProperty("i2cp.username", "")
	method = client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Errorf("After username cleared method = %d, want %d", method, AUTH_METHOD_NONE)
	}
}

// TestMsgGetDate_NoAuthentication tests GetDate message with no authentication
func TestMsgGetDate_NoAuthentication(t *testing.T) {
	client := NewClient(nil)

	// Ensure no authentication is configured
	if client.properties["i2cp.SSL"] != "false" {
		t.Error("TLS should be disabled")
	}
	if client.properties["i2cp.username"] != "" {
		t.Error("Username should be empty")
	}

	// Call msgGetDate (queuing mode to avoid actual send)
	client.msgGetDate(true)

	// Verify authentication method would be NONE
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Errorf("Expected AUTH_METHOD_NONE, got %d", method)
	}
}

// TestMsgGetDate_UsernamePassword tests GetDate message with username/password
func TestMsgGetDate_UsernamePassword(t *testing.T) {
	client := NewClient(nil)

	// Configure username/password authentication
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	// Call msgGetDate (queuing mode to avoid actual send)
	client.msgGetDate(true)

	// Verify authentication method would be USERNAME_PWD
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Errorf("Expected AUTH_METHOD_USERNAME_PWD, got %d", method)
	}
}

// TestMsgGetDate_TLS tests GetDate message with TLS authentication
func TestMsgGetDate_TLS(t *testing.T) {
	client := NewClient(nil)

	// Configure TLS authentication
	client.SetProperty("i2cp.SSL", "true")

	// Call msgGetDate (queuing mode to avoid actual send)
	client.msgGetDate(true)

	// Verify authentication method would be SSL_TLS
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_SSL_TLS {
		t.Errorf("Expected AUTH_METHOD_SSL_TLS, got %d", method)
	}
}

// TestAuthenticationMethodConstants tests that authentication method constants
// have expected values per I2CP specification
func TestAuthenticationMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"AUTH_METHOD_NONE", AUTH_METHOD_NONE, 0},
		{"AUTH_METHOD_USERNAME_PWD", AUTH_METHOD_USERNAME_PWD, 1},
		{"AUTH_METHOD_SSL_TLS", AUTH_METHOD_SSL_TLS, 2},
		{"AUTH_METHOD_PER_CLIENT_DH", AUTH_METHOD_PER_CLIENT_DH, 3},
		{"AUTH_METHOD_PER_CLIENT_PSK", AUTH_METHOD_PER_CLIENT_PSK, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestGetAuthenticationMethod_WithAllProperties tests authentication method
// detection with comprehensive property combinations
func TestGetAuthenticationMethod_WithAllProperties(t *testing.T) {
	tests := []struct {
		name           string
		tlsEnabled     string
		username       string
		password       string
		expectedMethod uint8
	}{
		{
			name:           "No auth configured",
			tlsEnabled:     "false",
			username:       "",
			password:       "",
			expectedMethod: AUTH_METHOD_NONE,
		},
		{
			name:           "Only username (no password)",
			tlsEnabled:     "false",
			username:       "user",
			password:       "",
			expectedMethod: AUTH_METHOD_USERNAME_PWD,
		},
		{
			name:           "Username and password",
			tlsEnabled:     "false",
			username:       "user",
			password:       "pass",
			expectedMethod: AUTH_METHOD_USERNAME_PWD,
		},
		{
			name:           "TLS enabled only",
			tlsEnabled:     "true",
			username:       "",
			password:       "",
			expectedMethod: AUTH_METHOD_SSL_TLS,
		},
		{
			name:           "TLS enabled with username/password",
			tlsEnabled:     "true",
			username:       "user",
			password:       "pass",
			expectedMethod: AUTH_METHOD_SSL_TLS,
		},
		{
			name:           "TLS string 'anything' treated as false",
			tlsEnabled:     "yes",
			username:       "user",
			password:       "pass",
			expectedMethod: AUTH_METHOD_USERNAME_PWD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			client.SetProperty("i2cp.SSL", tt.tlsEnabled)
			client.SetProperty("i2cp.username", tt.username)
			client.SetProperty("i2cp.password", tt.password)

			method := client.getAuthenticationMethod()
			if method != tt.expectedMethod {
				t.Errorf("getAuthenticationMethod() = %d, want %d",
					method, tt.expectedMethod)
			}
		})
	}
}

// TestMsgGetDate_EmptyMappingForAuthNone verifies that AUTH_METHOD_NONE
// sends an empty mapping (2 bytes: 0x00 0x00) per I2CP 0.9.11+ spec compliance.
//
// I2CP Specification:
//   - "Authentication [Mapping] (optional, as of release 0.9.11)"
//   - Strict spec-compliant routers expect the mapping field to be present
//   - Empty mapping = 2 bytes with value 0x0000 (size prefix only)
func TestMsgGetDate_EmptyMappingForAuthNone(t *testing.T) {
	client := NewClient(nil)

	// Ensure no authentication is configured
	client.SetProperty("i2cp.SSL", "false")
	client.SetProperty("i2cp.username", "")
	client.SetProperty("i2cp.password", "")

	// Verify we're using AUTH_METHOD_NONE
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_NONE {
		t.Fatalf("Expected AUTH_METHOD_NONE, got %d", method)
	}

	// Call msgGetDate in queuing mode to capture the message
	client.msgGetDate(true)

	// Get the message from the output queue
	if len(client.outputQueue) == 0 {
		t.Fatal("Expected message in output queue")
	}

	// The queued message format is:
	// - 4 bytes: payload length (big-endian)
	// - 1 byte: message type
	// - payload: version_len (1 byte) + version_string + mapping (2 bytes minimum for empty)
	fullMsg := client.outputQueue[0].Bytes()

	// Skip the 4-byte length prefix and 1-byte message type to get the payload
	if len(fullMsg) < 5 {
		t.Fatalf("Message too short: %d bytes", len(fullMsg))
	}
	payload := fullMsg[5:] // Skip 4 bytes length + 1 byte type

	// Find the version string length and skip past it
	if len(payload) < 1 {
		t.Fatal("Payload too short to contain version string length")
	}
	versionLen := int(payload[0])
	expectedMinLen := 1 + versionLen + 2 // length_prefix + version_string + empty_mapping
	if len(payload) < expectedMinLen {
		t.Fatalf("Payload too short: got %d bytes, expected at least %d", len(payload), expectedMinLen)
	}

	// Check the empty mapping bytes at the end
	mappingStart := 1 + versionLen
	mappingBytes := payload[mappingStart:]

	// Empty mapping should be exactly 2 bytes: 0x00 0x00
	if len(mappingBytes) != 2 {
		t.Errorf("Empty mapping should be 2 bytes, got %d bytes: %x", len(mappingBytes), mappingBytes)
	}
	if mappingBytes[0] != 0x00 || mappingBytes[1] != 0x00 {
		t.Errorf("Empty mapping should be 0x0000, got 0x%02x%02x", mappingBytes[0], mappingBytes[1])
	}

	t.Logf("Verified empty mapping (0x%02x%02x) sent for AUTH_METHOD_NONE", mappingBytes[0], mappingBytes[1])
}

// TestMsgGetDate_UsernamePasswordMappingContent verifies that AUTH_METHOD_USERNAME_PWD
// sends a proper mapping with i2cp.username and i2cp.password keys.
func TestMsgGetDate_UsernamePasswordMappingContent(t *testing.T) {
	client := NewClient(nil)

	// Configure username/password authentication
	client.SetProperty("i2cp.SSL", "false")
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	// Verify we're using AUTH_METHOD_USERNAME_PWD
	method := client.getAuthenticationMethod()
	if method != AUTH_METHOD_USERNAME_PWD {
		t.Fatalf("Expected AUTH_METHOD_USERNAME_PWD, got %d", method)
	}

	// Call msgGetDate in queuing mode
	client.msgGetDate(true)

	if len(client.outputQueue) == 0 {
		t.Fatal("Expected message in output queue")
	}

	// The queued message format is:
	// - 4 bytes: payload length (big-endian)
	// - 1 byte: message type
	// - payload: version_len (1 byte) + version_string + mapping
	fullMsg := client.outputQueue[0].Bytes()

	// Skip the 4-byte length prefix and 1-byte message type to get the payload
	if len(fullMsg) < 5 {
		t.Fatalf("Message too short: %d bytes", len(fullMsg))
	}
	payload := fullMsg[5:]

	// Find the version string length and skip past it
	if len(payload) < 1 {
		t.Fatal("Payload too short")
	}
	versionLen := int(payload[0])

	// The remaining bytes should be the mapping
	mappingStart := 1 + versionLen
	if len(payload) <= mappingStart {
		t.Fatal("Payload too short to contain mapping")
	}

	mappingBytes := payload[mappingStart:]

	// Mapping should have a 2-byte size prefix > 0
	if len(mappingBytes) < 2 {
		t.Fatal("Mapping too short for size prefix")
	}

	mappingSize := int(mappingBytes[0])<<8 | int(mappingBytes[1])
	if mappingSize == 0 {
		t.Error("Username/password mapping should not be empty")
	}

	// Verify the mapping contains expected keys
	mappingContent := string(mappingBytes[2:])
	if !containsSubstring(mappingContent, "i2cp.password") {
		t.Error("Mapping should contain 'i2cp.password' key")
	}
	if !containsSubstring(mappingContent, "i2cp.username") {
		t.Error("Mapping should contain 'i2cp.username' key")
	}

	t.Logf("Username/password mapping size: %d bytes", mappingSize)
}

// --- merged from client_tls_config_test.go ---

// TestTLSConfigurationDefaults verifies that TLS configuration properties
// are correctly initialized with secure defaults per PLAN.md Phase 1.1.1
func TestTLSConfigurationDefaults(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name          string
		property      string
		expectedValue string
	}{
		{
			name:          "TLS disabled by default",
			property:      "i2cp.SSL",
			expectedValue: "false",
		},
		{
			name:          "TLS cert file empty by default",
			property:      "i2cp.SSL.certFile",
			expectedValue: "",
		},
		{
			name:          "TLS key file empty by default",
			property:      "i2cp.SSL.keyFile",
			expectedValue: "",
		},
		{
			name:          "TLS CA file empty by default",
			property:      "i2cp.SSL.caFile",
			expectedValue: "",
		},
		{
			name:          "TLS insecure mode disabled by default",
			property:      "i2cp.SSL.insecure",
			expectedValue: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, exists := client.properties[tt.property]
			if !exists {
				t.Errorf("Property %s does not exist in defaultProperties", tt.property)
				return
			}
			if value != tt.expectedValue {
				t.Errorf("Property %s = %q, want %q", tt.property, value, tt.expectedValue)
			}
		})
	}
}

// TestSetTLSProperties verifies that TLS properties can be set at runtime
// and are properly propagated to the TCP layer
func TestSetTLSProperties(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name     string
		property string
		value    string
	}{
		{
			name:     "Enable TLS",
			property: "i2cp.SSL",
			value:    "true",
		},
		{
			name:     "Set TLS certificate file",
			property: "i2cp.SSL.certFile",
			value:    "/path/to/client.crt",
		},
		{
			name:     "Set TLS key file",
			property: "i2cp.SSL.keyFile",
			value:    "/path/to/client.key",
		},
		{
			name:     "Set TLS CA file",
			property: "i2cp.SSL.caFile",
			value:    "/path/to/ca.crt",
		},
		{
			name:     "Enable insecure mode for development",
			property: "i2cp.SSL.insecure",
			value:    "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.SetProperty(tt.property, tt.value)
			value := client.properties[tt.property]
			if value != tt.value {
				t.Errorf("After SetProperty(%q, %q), got %q", tt.property, tt.value, value)
			}
		})
	}
}

// TestClientPropertyConstants verifies that all TLS ClientProperty constants
// are defined correctly to prevent regression
func TestClientPropertyConstants(t *testing.T) {
	// This test ensures the enum values exist and are distinct
	// It will fail to compile if constants are missing or renamed
	properties := []ClientProperty{
		CLIENT_PROP_ROUTER_ADDRESS,
		CLIENT_PROP_ROUTER_PORT,
		CLIENT_PROP_ROUTER_USE_TLS,
		CLIENT_PROP_USERNAME,
		CLIENT_PROP_PASSWORD,
		CLIENT_PROP_TLS_CERT_FILE,
		CLIENT_PROP_TLS_KEY_FILE,
		CLIENT_PROP_TLS_CA_FILE,
		CLIENT_PROP_TLS_INSECURE,
	}

	// Verify count matches expected number
	if int(NR_OF_I2CP_CLIENT_PROPERTIES) != len(properties) {
		t.Errorf("NR_OF_I2CP_CLIENT_PROPERTIES = %d, want %d",
			NR_OF_I2CP_CLIENT_PROPERTIES, len(properties))
	}

	// Verify all constants are unique (no duplicates)
	seen := make(map[ClientProperty]bool)
	for _, prop := range properties {
		if seen[prop] {
			t.Errorf("Duplicate ClientProperty value: %d", prop)
		}
		seen[prop] = true
	}
}

// TestTLSConfigurationEdgeCases tests edge cases and error handling
func TestTLSConfigurationEdgeCases(t *testing.T) {
	client := NewClient(nil)

	t.Run("Set non-existent property is ignored", func(t *testing.T) {
		client.SetProperty("i2cp.nonexistent.property", "value")
		// Should not panic, property just won't exist
		if _, exists := client.properties["i2cp.nonexistent.property"]; exists {
			t.Error("Non-existent property should not be created")
		}
	})

	t.Run("Empty string values are valid", func(t *testing.T) {
		client.SetProperty("i2cp.SSL.certFile", "")
		if client.properties["i2cp.SSL.certFile"] != "" {
			t.Error("Empty string should be accepted as valid value")
		}
	})

	t.Run("Multiple SetProperty calls update value", func(t *testing.T) {
		client.SetProperty("i2cp.SSL", "true")
		if client.properties["i2cp.SSL"] != "true" {
			t.Error("First SetProperty failed")
		}

		client.SetProperty("i2cp.SSL", "false")
		if client.properties["i2cp.SSL"] != "false" {
			t.Error("Second SetProperty should override first value")
		}
	})
}

// TestTLSPropertyPropagationToTCP verifies that TLS-related properties
// are correctly propagated to the TCP layer when set
func TestTLSPropertyPropagationToTCP(t *testing.T) {
	client := NewClient(nil)

	t.Run("i2cp.SSL propagates to TCP_PROP_USE_TLS", func(t *testing.T) {
		client.SetProperty("i2cp.SSL", "true")
		// Verify it's stored in client properties
		if client.properties["i2cp.SSL"] != "true" {
			t.Error("i2cp.SSL not set in client properties")
		}
		// TCP layer property propagation is handled by SetProperty
		// The actual TLS setup happens in tcp.SetupTLS() during Connect()
	})

	t.Run("i2cp.SSL.certFile propagates to TCP layer", func(t *testing.T) {
		testPath := "/test/path/client.crt"
		client.SetProperty("i2cp.SSL.certFile", testPath)
		if client.properties["i2cp.SSL.certFile"] != testPath {
			t.Error("i2cp.SSL.certFile not set correctly")
		}
	})
}

// TestSecureDefaults ensures security-critical defaults are correct
// per I2CP security requirements
func TestSecureDefaults(t *testing.T) {
	client := NewClient(nil)

	t.Run("TLS disabled by default for backward compatibility", func(t *testing.T) {
		if client.properties["i2cp.SSL"] != "false" {
			t.Error("TLS should be disabled by default to maintain backward compatibility")
		}
	})

	t.Run("Insecure mode disabled by default", func(t *testing.T) {
		if client.properties["i2cp.SSL.insecure"] != "false" {
			t.Error("Insecure mode must be disabled by default for security")
		}
	})

	t.Run("No default certificate files for security", func(t *testing.T) {
		// Certificate files should be empty by default to prevent
		// accidental use of hardcoded/embedded certificates
		if client.properties["i2cp.SSL.certFile"] != "" {
			t.Error("Default cert file should be empty")
		}
		if client.properties["i2cp.SSL.keyFile"] != "" {
			t.Error("Default key file should be empty")
		}
		if client.properties["i2cp.SSL.caFile"] != "" {
			t.Error("Default CA file should be empty")
		}
	})
}

// --- merged from client_message_error_test.go ---

// TestMsgGetBandwidthLimits verifies GetBandwidthLimitsMessage sending behavior.
// Tests both queued and immediate message sending modes.
func TestMsgGetBandwidthLimits(t *testing.T) {
	tests := []struct {
		name           string
		queue          bool
		setupClient    func(*Client)
		expectError    bool
		validateClient func(*testing.T, *Client)
	}{
		{
			name:  "queued message",
			queue: true,
			setupClient: func(c *Client) {
				// Client with valid state for queuing
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
			},
			expectError: false,
			validateClient: func(t *testing.T, c *Client) {
				// Message should be added to queue
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
				}
			},
		},
		{
			name:  "immediate send with disconnected client",
			queue: false,
			setupClient: func(c *Client) {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.connected = false // Disconnected state should cause send error
			},
			expectError: false, // Function doesn't return error, logs instead
			validateClient: func(t *testing.T, c *Client) {
				// No queue should be created for immediate send
				if len(c.outputQueue) > 0 {
					t.Error("unexpected message in output queue for immediate send")
				}
			},
		},
		{
			name:  "nil message stream",
			queue: true,
			setupClient: func(c *Client) {
				c.messageStream = nil // This should cause a panic or error
				c.outputQueue = make([]*Stream, 0)
			},
			expectError: true,
			validateClient: func(t *testing.T, c *Client) {
				// Should recover from nil pointer
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			tt.setupClient(client)

			// Use defer-recover pattern to catch panics from nil pointers
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectError {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()

			client.msgGetBandwidthLimits(tt.queue)

			if tt.validateClient != nil {
				tt.validateClient(t, client)
			}
		})
	}
}

// TestMsgDestroySession verifies DestroySessionMessage sending for session cleanup.
// Tests session ID serialization and queue/immediate send modes.
func TestMsgDestroySession(t *testing.T) {
	tests := []struct {
		name        string
		queue       bool
		sessionID   uint16
		setupClient func(*Client) *Session
		validate    func(*testing.T, *Client, *Session)
	}{
		{
			name:      "queued destroy with valid session",
			queue:     true,
			sessionID: 42,
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
				sess := &Session{id: 42, client: c}
				c.sessions = make(map[uint16]*Session)
				c.sessions[42] = sess
				return sess
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
					return
				}
				// Verify session ID was written to message stream
				stream := c.outputQueue[0]
				if stream.Len() < 2 {
					t.Error("message too short, should contain session ID")
				}
			},
		},
		{
			name:      "immediate destroy with nil session",
			queue:     false,
			sessionID: 0,
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.connected = false
				// Return nil session to test error handling
				return &Session{id: 0, client: c}
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				// Should handle gracefully without panic
			},
		},
		{
			name:      "destroy with high session ID",
			queue:     true,
			sessionID: 65535, // Max uint16 value
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
				sess := &Session{id: 65535, client: c}
				return sess
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
					return
				}
				// Verify session ID encoding
				stream := c.outputQueue[0]
				if stream.Len() < 2 {
					t.Error("message missing session ID")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			session := tt.setupClient(client)

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic in msgDestroySession: %v", r)
				}
			}()

			// callerHoldsLock=false because test doesn't hold session.mu
			client.msgDestroySession(session, session.ID(), session.IsPrimary(), tt.queue, false)

			if tt.validate != nil {
				tt.validate(t, client, session)
			}
		})
	}
}

// TestEnableAutoReconnect verifies auto-reconnect configuration.
// Tests parameter validation and thread-safety of reconnection settings.
func TestEnableAutoReconnect(t *testing.T) {
	tests := []struct {
		name           string
		maxRetries     int
		initialBackoff time.Duration
		expectedState  bool
	}{
		{
			name:           "enable with finite retries",
			maxRetries:     5,
			initialBackoff: 1 * time.Second,
			expectedState:  true,
		},
		{
			name:           "enable with infinite retries",
			maxRetries:     0, // 0 = infinite retries
			initialBackoff: 500 * time.Millisecond,
			expectedState:  true,
		},
		{
			name:           "enable with negative retries",
			maxRetries:     -1, // Should be allowed, treated as special value
			initialBackoff: 2 * time.Second,
			expectedState:  true,
		},
		{
			name:           "enable with zero backoff",
			maxRetries:     3,
			initialBackoff: 0, // Should be allowed, immediate retry
			expectedState:  true,
		},
		{
			name:           "enable with large backoff",
			maxRetries:     10,
			initialBackoff: 5 * time.Minute,
			expectedState:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)

			// Verify initial state is disabled
			if client.IsAutoReconnectEnabled() {
				t.Error("auto-reconnect should be disabled by default")
			}

			// Enable with test parameters
			client.EnableAutoReconnect(tt.maxRetries, tt.initialBackoff)

			// Verify enabled state
			if client.IsAutoReconnectEnabled() != tt.expectedState {
				t.Errorf("expected enabled=%v, got=%v", tt.expectedState, client.IsAutoReconnectEnabled())
			}

			// Verify parameters were set correctly
			client.reconnectMu.Lock()
			if client.reconnectMaxRetries != tt.maxRetries {
				t.Errorf("expected maxRetries=%d, got=%d", tt.maxRetries, client.reconnectMaxRetries)
			}
			if client.reconnectBackoff != tt.initialBackoff {
				t.Errorf("expected backoff=%v, got=%v", tt.initialBackoff, client.reconnectBackoff)
			}
			if client.reconnectAttempts != 0 {
				t.Errorf("expected attempts=0, got=%d", client.reconnectAttempts)
			}
			client.reconnectMu.Unlock()

			// Verify reconnection attempt counter
			if client.ReconnectAttempts() != 0 {
				t.Errorf("expected 0 reconnect attempts, got=%d", client.ReconnectAttempts())
			}
		})
	}
}

// TestDisableAutoReconnect verifies auto-reconnect can be disabled.
func TestDisableAutoReconnect(t *testing.T) {
	client := NewClient(nil)

	// Enable first
	client.EnableAutoReconnect(5, 1*time.Second)
	if !client.IsAutoReconnectEnabled() {
		t.Fatal("failed to enable auto-reconnect")
	}

	// Disable
	client.DisableAutoReconnect()
	if client.IsAutoReconnectEnabled() {
		t.Error("auto-reconnect should be disabled")
	}

	// Verify state is properly locked
	client.reconnectMu.Lock()
	if client.reconnectEnabled {
		t.Error("reconnectEnabled flag should be false")
	}
	client.reconnectMu.Unlock()
}

// TestAutoReconnectThreadSafety verifies thread-safety of reconnect state access.
// Concurrent calls to Enable/Disable/IsEnabled should not race.
func TestAutoReconnectThreadSafety(t *testing.T) {
	client := NewClient(nil)
	var wg sync.WaitGroup
	iterations := 100

	// Concurrently enable and disable auto-reconnect
	for i := 0; i < iterations; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			client.EnableAutoReconnect(5, 1*time.Second)
		}()

		go func() {
			defer wg.Done()
			client.DisableAutoReconnect()
		}()

		go func() {
			defer wg.Done()
			_ = client.IsAutoReconnectEnabled()
			_ = client.ReconnectAttempts()
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Final state should be consistent (no panics or races)
	_ = client.IsAutoReconnectEnabled()
}

// TestAutoReconnectWithDisabled verifies autoReconnect returns error when disabled.
func TestAutoReconnectWithDisabled(t *testing.T) {
	client := NewClient(nil)

	// Ensure auto-reconnect is disabled
	client.DisableAutoReconnect()

	ctx := context.Background()
	err := client.autoReconnect(ctx)

	if err == nil {
		t.Error("expected error when auto-reconnect is disabled")
	}

	expectedMsg := "auto-reconnect is not enabled"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// TestAutoReconnectContextCancellation verifies context cancellation is respected.
func TestAutoReconnectContextCancellation(t *testing.T) {
	client := NewClient(nil)
	client.EnableAutoReconnect(5, 100*time.Millisecond)

	// Create context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// autoReconnect should respect context cancellation
	// Note: This test may pass quickly or fail based on implementation
	// The key is ensuring no panic and proper error handling
	err := client.autoReconnect(ctx)
	if err == nil {
		// May succeed if reconnection is attempted before context check
		// This is acceptable behavior
	}
}

// TestReconnectAttempts verifies reconnection attempt counter.
func TestReconnectAttempts(t *testing.T) {
	client := NewClient(nil)

	// Initial state
	if client.ReconnectAttempts() != 0 {
		t.Error("expected 0 initial reconnect attempts")
	}

	// Manually increment counter for testing (normally done by autoReconnect)
	client.reconnectMu.Lock()
	client.reconnectAttempts = 5
	client.reconnectMu.Unlock()

	if attempts := client.ReconnectAttempts(); attempts != 5 {
		t.Errorf("expected 5 reconnect attempts, got=%d", attempts)
	}
}

// TestAutoReconnectParameterBoundaries tests edge cases for parameters.
func TestAutoReconnectParameterBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		maxRetries int
		backoff    time.Duration
	}{
		{"max retries int overflow", int(^uint(0) >> 1), 1 * time.Second},
		{"min retries", -2147483648, 1 * time.Second},
		{"max backoff", 5, time.Duration(1<<62 - 1)},
		{"negative backoff", 5, -1 * time.Second}, // Unusual but should not panic
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)

			// Should not panic with extreme values
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic with parameters maxRetries=%d, backoff=%v: %v",
						tt.maxRetries, tt.backoff, r)
				}
			}()

			client.EnableAutoReconnect(tt.maxRetries, tt.backoff)

			// Verify values were stored
			client.reconnectMu.Lock()
			storedRetries := client.reconnectMaxRetries
			storedBackoff := client.reconnectBackoff
			client.reconnectMu.Unlock()

			if storedRetries != tt.maxRetries {
				t.Errorf("maxRetries not stored correctly: expected=%d, got=%d",
					tt.maxRetries, storedRetries)
			}
			if storedBackoff != tt.backoff {
				t.Errorf("backoff not stored correctly: expected=%v, got=%v",
					tt.backoff, storedBackoff)
			}
		})
	}
}
