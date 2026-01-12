package go_i2cp

import (
	"testing"
)

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
