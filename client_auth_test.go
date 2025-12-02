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
