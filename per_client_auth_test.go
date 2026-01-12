package go_i2cp

import (
	"testing"
	"time"
)

// TestNewPerClientAuthDH tests DH authentication config creation.
func TestNewPerClientAuthDH(t *testing.T) {
	tests := []struct {
		name        string
		key         []byte
		expectError bool
		errorSubstr string
	}{
		{
			name:        "valid 32-byte key",
			key:         make([]byte, 32),
			expectError: false,
		},
		{
			name:        "key too short",
			key:         make([]byte, 31),
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
		{
			name:        "key too long",
			key:         make([]byte, 33),
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
		{
			name:        "empty key",
			key:         []byte{},
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
		{
			name:        "nil key",
			key:         nil,
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewPerClientAuthDH(tt.key)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !containsSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if config == nil {
					t.Error("expected config, got nil")
				} else if config.AuthScheme != BLINDING_AUTH_SCHEME_DH {
					t.Errorf("expected auth scheme %d, got %d", BLINDING_AUTH_SCHEME_DH, config.AuthScheme)
				}
			}
		})
	}
}

// TestNewPerClientAuthPSK tests PSK authentication config creation.
func TestNewPerClientAuthPSK(t *testing.T) {
	tests := []struct {
		name        string
		key         []byte
		expectError bool
		errorSubstr string
	}{
		{
			name:        "valid 32-byte key",
			key:         make([]byte, 32),
			expectError: false,
		},
		{
			name:        "key too short",
			key:         make([]byte, 31),
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
		{
			name:        "key too long",
			key:         make([]byte, 33),
			expectError: true,
			errorSubstr: "must be exactly 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewPerClientAuthPSK(tt.key)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !containsSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if config == nil {
					t.Error("expected config, got nil")
				} else if config.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
					t.Errorf("expected auth scheme %d, got %d", BLINDING_AUTH_SCHEME_PSK, config.AuthScheme)
				}
			}
		})
	}
}

// TestGenerateRandomPrivateKey tests random key generation.
func TestGenerateRandomPrivateKey(t *testing.T) {
	key1, err := GenerateRandomPrivateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify key is non-zero
	allZero := true
	for _, b := range key1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("generated key should not be all zeros")
	}

	// Generate another key and verify they're different
	key2, err := GenerateRandomPrivateKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key1 == key2 {
		t.Error("two generated keys should be different")
	}
}

// TestPerClientAuthConfig_WithLookupPassword tests password configuration.
func TestPerClientAuthConfig_WithLookupPassword(t *testing.T) {
	config, err := NewPerClientAuthDH(make([]byte, 32))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test fluent interface
	result := config.WithLookupPassword("secret123")

	if result != config {
		t.Error("WithLookupPassword should return the same config for chaining")
	}
	if config.LookupPassword != "secret123" {
		t.Errorf("expected password %q, got %q", "secret123", config.LookupPassword)
	}
}

// TestNewBlindingInfoWithHash tests hash endpoint creation.
func TestNewBlindingInfoWithHash(t *testing.T) {
	expiration := uint32(time.Now().Unix())

	tests := []struct {
		name        string
		hash        []byte
		expectError bool
	}{
		{
			name:        "valid 32-byte hash",
			hash:        make([]byte, 32),
			expectError: false,
		},
		{
			name:        "hash too short",
			hash:        make([]byte, 31),
			expectError: true,
		},
		{
			name:        "hash too long",
			hash:        make([]byte, 33),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := NewBlindingInfoWithHash(tt.hash, 11, expiration)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Error("expected info, got nil")
				} else if info.EndpointType != BLINDING_ENDPOINT_HASH {
					t.Errorf("expected endpoint type %d, got %d", BLINDING_ENDPOINT_HASH, info.EndpointType)
				}
			}
		})
	}
}

// TestNewBlindingInfoWithHostname tests hostname endpoint creation.
func TestNewBlindingInfoWithHostname(t *testing.T) {
	expiration := uint32(time.Now().Unix())

	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{
			name:        "valid hostname",
			hostname:    "example.i2p",
			expectError: false,
		},
		{
			name:        "empty hostname",
			hostname:    "",
			expectError: true,
		},
		{
			name:        "hostname too long",
			hostname:    string(make([]byte, 256)),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := NewBlindingInfoWithHostname(tt.hostname, 11, expiration)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Error("expected info, got nil")
				} else if info.EndpointType != BLINDING_ENDPOINT_HOSTNAME {
					t.Errorf("expected endpoint type %d, got %d", BLINDING_ENDPOINT_HOSTNAME, info.EndpointType)
				}
			}
		})
	}
}

// TestNewBlindingInfoWithDestination tests destination endpoint creation.
func TestNewBlindingInfoWithDestination(t *testing.T) {
	expiration := uint32(time.Now().Unix())

	tests := []struct {
		name        string
		destBytes   []byte
		expectError bool
	}{
		{
			name:        "valid destination",
			destBytes:   make([]byte, 387),
			expectError: false,
		},
		{
			name:        "destination too short",
			destBytes:   make([]byte, 100),
			expectError: true,
		},
		{
			name:        "longer destination",
			destBytes:   make([]byte, 500),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := NewBlindingInfoWithDestination(tt.destBytes, 11, expiration)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Error("expected info, got nil")
				}
			}
		})
	}
}

// TestNewBlindingInfoWithSigningKey tests signing key endpoint creation.
func TestNewBlindingInfoWithSigningKey(t *testing.T) {
	expiration := uint32(time.Now().Unix())

	tests := []struct {
		name        string
		sigType     uint16
		sigKey      []byte
		expectError bool
	}{
		{
			name:        "valid Ed25519 key",
			sigType:     7, // Ed25519
			sigKey:      make([]byte, 32),
			expectError: false,
		},
		{
			name:        "valid DSA key",
			sigType:     0, // DSA
			sigKey:      make([]byte, 128),
			expectError: false,
		},
		{
			name:        "empty key",
			sigType:     7,
			sigKey:      []byte{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := NewBlindingInfoWithSigningKey(tt.sigType, tt.sigKey, 11, expiration)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if info == nil {
					t.Error("expected info, got nil")
				} else if info.EndpointType != BLINDING_ENDPOINT_SIGKEY {
					t.Errorf("expected endpoint type %d, got %d", BLINDING_ENDPOINT_SIGKEY, info.EndpointType)
				}
			}
		})
	}
}

// TestBlindingInfo_SetPerClientAuth tests per-client auth configuration.
func TestBlindingInfo_SetPerClientAuth(t *testing.T) {
	expiration := uint32(time.Now().Unix())
	info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, expiration)

	// Test nil config
	err := info.SetPerClientAuth(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}

	// Test valid DH config
	dhConfig, _ := NewPerClientAuthDH(make([]byte, 32))
	err = info.SetPerClientAuth(dhConfig)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !info.PerClientAuth {
		t.Error("expected PerClientAuth to be true")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_DH {
		t.Errorf("expected auth scheme %d, got %d", BLINDING_AUTH_SCHEME_DH, info.AuthScheme)
	}

	// Test valid PSK config with password
	info2, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, expiration)
	pskConfig, _ := NewPerClientAuthPSK(make([]byte, 32))
	pskConfig.WithLookupPassword("secret")
	err = info2.SetPerClientAuth(pskConfig)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if info2.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("expected auth scheme %d, got %d", BLINDING_AUTH_SCHEME_PSK, info2.AuthScheme)
	}
	if info2.LookupPassword != "secret" {
		t.Errorf("expected password %q, got %q", "secret", info2.LookupPassword)
	}
}

// TestBlindingInfo_ClearPerClientAuth tests clearing per-client auth.
func TestBlindingInfo_ClearPerClientAuth(t *testing.T) {
	info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, uint32(time.Now().Unix()))
	config, _ := NewPerClientAuthDH(make([]byte, 32))
	info.SetPerClientAuth(config)

	// Verify auth is set
	if !info.PerClientAuth {
		t.Error("expected PerClientAuth to be true before clear")
	}

	// Clear auth
	info.ClearPerClientAuth()

	if info.PerClientAuth {
		t.Error("expected PerClientAuth to be false after clear")
	}
	if info.DecryptionKey != nil {
		t.Error("expected DecryptionKey to be nil after clear")
	}
}

// TestBlindingInfo_IsPerClientAuthEnabled tests the enabled check.
func TestBlindingInfo_IsPerClientAuthEnabled(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*BlindingInfo)
		expected bool
	}{
		{
			name:     "not enabled",
			setup:    func(info *BlindingInfo) {},
			expected: false,
		},
		{
			name: "enabled with DH",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthDH(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			expected: true,
		},
		{
			name: "enabled with PSK",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthPSK(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			expected: true,
		},
		{
			name: "flag set but no key",
			setup: func(info *BlindingInfo) {
				info.PerClientAuth = true
				info.DecryptionKey = nil
			},
			expected: false,
		},
		{
			name: "flag set but short key",
			setup: func(info *BlindingInfo) {
				info.PerClientAuth = true
				info.DecryptionKey = make([]byte, 16)
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, uint32(time.Now().Unix()))
			tt.setup(info)

			if got := info.IsPerClientAuthEnabled(); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

// TestBlindingInfo_GetAuthSchemeName tests the human-readable scheme name.
func TestBlindingInfo_GetAuthSchemeName(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*BlindingInfo)
		expected string
	}{
		{
			name:     "no auth",
			setup:    func(info *BlindingInfo) {},
			expected: "none",
		},
		{
			name: "DH auth",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthDH(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			expected: "DH (Diffie-Hellman)",
		},
		{
			name: "PSK auth",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthPSK(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			expected: "PSK (Pre-Shared Key)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, uint32(time.Now().Unix()))
			tt.setup(info)

			if got := info.GetAuthSchemeName(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestBlindingInfo_String tests the string representation.
func TestBlindingInfo_String(t *testing.T) {
	info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, 1234567890)

	// Without auth
	str := info.String()
	if !containsSubstring(str, "BlindingInfo") {
		t.Error("expected BlindingInfo in string")
	}
	if !containsSubstring(str, "hash") {
		t.Error("expected 'hash' endpoint type in string")
	}
	if !containsSubstring(str, "no auth") {
		t.Error("expected 'no auth' in string")
	}

	// With DH auth
	config, _ := NewPerClientAuthDH(make([]byte, 32))
	info.SetPerClientAuth(config)
	str = info.String()
	if !containsSubstring(str, "DH") {
		t.Error("expected 'DH' in string with auth")
	}

	// With password
	info.LookupPassword = "secret"
	str = info.String()
	if !containsSubstring(str, "password") {
		t.Error("expected 'password' in string with password")
	}
}

// TestHandleHostReplyAuthError tests auth error handling.
func TestHandleHostReplyAuthError(t *testing.T) {
	tests := []struct {
		code          uint8
		expectMessage string
		expectAction  string
	}{
		{
			code:          HOST_REPLY_PASSWORD_REQUIRED,
			expectMessage: "password",
			expectAction:  "LookupPassword",
		},
		{
			code:          HOST_REPLY_PRIVATE_KEY_REQUIRED,
			expectMessage: "authentication required",
			expectAction:  "NewPerClientAuth",
		},
		{
			code:          HOST_REPLY_PASSWORD_AND_KEY_REQUIRED,
			expectMessage: "password and private key",
			expectAction:  "both",
		},
		{
			code:          HOST_REPLY_DECRYPTION_FAILURE,
			expectMessage: "decrypt",
			expectAction:  "credentials",
		},
		{
			code:          99,
			expectMessage: "Unknown",
			expectAction:  "specification",
		},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.code)), func(t *testing.T) {
			msg, action := HandleHostReplyAuthError(tt.code)

			if !containsSubstring(msg, tt.expectMessage) {
				t.Errorf("expected message containing %q, got %q", tt.expectMessage, msg)
			}
			if !containsSubstring(action, tt.expectAction) {
				t.Errorf("expected action containing %q, got %q", tt.expectAction, action)
			}
		})
	}
}

// TestClient_ValidatePerClientAuthSupport tests version validation.
func TestClient_ValidatePerClientAuthSupport(t *testing.T) {
	tests := []struct {
		name        string
		version     Version
		expectError bool
	}{
		{
			name:        "supported version",
			version:     Version{major: 0, minor: 9, micro: 43, qualifier: 0},
			expectError: false,
		},
		{
			name:        "newer version",
			version:     Version{major: 0, minor: 9, micro: 50, qualifier: 0},
			expectError: false,
		},
		{
			name:        "older version",
			version:     Version{major: 0, minor: 9, micro: 42, qualifier: 0},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			client.router.version = tt.version

			err := client.ValidatePerClientAuthSupport()

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPerClientAuth_EndToEndDH tests the DH auth workflow.
func TestPerClientAuth_EndToEndDH(t *testing.T) {
	// Generate a random private key
	privKey, err := GenerateRandomPrivateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create DH auth config
	authConfig, err := NewPerClientAuthDH(privKey[:])
	if err != nil {
		t.Fatalf("failed to create DH config: %v", err)
	}

	// Create BlindingInfo
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	expiration := uint32(time.Now().Add(24 * time.Hour).Unix())

	info, err := NewBlindingInfoWithHash(hash, 11, expiration)
	if err != nil {
		t.Fatalf("failed to create BlindingInfo: %v", err)
	}

	// Set per-client auth
	err = info.SetPerClientAuth(authConfig)
	if err != nil {
		t.Fatalf("failed to set auth: %v", err)
	}

	// Verify configuration
	if !info.IsPerClientAuthEnabled() {
		t.Error("expected per-client auth to be enabled")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_DH {
		t.Errorf("expected DH scheme, got %d", info.AuthScheme)
	}
	if len(info.DecryptionKey) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(info.DecryptionKey))
	}
}

// TestPerClientAuth_EndToEndPSK tests the PSK auth workflow.
func TestPerClientAuth_EndToEndPSK(t *testing.T) {
	// Use a fixed PSK
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i * 2)
	}

	// Create PSK auth config with password
	authConfig, err := NewPerClientAuthPSK(psk)
	if err != nil {
		t.Fatalf("failed to create PSK config: %v", err)
	}
	authConfig.WithLookupPassword("secretPassword")

	// Create BlindingInfo with hostname
	expiration := uint32(time.Now().Add(24 * time.Hour).Unix())
	info, err := NewBlindingInfoWithHostname("secret.i2p", 11, expiration)
	if err != nil {
		t.Fatalf("failed to create BlindingInfo: %v", err)
	}

	// Set per-client auth
	err = info.SetPerClientAuth(authConfig)
	if err != nil {
		t.Fatalf("failed to set auth: %v", err)
	}

	// Verify configuration
	if !info.IsPerClientAuthEnabled() {
		t.Error("expected per-client auth to be enabled")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("expected PSK scheme, got %d", info.AuthScheme)
	}
	if info.LookupPassword != "secretPassword" {
		t.Errorf("expected password 'secretPassword', got %q", info.LookupPassword)
	}

	// Test string representation
	str := info.String()
	if !containsSubstring(str, "PSK") {
		t.Error("expected 'PSK' in string representation")
	}
	if !containsSubstring(str, "password") {
		t.Error("expected 'password' in string representation")
	}
}

// TestPerClientAuth_FlagConstruction tests that flags are built correctly.
func TestPerClientAuth_FlagConstruction(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name          string
		setup         func(*BlindingInfo)
		expectedFlags uint8
	}{
		{
			name:          "no auth no password",
			setup:         func(info *BlindingInfo) {},
			expectedFlags: 0x00,
		},
		{
			name: "DH auth only",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthDH(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			// Bit 0 set (per-client), bits 3-1 = 000 (DH)
			expectedFlags: 0x01,
		},
		{
			name: "PSK auth only",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthPSK(make([]byte, 32))
				info.SetPerClientAuth(config)
			},
			// Bit 0 set (per-client), bits 3-1 = 001 (PSK)
			expectedFlags: 0x03,
		},
		{
			name: "password only",
			setup: func(info *BlindingInfo) {
				info.LookupPassword = "secret"
			},
			// Bit 4 set (secret required)
			expectedFlags: 0x10,
		},
		{
			name: "DH auth with password",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthDH(make([]byte, 32))
				config.WithLookupPassword("secret")
				info.SetPerClientAuth(config)
			},
			// Bit 0 set (per-client), bits 3-1 = 000 (DH), bit 4 set (secret)
			expectedFlags: 0x11,
		},
		{
			name: "PSK auth with password",
			setup: func(info *BlindingInfo) {
				config, _ := NewPerClientAuthPSK(make([]byte, 32))
				config.WithLookupPassword("secret")
				info.SetPerClientAuth(config)
			},
			// Bit 0 set (per-client), bits 3-1 = 001 (PSK), bit 4 set (secret)
			expectedFlags: 0x13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, _ := NewBlindingInfoWithHash(make([]byte, 32), 11, uint32(time.Now().Unix()))
			tt.setup(info)

			flags := client.buildBlindingFlags(info)
			if flags != tt.expectedFlags {
				t.Errorf("expected flags 0x%02x, got 0x%02x", tt.expectedFlags, flags)
			}
		})
	}
}

// Note: containsSubstring helper is defined in circuit_breaker_test.go
