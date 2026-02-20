package go_i2cp

import (
	"encoding/base64"
	"testing"
	"time"
)

// TestOfflineSignature_SetOfflineSignature tests the SetOfflineSignature method
func TestOfflineSignature_SetOfflineSignature(t *testing.T) {
	tests := []struct {
		name               string
		expiration         uint32
		transientPublicKey []byte
		signature          []byte
		wantErr            bool
		errContains        string
	}{
		{
			name:               "Valid configuration",
			expiration:         uint32(time.Now().Unix()) + 3600, // 1 hour from now
			transientPublicKey: []byte("fake-transient-public-key-32bytes"),
			signature:          []byte("fake-signature-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
			wantErr:            false,
		},
		{
			name:               "Empty transient public key",
			expiration:         uint32(time.Now().Unix()) + 3600,
			transientPublicKey: nil,
			signature:          []byte("fake-signature"),
			wantErr:            true,
			errContains:        "transient public key cannot be empty",
		},
		{
			name:               "Empty signature",
			expiration:         uint32(time.Now().Unix()) + 3600,
			transientPublicKey: []byte("fake-key"),
			signature:          nil,
			wantErr:            true,
			errContains:        "offline signature cannot be empty",
		},
		{
			name:               "Zero expiration",
			expiration:         0,
			transientPublicKey: []byte("fake-key"),
			signature:          []byte("fake-signature"),
			wantErr:            true,
			errContains:        "expiration timestamp cannot be zero",
		},
		{
			name:               "Expired timestamp",
			expiration:         uint32(time.Now().Unix()) - 3600, // 1 hour ago
			transientPublicKey: []byte("fake-key"),
			signature:          []byte("fake-signature"),
			wantErr:            true,
			errContains:        "in the past",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SessionConfig{}
			err := config.SetOfflineSignature(tt.expiration, tt.transientPublicKey, tt.signature)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetOfflineSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("SetOfflineSignature() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify properties were set correctly
			if !tt.wantErr {
				if !config.HasOfflineSignature() {
					t.Error("HasOfflineSignature() = false after successful SetOfflineSignature()")
				}

				// Verify expiration
				if got := config.GetOfflineSignatureExpiration(); got != tt.expiration {
					t.Errorf("GetOfflineSignatureExpiration() = %d, want %d", got, tt.expiration)
				}

				// Verify transient key
				if got := config.GetOfflineSignatureTransientKey(); string(got) != string(tt.transientPublicKey) {
					t.Errorf("GetOfflineSignatureTransientKey() mismatch")
				}

				// Verify signature
				if got := config.GetOfflineSignatureBytes(); string(got) != string(tt.signature) {
					t.Errorf("GetOfflineSignatureBytes() mismatch")
				}
			}
		})
	}
}

// TestOfflineSignature_HasOfflineSignature tests the HasOfflineSignature method
func TestOfflineSignature_HasOfflineSignature(t *testing.T) {
	tests := []struct {
		name       string
		setupFunc  func(*SessionConfig)
		wantResult bool
	}{
		{
			name:       "No properties set",
			setupFunc:  func(c *SessionConfig) {},
			wantResult: false,
		},
		{
			name: "Only expiration set",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "12345")
			},
			wantResult: false,
		},
		{
			name: "Only transient key set",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "dGVzdA==")
			},
			wantResult: false,
		},
		{
			name: "Only signature set",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, "c2ln")
			},
			wantResult: false,
		},
		{
			name: "Two of three set",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "12345")
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "dGVzdA==")
			},
			wantResult: false,
		},
		{
			name: "All three set",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "12345")
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "dGVzdA==")
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, "c2ln")
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SessionConfig{}
			tt.setupFunc(config)

			if got := config.HasOfflineSignature(); got != tt.wantResult {
				t.Errorf("HasOfflineSignature() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

// TestOfflineSignature_ValidateOfflineSignature tests validation logic
func TestOfflineSignature_ValidateOfflineSignature(t *testing.T) {
	futureExp := uint32(time.Now().Unix()) + 3600
	pastExp := uint32(time.Now().Unix()) - 3600

	tests := []struct {
		name        string
		setupFunc   func(*SessionConfig)
		wantErr     bool
		errContains string
	}{
		{
			name:      "No offline signature configured (valid)",
			setupFunc: func(c *SessionConfig) {},
			wantErr:   false,
		},
		{
			name: "Valid complete configuration",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(futureExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr: false,
		},
		{
			name: "Incomplete - missing expiration",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr:     true,
			errContains: "incomplete offline signature configuration",
		},
		{
			name: "Incomplete - missing transient key",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(futureExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr:     true,
			errContains: "incomplete offline signature configuration",
		},
		{
			name: "Incomplete - missing signature",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(futureExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
			},
			wantErr:     true,
			errContains: "incomplete offline signature configuration",
		},
		{
			name: "Expired timestamp",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(pastExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr:     true,
			errContains: "offline signature expired",
		},
		{
			name: "Invalid base64 transient key",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(futureExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "not-valid-base64!!!")
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr:     true,
			errContains: "invalid base64 encoding for transient public key",
		},
		{
			name: "Invalid base64 signature",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, formatUint32(futureExp))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, "not-valid-base64!!!")
			},
			wantErr:     true,
			errContains: "invalid base64 encoding for offline signature",
		},
		{
			name: "Invalid expiration format",
			setupFunc: func(c *SessionConfig) {
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "not-a-number")
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString([]byte("key")))
				c.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString([]byte("sig")))
			},
			wantErr:     true,
			errContains: "invalid offline expiration timestamp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SessionConfig{}
			tt.setupFunc(config)

			err := config.ValidateOfflineSignature()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOfflineSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("ValidateOfflineSignature() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestOfflineSignature_GetterMethods tests the getter methods
func TestOfflineSignature_GetterMethods(t *testing.T) {
	t.Run("Getters return nil/zero when not configured", func(t *testing.T) {
		config := &SessionConfig{}

		if got := config.GetOfflineSignatureExpiration(); got != 0 {
			t.Errorf("GetOfflineSignatureExpiration() = %d, want 0", got)
		}

		if got := config.GetOfflineSignatureTransientKey(); got != nil {
			t.Errorf("GetOfflineSignatureTransientKey() = %v, want nil", got)
		}

		if got := config.GetOfflineSignatureBytes(); got != nil {
			t.Errorf("GetOfflineSignatureBytes() = %v, want nil", got)
		}
	})

	t.Run("Getters return correct values when configured", func(t *testing.T) {
		config := &SessionConfig{}
		expiration := uint32(time.Now().Unix()) + 7200
		transientKey := []byte("test-transient-key-32-bytes-here")
		signature := []byte("test-signature-64-bytes-here-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

		err := config.SetOfflineSignature(expiration, transientKey, signature)
		if err != nil {
			t.Fatalf("SetOfflineSignature() failed: %v", err)
		}

		if got := config.GetOfflineSignatureExpiration(); got != expiration {
			t.Errorf("GetOfflineSignatureExpiration() = %d, want %d", got, expiration)
		}

		gotKey := config.GetOfflineSignatureTransientKey()
		if string(gotKey) != string(transientKey) {
			t.Errorf("GetOfflineSignatureTransientKey() mismatch")
		}

		gotSig := config.GetOfflineSignatureBytes()
		if string(gotSig) != string(signature) {
			t.Errorf("GetOfflineSignatureBytes() mismatch")
		}
	})

	t.Run("Getters handle invalid base64 gracefully", func(t *testing.T) {
		config := &SessionConfig{}
		config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "invalid")
		config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "not-base64!!!")
		config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, "also-not-base64!!!")

		// Should return zero/nil for invalid data
		if got := config.GetOfflineSignatureExpiration(); got != 0 {
			t.Errorf("GetOfflineSignatureExpiration() = %d for invalid input, want 0", got)
		}

		if got := config.GetOfflineSignatureTransientKey(); got != nil {
			t.Errorf("GetOfflineSignatureTransientKey() = %v for invalid input, want nil", got)
		}

		if got := config.GetOfflineSignatureBytes(); got != nil {
			t.Errorf("GetOfflineSignatureBytes() = %v for invalid input, want nil", got)
		}
	})
}

// TestOfflineSignature_PropertyConstants verifies the property constants are correct
func TestOfflineSignature_PropertyConstants(t *testing.T) {
	tests := []struct {
		prop     SessionConfigProperty
		expected string
	}{
		{SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, "i2cp.leaseSetOfflineExpiration"},
		{SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, "i2cp.leaseSetTransientPublicKey"},
		{SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, "i2cp.leaseSetOfflineSignature"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			config := &SessionConfig{}
			got := config.configOptLookup(tt.prop)
			if got != tt.expected {
				t.Errorf("configOptLookup(%d) = %q, want %q", tt.prop, got, tt.expected)
			}
		})
	}
}

// Helper functions

func formatUint32(v uint32) string {
	return string([]byte{
		byte('0' + (v/1000000000)%10),
		byte('0' + (v/100000000)%10),
		byte('0' + (v/10000000)%10),
		byte('0' + (v/1000000)%10),
		byte('0' + (v/100000)%10),
		byte('0' + (v/10000)%10),
		byte('0' + (v/1000)%10),
		byte('0' + (v/100)%10),
		byte('0' + (v/10)%10),
		byte('0' + v%10),
	})
}

// --- merged from session_config_timestamp_test.go ---

// TestSessionConfigValidateTimestamp tests the ±30 second timestamp validation
// required by I2CP spec § SessionConfig Notes
func TestSessionConfigValidateTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp uint64 // milliseconds since epoch
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "current time - valid",
			timestamp: uint64(time.Now().Unix() * 1000),
			wantErr:   false,
		},
		{
			name:      "29 seconds in past - valid",
			timestamp: uint64(time.Now().Unix()*1000 - 29000),
			wantErr:   false,
		},
		{
			name:      "29 seconds in future - valid",
			timestamp: uint64(time.Now().Unix()*1000 + 29000),
			wantErr:   false,
		},
		{
			name:      "exactly 30 seconds in past - valid boundary",
			timestamp: uint64(time.Now().Unix()*1000 - 30000),
			wantErr:   false,
		},
		{
			name:      "exactly 30 seconds in future - valid boundary",
			timestamp: uint64(time.Now().Unix()*1000 + 30000),
			wantErr:   false,
		},
		{
			name:      "31 seconds in past - invalid",
			timestamp: uint64(time.Now().Unix()*1000 - 31000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "31 seconds in future - invalid",
			timestamp: uint64(time.Now().Unix()*1000 + 31000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "1 minute in past - invalid",
			timestamp: uint64(time.Now().Unix()*1000 - 60000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "5 minutes in future - invalid",
			timestamp: uint64(time.Now().Unix()*1000 + 300000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "zero timestamp - invalid",
			timestamp: 0,
			wantErr:   true,
			errMsg:    "not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SessionConfig{
				date: tt.timestamp,
			}

			err := config.ValidateTimestamp()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateTimestamp() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" {
					// Simple substring check
					found := false
					for i := 0; i <= len(err.Error())-len(tt.errMsg); i++ {
						if err.Error()[i:i+len(tt.errMsg)] == tt.errMsg {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("ValidateTimestamp() error = %v, want error containing %q", err, tt.errMsg)
					}
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTimestamp() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestSessionConfigValidateTimestampEdgeCases tests edge cases for timestamp validation
func TestSessionConfigValidateTimestampEdgeCases(t *testing.T) {
	t.Run("config with destination but no timestamp", func(t *testing.T) {
		crypto := NewCrypto()
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		config := &SessionConfig{
			destination: dest,
			date:        0,
		}

		err = config.ValidateTimestamp()
		if err == nil {
			t.Error("ValidateTimestamp() expected error for zero timestamp, got nil")
		}
	})
}

// TestSessionConfigTimestampInCreateSession tests timestamp validation during session creation
func TestSessionConfigTimestampInCreateSession(t *testing.T) {
	// This test verifies that session creation properly validates timestamps
	// and that the writeToMessage function generates proper timestamps

	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Test: Create session config and verify timestamp is set
	t.Run("timestamp set by writeToMessage", func(t *testing.T) {
		config := &SessionConfig{
			destination: dest,
		}

		stream := NewStream(make([]byte, 0, 512))
		config.writeToMessage(stream, crypto, nil)

		// Verify some data was written (destination + mapping + date + signature)
		if stream.Len() == 0 {
			t.Error("writeToMessage() wrote no data")
		}

		// Note: config.date is set inside writeToMessage
		// We can't easily validate it here without exposing internals
		t.Logf("writeToMessage generated %d bytes", stream.Len())
	})
}

// TestSessionConfigTimestampClockSkew tests behavior with various clock skew scenarios
func TestSessionConfigTimestampClockSkew(t *testing.T) {
	tests := []struct {
		name      string
		skewMs    int64 // milliseconds offset from current time
		wantValid bool
	}{
		{name: "no skew", skewMs: 0, wantValid: true},
		{name: "1 second skew", skewMs: 1000, wantValid: true},
		{name: "10 second skew", skewMs: 10000, wantValid: true},
		{name: "20 second skew", skewMs: 20000, wantValid: true},
		{name: "29 second skew", skewMs: 29000, wantValid: true},
		{name: "30 second skew (boundary)", skewMs: 30000, wantValid: true},
		{name: "31 second skew (over limit)", skewMs: 31000, wantValid: false},
		{name: "60 second skew", skewMs: 60000, wantValid: false},
		{name: "-29 second skew", skewMs: -29000, wantValid: true},
		{name: "-31 second skew", skewMs: -31000, wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now().Unix() * 1000
			config := &SessionConfig{
				date: uint64(now + tt.skewMs),
			}

			err := config.ValidateTimestamp()

			if tt.wantValid && err != nil {
				t.Errorf("ValidateTimestamp() unexpected error for skew %d ms: %v", tt.skewMs, err)
			} else if !tt.wantValid && err == nil {
				t.Errorf("ValidateTimestamp() expected error for skew %d ms, got nil", tt.skewMs)
			}
		})
	}
}

// --- merged from session_config_wire_test.go ---

// TestSessionConfigWireFormatVerification tests that a signature created over truncated format
// can be verified against wire format after Java-style extraction
func TestSessionConfigWireFormatVerification(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")

	// Step 1: Build signature data (truncated format) and sign it
	signatureData := NewStream(make([]byte, 0, 512))
	if err := config.destination.WriteForSignature(signatureData); err != nil {
		t.Fatalf("Failed to write destination for signature: %v", err)
	}
	if err := config.writeMappingToMessage(signatureData); err != nil {
		t.Fatalf("Failed to write mapping for signature: %v", err)
	}
	timestamp := uint64(1234567890000)
	signatureData.WriteUint64(timestamp)

	signature, err := config.signSessionConfig(signatureData.Bytes(), crypto)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Logf("Signed %d bytes", signatureData.Len())
	t.Logf("Signature: %x", signature)

	// Step 2: Build wire message (padded format)
	wireMessage := NewStream(make([]byte, 0, 512))
	if err := config.destination.WriteToMessage(wireMessage); err != nil {
		t.Fatalf("Failed to write destination to wire: %v", err)
	}
	if err := config.writeMappingToMessage(wireMessage); err != nil {
		t.Fatalf("Failed to write mapping to wire: %v", err)
	}
	wireMessage.WriteUint64(timestamp)
	wireMessage.Write(signature)

	t.Logf("Wire message: %d bytes", wireMessage.Len())

	// Step 3: Simulate Java's process: read wire message, extract keys, re-serialize for verification
	readStream := NewStream(wireMessage.Bytes())

	// Read wire format destination
	destRead, err := NewDestinationFromMessage(readStream, crypto)
	if err != nil {
		t.Fatalf("Failed to read destination from wire: %v", err)
	}

	// Read properties
	propsRead, err := readStream.ReadMapping()
	if err != nil {
		t.Fatalf("Failed to read properties: %v", err)
	}

	// Read timestamp
	timestampRead, err := readStream.ReadUint64()
	if err != nil {
		t.Fatalf("Failed to read timestamp: %v", err)
	}

	// Read signature
	signatureRead := make([]byte, 64)
	if _, err := readStream.Read(signatureRead); err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}

	t.Logf("Read destination, %d properties, timestamp %d", len(propsRead), timestampRead)

	// CRITICAL CHECK: Verify the public key we read matches the original
	originalPubKey := dest.sgk.ed25519KeyPair.PublicKey()
	readPubKey := destRead.sgk.ed25519KeyPair.PublicKey()

	t.Logf("Original public key: %x", originalPubKey[:])
	t.Logf("Read public key:     %x", readPubKey[:])

	if string(originalPubKey[:]) != string(readPubKey[:]) {
		t.Fatalf("Public key mismatch! Original != Read")
	}
	t.Log("Public keys match ✓")

	// Step 4: Re-serialize for verification (truncated format, like Java does)
	verifyData := NewStream(make([]byte, 0, 512))
	if err := destRead.WriteForSignature(verifyData); err != nil {
		t.Fatalf("Failed to write destination for verification: %v", err)
	}

	// Write properties using WriteMapping
	if err := verifyData.WriteMapping(propsRead); err != nil {
		t.Fatalf("Failed to write properties for verification: %v", err)
	}

	verifyData.WriteUint64(timestampRead)

	t.Logf("Verify data: %d bytes", verifyData.Len())
	t.Logf("Original signature data: %d bytes", signatureData.Len())

	if verifyData.Len() != signatureData.Len() {
		t.Fatalf("Data length mismatch: signed %d bytes, verifying %d bytes", signatureData.Len(), verifyData.Len())
	}

	// Compare byte-by-byte
	for i := 0; i < signatureData.Len(); i++ {
		if signatureData.Bytes()[i] != verifyData.Bytes()[i] {
			t.Errorf("Byte mismatch at position %d: signed=0x%02x, verify=0x%02x", i, signatureData.Bytes()[i], verifyData.Bytes()[i])
			if i > 0 {
				t.Logf("Context at %d: signed[%d--%d]=%x", i, max(0, i-4), min(signatureData.Len(), i+4), signatureData.Bytes()[max(0, i-4):min(signatureData.Len(), i+4)])
				t.Logf("Context at %d: verify[%d:%d]=%x", i, max(0, i-4), min(verifyData.Len(), i+4), verifyData.Bytes()[max(0, i-4):min(verifyData.Len(), i+4)])
			}
			break
		}
	}

	// Step 5: Verify signature
	if destRead.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available after reading")
	}

	verified := destRead.sgk.ed25519KeyPair.Verify(verifyData.Bytes(), signatureRead)
	if !verified {
		t.Fatal("Signature verification failed!")
	}

	t.Log("Signature verification succeeded!")
}
