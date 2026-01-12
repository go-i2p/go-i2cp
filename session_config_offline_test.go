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
				if err == nil || !offlineContainsString(err.Error(), tt.errContains) {
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
				if err == nil || !offlineContainsString(err.Error(), tt.errContains) {
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

func offlineContainsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && offlineContainsStringImpl(s, substr))
}

func offlineContainsStringImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

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
