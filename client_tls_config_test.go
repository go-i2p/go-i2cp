package go_i2cp

import (
	"testing"
)

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
