package go_i2cp

import (
	"testing"
)

// TestTcp_SetProperty tests setting TCP properties
func TestTcp_SetProperty(t *testing.T) {
	tests := []struct {
		name     string
		property TcpProperty
		value    string
	}{
		{
			name:     "set address property",
			property: TCP_PROP_ADDRESS,
			value:    "192.168.1.1",
		},
		{
			name:     "set port property",
			property: TCP_PROP_PORT,
			value:    "8080",
		},
		{
			name:     "set TLS property",
			property: TCP_PROP_USE_TLS,
			value:    "true",
		},
		{
			name:     "set TLS certificate property",
			property: TCP_PROP_TLS_CLIENT_CERTIFICATE,
			value:    "/path/to/cert.pem",
		},
		{
			name:     "set empty value",
			property: TCP_PROP_ADDRESS,
			value:    "",
		},
		{
			name:     "set special characters",
			property: TCP_PROP_ADDRESS,
			value:    "test@#$%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &Tcp{}
			tcp.SetProperty(tt.property, tt.value)

			// Verify the property was set correctly using GetProperty
			got := tcp.GetProperty(tt.property)
			if got != tt.value {
				t.Errorf("GetProperty() = %q, want %q", got, tt.value)
			}
		})
	}
}

// TestTcp_GetProperty tests retrieving TCP properties
func TestTcp_GetProperty(t *testing.T) {
	tests := []struct {
		name     string
		property TcpProperty
		setValue string
		want     string
	}{
		{
			name:     "get previously set address",
			property: TCP_PROP_ADDRESS,
			setValue: "127.0.0.1",
			want:     "127.0.0.1",
		},
		{
			name:     "get previously set port",
			property: TCP_PROP_PORT,
			setValue: "7654",
			want:     "7654",
		},
		{
			name:     "get unset property returns empty string",
			property: TCP_PROP_USE_TLS,
			setValue: "",
			want:     "",
		},
		{
			name:     "get after multiple sets returns latest value",
			property: TCP_PROP_ADDRESS,
			setValue: "final.address",
			want:     "final.address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &Tcp{}

			// For the "multiple sets" test, set different values first
			if tt.name == "get after multiple sets returns latest value" {
				tcp.SetProperty(tt.property, "first.address")
				tcp.SetProperty(tt.property, "second.address")
			}

			// Set the final value
			tcp.SetProperty(tt.property, tt.setValue)

			// Get the property
			got := tcp.GetProperty(tt.property)
			if got != tt.want {
				t.Errorf("GetProperty() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTcp_GetProperty_DefaultValues tests that properties have empty default values
func TestTcp_GetProperty_DefaultValues(t *testing.T) {
	tcp := &Tcp{}

	properties := []TcpProperty{
		TCP_PROP_ADDRESS,
		TCP_PROP_PORT,
		TCP_PROP_USE_TLS,
		TCP_PROP_TLS_CLIENT_CERTIFICATE,
	}

	for _, prop := range properties {
		t.Run("default value for property", func(t *testing.T) {
			got := tcp.GetProperty(prop)
			if got != "" {
				t.Errorf("GetProperty() for uninitialized property = %q, want empty string", got)
			}
		})
	}
}

// TestTcp_SetGetProperty_AllProperties tests all defined TCP properties
func TestTcp_SetGetProperty_AllProperties(t *testing.T) {
	tcp := &Tcp{}

	testValues := map[TcpProperty]string{
		TCP_PROP_ADDRESS:                "test.address.com",
		TCP_PROP_PORT:                   "9999",
		TCP_PROP_USE_TLS:                "enabled",
		TCP_PROP_TLS_CLIENT_CERTIFICATE: "/etc/ssl/cert.pem",
	}

	// Set all properties
	for prop, value := range testValues {
		tcp.SetProperty(prop, value)
	}

	// Verify all properties were set correctly
	for prop, expectedValue := range testValues {
		got := tcp.GetProperty(prop)
		if got != expectedValue {
			t.Errorf("Property %d: got %q, want %q", prop, got, expectedValue)
		}
	}
}

// TestTcp_SetProperty_Overwrite tests overwriting existing property values
func TestTcp_SetProperty_Overwrite(t *testing.T) {
	tcp := &Tcp{}
	property := TCP_PROP_ADDRESS

	// Set initial value
	tcp.SetProperty(property, "initial.value")
	if got := tcp.GetProperty(property); got != "initial.value" {
		t.Fatalf("Initial set failed: got %q, want %q", got, "initial.value")
	}

	// Overwrite with new value
	tcp.SetProperty(property, "overwritten.value")
	if got := tcp.GetProperty(property); got != "overwritten.value" {
		t.Errorf("Overwrite failed: got %q, want %q", got, "overwritten.value")
	}

	// Overwrite with empty value
	tcp.SetProperty(property, "")
	if got := tcp.GetProperty(property); got != "" {
		t.Errorf("Overwrite with empty failed: got %q, want empty string", got)
	}
}

// TestTcp_PropertyIsolation tests that different properties don't interfere with each other
func TestTcp_PropertyIsolation(t *testing.T) {
	tcp := &Tcp{}

	// Set different values for different properties
	tcp.SetProperty(TCP_PROP_ADDRESS, "address_value")
	tcp.SetProperty(TCP_PROP_PORT, "port_value")
	tcp.SetProperty(TCP_PROP_USE_TLS, "tls_value")
	tcp.SetProperty(TCP_PROP_TLS_CLIENT_CERTIFICATE, "cert_value")

	// Verify each property maintains its own value
	if got := tcp.GetProperty(TCP_PROP_ADDRESS); got != "address_value" {
		t.Errorf("TCP_PROP_ADDRESS = %q, want %q", got, "address_value")
	}
	if got := tcp.GetProperty(TCP_PROP_PORT); got != "port_value" {
		t.Errorf("TCP_PROP_PORT = %q, want %q", got, "port_value")
	}
	if got := tcp.GetProperty(TCP_PROP_USE_TLS); got != "tls_value" {
		t.Errorf("TCP_PROP_USE_TLS = %q, want %q", got, "tls_value")
	}
	if got := tcp.GetProperty(TCP_PROP_TLS_CLIENT_CERTIFICATE); got != "cert_value" {
		t.Errorf("TCP_PROP_TLS_CLIENT_CERTIFICATE = %q, want %q", got, "cert_value")
	}
}

// TestTcp_SetProperty_LongValue tests handling of very long property values
func TestTcp_SetProperty_LongValue(t *testing.T) {
	tcp := &Tcp{}

	// Create a long value (1000 characters)
	longValue := ""
	for i := 0; i < 100; i++ {
		longValue += "0123456789"
	}

	tcp.SetProperty(TCP_PROP_ADDRESS, longValue)
	got := tcp.GetProperty(TCP_PROP_ADDRESS)

	if got != longValue {
		t.Errorf("Long value not preserved: got length %d, want %d", len(got), len(longValue))
	}
}

// TestTcp_SetProperty_UnicodeValue tests handling of Unicode property values
func TestTcp_SetProperty_UnicodeValue(t *testing.T) {
	tcp := &Tcp{}

	unicodeValues := []string{
		"日本語",
		"Ελληνικά",
		"Русский",
		"🚀🌟💻",
		"mixed-ASCII-日本語-123",
	}

	for _, value := range unicodeValues {
		t.Run("unicode: "+value, func(t *testing.T) {
			tcp.SetProperty(TCP_PROP_ADDRESS, value)
			got := tcp.GetProperty(TCP_PROP_ADDRESS)
			if got != value {
				t.Errorf("Unicode value not preserved: got %q, want %q", got, value)
			}
		})
	}
}

// TestTcp_GetProperty_AfterInit tests that Init doesn't interfere with properties
func TestTcp_GetProperty_AfterInit(t *testing.T) {
	tcp := &Tcp{}

	// Set properties before Init
	tcp.SetProperty(TCP_PROP_USE_TLS, "test_value")

	// Call Init
	err := tcp.Init("127.0.0.1:7654")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify property is still accessible
	got := tcp.GetProperty(TCP_PROP_USE_TLS)
	if got != "test_value" {
		t.Errorf("Property lost after Init: got %q, want %q", got, "test_value")
	}
}
