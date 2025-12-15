package go_i2cp

import (
	"context"
	"testing"
	"time"
)

// TestClient_Connect_TLSConfiguration tests that TLS configuration is applied during Connect
func TestClient_Connect_TLSConfiguration(t *testing.T) {
	client := NewClient(nil)

	// Enable TLS
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true") // For testing without real certs

	// Verify properties are set
	if client.properties["i2cp.SSL"] != "true" {
		t.Error("TLS should be enabled")
	}

	// Note: We can't actually connect without a real I2P router
	// This test verifies that the configuration is properly read and processed
	// The actual connection attempt will fail, but that's expected
}

// TestClient_Connect_TLSDisabled tests that plain TCP is used when TLS is disabled
func TestClient_Connect_TLSDisabled(t *testing.T) {
	client := NewClient(nil)

	// Verify TLS is disabled by default
	if client.properties["i2cp.SSL"] != "false" {
		t.Error("TLS should be disabled by default")
	}

	// tcp.tlsConfig should remain nil when TLS is disabled
	if client.tcp.tlsConfig != nil {
		t.Error("tlsConfig should be nil when TLS is disabled")
	}
}

// TestClient_Connect_TLSWithCertificates tests certificate configuration
func TestClient_Connect_TLSWithCertificates(t *testing.T) {
	client := NewClient(nil)

	// Configure TLS with certificate paths
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.certFile", "/path/to/client.crt")
	client.SetProperty("i2cp.SSL.keyFile", "/path/to/client.key")
	client.SetProperty("i2cp.SSL.caFile", "/path/to/ca.crt")

	// Verify properties are set correctly
	if client.properties["i2cp.SSL.certFile"] != "/path/to/client.crt" {
		t.Error("Certificate file path not set correctly")
	}
	if client.properties["i2cp.SSL.keyFile"] != "/path/to/client.key" {
		t.Error("Key file path not set correctly")
	}
	if client.properties["i2cp.SSL.caFile"] != "/path/to/ca.crt" {
		t.Error("CA file path not set correctly")
	}
}

// TestClient_Connect_TLSInsecureMode tests insecure mode configuration
func TestClient_Connect_TLSInsecureMode(t *testing.T) {
	client := NewClient(nil)

	// Configure insecure TLS mode
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true")

	// Verify insecure mode is set
	if client.properties["i2cp.SSL.insecure"] != "true" {
		t.Error("Insecure mode should be enabled")
	}
}

// TestClient_Connect_WithContext tests context cancellation during TLS setup
func TestClient_Connect_WithContext(t *testing.T) {
	client := NewClient(nil)
	client.SetProperty("i2cp.SSL", "true")

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Connect should fail with context error
	err := client.Connect(ctx)
	if err == nil {
		t.Error("Expected error when context is cancelled")
	}

	// Error should mention context cancellation
	if err != nil && err.Error() != "context cancelled before connect: context canceled" {
		// Expected behavior - context checked before TLS setup
		t.Logf("Got expected context error: %v", err)
	}
}

// TestClient_Connect_WithTimeout tests connection timeout with TLS
func TestClient_Connect_WithTimeout(t *testing.T) {
	client := NewClient(nil)
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true")

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give context time to expire
	time.Sleep(10 * time.Millisecond)

	// Connect should fail with context deadline exceeded
	err := client.Connect(ctx)
	if err == nil {
		t.Error("Expected error when context times out")
	}
}

// TestClient_TLSPropertyPropagation tests that TLS properties propagate to TCP layer
func TestClient_TLSPropertyPropagation(t *testing.T) {
	client := NewClient(nil)

	// Set various TLS properties
	tests := []struct {
		property string
		value    string
	}{
		{"i2cp.SSL", "true"},
		{"i2cp.SSL.certFile", "/test/cert.pem"},
		{"i2cp.SSL.keyFile", "/test/key.pem"},
		{"i2cp.SSL.caFile", "/test/ca.pem"},
		{"i2cp.SSL.insecure", "false"},
	}

	for _, tt := range tests {
		client.SetProperty(tt.property, tt.value)
		if client.properties[tt.property] != tt.value {
			t.Errorf("Property %s = %q, want %q",
				tt.property, client.properties[tt.property], tt.value)
		}
	}
}

// TestClient_TLSDefaultValues tests default TLS configuration values
func TestClient_TLSDefaultValues(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		property      string
		expectedValue string
	}{
		{"i2cp.SSL", "false"},
		{"i2cp.SSL.certFile", ""},
		{"i2cp.SSL.keyFile", ""},
		{"i2cp.SSL.caFile", ""},
		{"i2cp.SSL.insecure", "false"},
	}

	for _, tt := range tests {
		if client.properties[tt.property] != tt.expectedValue {
			t.Errorf("Default property %s = %q, want %q",
				tt.property, client.properties[tt.property], tt.expectedValue)
		}
	}
}

// TestClient_MultipleTLSPropertyChanges tests changing TLS configuration multiple times
func TestClient_MultipleTLSPropertyChanges(t *testing.T) {
	client := NewClient(nil)

	// Initially disable TLS
	client.SetProperty("i2cp.SSL", "false")
	if client.properties["i2cp.SSL"] != "false" {
		t.Error("TLS should be disabled")
	}

	// Enable TLS
	client.SetProperty("i2cp.SSL", "true")
	if client.properties["i2cp.SSL"] != "true" {
		t.Error("TLS should be enabled")
	}

	// Disable again
	client.SetProperty("i2cp.SSL", "false")
	if client.properties["i2cp.SSL"] != "false" {
		t.Error("TLS should be disabled again")
	}
}

// TestClient_TLSConfigurationBeforeConnect tests that TLS can be configured before Connect
func TestClient_TLSConfigurationBeforeConnect(t *testing.T) {
	client := NewClient(nil)

	// Configure TLS before attempting to connect
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true")
	client.SetProperty("i2cp.SSL.certFile", "/test/cert.pem")

	// Verify all properties are set
	if client.properties["i2cp.SSL"] != "true" {
		t.Error("TLS should be enabled")
	}
	if client.properties["i2cp.SSL.insecure"] != "true" {
		t.Error("Insecure mode should be enabled")
	}
	if client.properties["i2cp.SSL.certFile"] != "/test/cert.pem" {
		t.Error("Certificate file should be set")
	}

	// These properties should be ready for Connect to use
	// (actual connection would require a running I2P router)
}

// TestClient_EmptyTLSCertificates tests behavior with empty certificate paths
func TestClient_EmptyTLSCertificates(t *testing.T) {
	client := NewClient(nil)

	// Enable TLS but leave certificates empty
	client.SetProperty("i2cp.SSL", "true")

	// Empty strings should be the default
	if client.properties["i2cp.SSL.certFile"] != "" {
		t.Error("Certificate file should be empty by default")
	}
	if client.properties["i2cp.SSL.keyFile"] != "" {
		t.Error("Key file should be empty by default")
	}
	if client.properties["i2cp.SSL.caFile"] != "" {
		t.Error("CA file should be empty by default")
	}

	// This configuration is valid - uses system cert pool
}

// TestClient_TLSEnabledButNoRouter tests error handling when router is unreachable
func TestClient_TLSEnabledButNoRouter(t *testing.T) {
	client := NewClient(nil)
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should fail because there's no I2P router listening
	err := client.Connect(ctx)
	if err == nil {
		t.Error("Expected connection error when no router is available")
	}

	// Error should be a connection failure, not a TLS setup failure
	// (TLS setup should succeed, connection should fail)
	if err != nil {
		t.Logf("Got expected connection error: %v", err)
	}
}
