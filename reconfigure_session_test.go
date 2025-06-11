package go_i2cp

import (
	"testing"
)

// TestReconfigureSessionMessage tests the ReconfigureSession message handling
func TestReconfigureSessionMessage(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	// Add session to client's session map (simulate session creation)
	session.id = 1
	client.sessions[1] = session

	// Test configuration properties
	testProperties := map[string]string{
		"inbound.quantity":  "3",
		"outbound.quantity": "3",
		"inbound.length":    "2",
		"outbound.length":   "2",
	}

	// Create a test stream with session ID and properties mapping
	testStream := NewStream(make([]byte, 0))
	testStream.WriteUint16(1) // Session ID

	// Use WriteMapping to properly format the properties
	err := testStream.WriteMapping(testProperties)
	if err != nil {
		t.Fatalf("Failed to write mapping: %v", err)
	}

	// Create a new stream for reading from the written data
	readStream := NewStream(testStream.Bytes())

	// Test the message handler
	client.onMsgReconfigureSession(readStream)

	// Verify that properties were applied to session configuration
	config := session.config
	if config.properties[SESSION_CONFIG_PROP_INBOUND_QUANTITY] != "3" {
		t.Errorf("Expected inbound quantity to be updated to '3', got '%s'",
			config.properties[SESSION_CONFIG_PROP_INBOUND_QUANTITY])
	}

	if config.properties[SESSION_CONFIG_PROP_OUTBOUND_QUANTITY] != "3" {
		t.Errorf("Expected outbound quantity to be updated to '3', got '%s'",
			config.properties[SESSION_CONFIG_PROP_OUTBOUND_QUANTITY])
	}
}

// TestMsgReconfigureSession tests the msgReconfigureSession function
func TestMsgReconfigureSession(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	// Simulate session creation
	session.id = 1
	client.sessions[1] = session

	// Test properties to update
	properties := map[string]string{
		"inbound.quantity":  "4",
		"outbound.quantity": "4",
		"crypto.tagsToSend": "40",
	}

	// Test sending reconfigure message (won't actually send due to no connection)
	err := client.msgReconfigureSession(session, properties, true) // queue=true

	// Should not return error even though not connected (it's queued)
	if err != nil {
		t.Errorf("msgReconfigureSession returned unexpected error: %v", err)
	}
}

// TestValidateSessionConfig tests session configuration validation
func TestValidateSessionConfig(t *testing.T) {
	client := NewClient(nil)

	// Test valid configuration
	validConfig := SessionConfig{}
	validConfig.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	validConfig.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")
	validConfig.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "2")
	validConfig.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "2")

	err := client.validateSessionConfig(&validConfig)
	if err != nil {
		t.Errorf("Valid configuration failed validation: %v", err)
	}

	// Test invalid tunnel quantity (too high)
	invalidConfig := SessionConfig{}
	invalidConfig.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "20")

	err = client.validateSessionConfig(&invalidConfig)
	if err == nil {
		t.Error("Expected validation error for invalid tunnel quantity, got nil")
	}

	// Test invalid tunnel length (too high)
	invalidConfig2 := SessionConfig{}
	invalidConfig2.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "10")

	err = client.validateSessionConfig(&invalidConfig2)
	if err == nil {
		t.Error("Expected validation error for invalid tunnel length, got nil")
	}

	// Test invalid length variance (too low)
	invalidConfig3 := SessionConfig{}
	invalidConfig3.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH_VARIANCE, "-10")

	err = client.validateSessionConfig(&invalidConfig3)
	if err == nil {
		t.Error("Expected validation error for invalid length variance, got nil")
	}
}

// TestSessionReconfigureMethod tests the Session.ReconfigureSession convenience method
func TestSessionReconfigureMethod(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	// Set up session
	session.id = 1
	client.sessions[1] = session

	properties := map[string]string{
		"inbound.quantity":  "2",
		"outbound.quantity": "2",
	}

	// Test the convenience method
	err := session.ReconfigureSession(properties)
	if err != nil {
		t.Errorf("Session.ReconfigureSession returned unexpected error: %v", err)
	}
}
