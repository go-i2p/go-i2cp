package go_i2cp

import (
	"testing"
)

// TestNewSession verifies session creation with proper initialization
func TestNewSession(t *testing.T) {
	// Create mock client
	client := NewClient(nil)

	// Define test callbacks
	callbacks := SessionCallbacks{
		OnDestination: func(session *Session, requestId uint32, address string, dest *Destination) {
			// Mock callback for testing
		},
		OnStatus: func(session *Session, status SessionStatus) {
			// Mock callback for testing
		},
		OnMessage: func(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			// Mock callback for testing
		},
	}

	// Test session creation
	session := NewSession(client, callbacks)

	// Verify session was properly initialized
	if session == nil {
		t.Fatal("NewSession returned nil")
	}

	if session.client != client {
		t.Error("Session client reference not set correctly")
	}

	if session.callbacks == nil {
		t.Error("Session callbacks not set correctly")
	}

	if session.config == nil {
		t.Error("Session config not initialized")
	}

	if session.config.destination == nil {
		t.Error("Session destination not initialized")
	}
}

// TestSessionDestination verifies destination access
func TestSessionDestination(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	dest := session.Destination()
	if dest == nil {
		t.Fatal("Session destination is nil")
	}

	// Verify destination has required fields
	if dest.b32 == "" {
		t.Error("Destination b32 address not generated")
	}

	if dest.b64 == "" {
		t.Error("Destination b64 address not generated")
	}
}

// TestSessionSendMessage verifies message sending functionality
func TestSessionSendMessage(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	// Create test destination
	testDest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	// Create test payload
	payload := NewStream([]byte("test message"))

	// Test message sending (should not panic)
	// Using protocol=6 as test value (not I2CP-defined, represents application-level protocol)
	session.SendMessage(testDest, 6, 1234, 5678, payload, 123456)

	// Verify no immediate errors (actual sending requires router connection)
}

// TestSessionDispatchMessage verifies message dispatch to callbacks
func TestSessionDispatchMessage(t *testing.T) {
	client := NewClient(nil)

	// Track callback invocations
	var callbackInvoked bool
	var receivedProtocol uint8
	var receivedSrcPort, receivedDestPort uint16
	var receivedPayload *Stream
	var receivedSrcDest *Destination

	callbacks := SessionCallbacks{
		OnMessage: func(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			callbackInvoked = true
			receivedSrcDest = srcDest
			receivedProtocol = protocol
			receivedSrcPort = srcPort
			receivedDestPort = destPort
			receivedPayload = payload
		},
	}

	session := NewSession(client, callbacks)

	// Test message dispatch
	// Using protocol=17 as test value (not I2CP-defined, represents application-level protocol)
	const testProtocol uint8 = 17
	testPayload := NewStream([]byte("test payload"))
	// Create a test source destination
	testSrcDest, _ := NewDestination(client.crypto)
	session.dispatchMessage(testSrcDest, testProtocol, 1111, 2222, testPayload)

	// Verify callback was invoked with correct parameters
	if !callbackInvoked {
		t.Error("Message callback was not invoked")
	}

	if receivedSrcDest != testSrcDest {
		t.Error("Received source destination does not match sent source destination")
	}

	if receivedProtocol != testProtocol {
		t.Errorf("Expected protocol %d, got %d", testProtocol, receivedProtocol)
	}

	if receivedSrcPort != 1111 {
		t.Errorf("Expected srcPort 1111, got %d", receivedSrcPort)
	}

	if receivedDestPort != 2222 {
		t.Errorf("Expected destPort 2222, got %d", receivedDestPort)
	}

	if receivedPayload != testPayload {
		t.Error("Received payload does not match sent payload")
	}
}

// TestSessionDispatchDestination verifies destination lookup dispatch
func TestSessionDispatchDestination(t *testing.T) {
	client := NewClient(nil)

	// Track callback invocations
	var callbackInvoked bool
	var receivedRequestId uint32
	var receivedAddress string
	var receivedDest *Destination

	callbacks := SessionCallbacks{
		OnDestination: func(session *Session, requestId uint32, address string, dest *Destination) {
			callbackInvoked = true
			receivedRequestId = requestId
			receivedAddress = address
			receivedDest = dest
		},
	}

	session := NewSession(client, callbacks)

	// Create test destination
	testDest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create test destination: %v", err)
	}

	// Test destination dispatch
	session.dispatchDestination(12345, "test.b32.i2p", testDest)

	// Verify callback was invoked with correct parameters
	if !callbackInvoked {
		t.Error("Destination callback was not invoked")
	}

	if receivedRequestId != 12345 {
		t.Errorf("Expected requestId 12345, got %d", receivedRequestId)
	}

	if receivedAddress != "test.b32.i2p" {
		t.Errorf("Expected address 'test.b32.i2p', got '%s'", receivedAddress)
	}

	if receivedDest != testDest {
		t.Error("Received destination does not match sent destination")
	}
}

// TestSessionDispatchStatus verifies status change dispatch
func TestSessionDispatchStatus(t *testing.T) {
	client := NewClient(nil)

	// Track callback invocations
	var callbackInvoked bool
	var receivedStatus SessionStatus

	callbacks := SessionCallbacks{
		OnStatus: func(session *Session, status SessionStatus) {
			callbackInvoked = true
			receivedStatus = status
		},
	}

	session := NewSession(client, callbacks)

	// Test each status type
	statuses := []SessionStatus{
		I2CP_SESSION_STATUS_CREATED,
		I2CP_SESSION_STATUS_DESTROYED,
		I2CP_SESSION_STATUS_UPDATED,
		I2CP_SESSION_STATUS_INVALID,
	}

	for _, status := range statuses {
		callbackInvoked = false
		session.dispatchStatus(status)

		if !callbackInvoked {
			t.Errorf("Status callback was not invoked for status %d", status)
		}

		if receivedStatus != status {
			t.Errorf("Expected status %d, got %d", status, receivedStatus)
		}
	}
}

// TestSessionWithNilCallbacks verifies graceful handling of nil callbacks
func TestSessionWithNilCallbacks(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test that nil callbacks don't cause panics
	testPayload := NewStream([]byte("test"))

	// These should not panic even with nil callbacks
	// Using protocol=6 as test value (not I2CP-defined, represents application-level protocol)
	testSrcDest, _ := NewDestination(client.crypto)
	session.dispatchMessage(testSrcDest, 6, 1, 2, testPayload)
	session.dispatchDestination(1, "test", nil)
	session.dispatchStatus(I2CP_SESSION_STATUS_CREATED)
}

// TestSessionConfigIntegration verifies session config integration
func TestSessionConfigIntegration(t *testing.T) {
	client := NewClient(nil)
	callbacks := SessionCallbacks{}
	session := NewSession(client, callbacks)

	// Test config property setting
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "test-session")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")

	// Verify properties were set
	if session.config.properties[SESSION_CONFIG_PROP_OUTBOUND_NICKNAME] != "test-session" {
		t.Error("Session config property not set correctly")
	}

	if session.config.properties[SESSION_CONFIG_PROP_OUTBOUND_QUANTITY] != "2" {
		t.Error("Session config quantity not set correctly")
	}
}
