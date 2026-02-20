package go_i2cp

import (
	"encoding/binary"
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

// --- merged from session_getters_test.go ---

// TestSessionID verifies session ID getter/setter operations
func TestSessionID(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial ID (should be 0)
	if id := session.ID(); id != 0 {
		t.Errorf("expected initial ID to be 0, got %d", id)
	}

	// Test setting ID
	testID := uint16(12345)
	session.SetID(testID)

	// Verify ID was set correctly
	if id := session.ID(); id != testID {
		t.Errorf("expected ID %d, got %d", testID, id)
	}

	// Test multiple sets
	newID := uint16(54321)
	session.SetID(newID)
	if id := session.ID(); id != newID {
		t.Errorf("expected ID %d after second set, got %d", newID, id)
	}
}

// TestSessionIDAlias verifies SessionID() is an alias for ID()
func TestSessionIDAlias(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial ID with both methods
	if session.ID() != session.SessionID() {
		t.Error("ID() and SessionID() should return the same value")
	}

	// Test after setting ID
	testID := uint16(9876)
	session.SetID(testID)

	if session.SessionID() != testID {
		t.Errorf("expected SessionID() to return %d, got %d", testID, session.SessionID())
	}

	if session.ID() != session.SessionID() {
		t.Error("ID() and SessionID() should always return the same value")
	}
}

// TestSessionIsPrimary verifies primary session flag operations
func TestSessionIsPrimary(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial state (should be true by default)
	if !session.IsPrimary() {
		t.Error("expected new session to be primary by default")
	}

	// Test setting to false
	session.SetPrimary(false)
	if session.IsPrimary() {
		t.Error("expected session to be non-primary after SetPrimary(false)")
	}

	// Test setting back to true
	session.SetPrimary(true)
	if !session.IsPrimary() {
		t.Error("expected session to be primary after SetPrimary(true)")
	}
}

// TestSessionPrimarySession verifies primary session reference operations
func TestSessionPrimarySession(t *testing.T) {
	client := NewClient(nil)
	primarySession := NewSession(client, SessionCallbacks{})
	subsession := NewSession(client, SessionCallbacks{})

	// Test initial state (should be nil)
	if ps := subsession.PrimarySession(); ps != nil {
		t.Error("expected initial primary session to be nil")
	}

	// Test setting valid primary session
	primarySession.SetID(1)
	subsession.SetID(2)

	err := subsession.SetPrimarySession(primarySession)
	if err != nil {
		t.Fatalf("unexpected error setting primary session: %v", err)
	}

	// Verify primary session was set correctly
	if ps := subsession.PrimarySession(); ps != primarySession {
		t.Error("primary session reference not set correctly")
	}

	// Verify subsession flag was automatically set to false
	if subsession.IsPrimary() {
		t.Error("expected subsession to be marked as non-primary")
	}
}

// TestSetPrimarySessionErrors verifies error handling in SetPrimarySession
func TestSetPrimarySessionErrors(t *testing.T) {
	client := NewClient(nil)
	subsession := NewSession(client, SessionCallbacks{})

	// Test nil primary session
	err := subsession.SetPrimarySession(nil)
	if err == nil {
		t.Error("expected error when setting nil primary session")
	}
	if err != nil && err.Error() != "primary session cannot be nil" {
		t.Errorf("unexpected error message: %v", err)
	}

	// Test setting non-primary session as primary
	nonPrimarySession := NewSession(client, SessionCallbacks{})
	nonPrimarySession.SetPrimary(false) // Explicitly set as non-primary

	err = subsession.SetPrimarySession(nonPrimarySession)
	if err == nil {
		t.Error("expected error when setting non-primary session as primary")
	}
	if err != nil && err.Error() != "referenced session is not a primary session" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSessionIDThreadSafety verifies concurrent ID operations are thread-safe
func TestSessionIDThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Run concurrent reads and writes
	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func(id uint16) {
			session.SetID(id)
			done <- true
		}(uint16(i))
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = session.ID()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read the ID without panic
	_ = session.ID()
}

// TestSessionPrimaryThreadSafety verifies concurrent primary flag operations are thread-safe
func TestSessionPrimaryThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func(isPrimary bool) {
			session.SetPrimary(isPrimary)
			done <- true
		}(i%2 == 0)
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = session.IsPrimary()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_ = session.IsPrimary()
}

// TestSessionPrimaryReferenceThreadSafety verifies concurrent primary session reference operations
func TestSessionPrimaryReferenceThreadSafety(t *testing.T) {
	client := NewClient(nil)
	primarySession := NewSession(client, SessionCallbacks{})
	subsession := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func() {
			_ = subsession.SetPrimarySession(primarySession)
			done <- true
		}()
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = subsession.PrimarySession()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_ = subsession.PrimarySession()
}

// TestSessionSigningKeyPair verifies SigningKeyPair() returns the correct key pair
func TestSessionSigningKeyPair(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error getting signing key pair: %v", err)
	}

	if keyPair == nil {
		t.Fatal("expected non-nil key pair")
	}

	// Verify it's the same key pair as in the destination
	dest := session.Destination()
	if dest == nil {
		t.Fatal("expected non-nil destination")
	}

	if dest.sgk.ed25519KeyPair != keyPair {
		t.Error("SigningKeyPair() should return the same key pair as destination's sgk.ed25519KeyPair")
	}

	// Verify key pair has valid public and private keys
	pubKey := keyPair.PublicKey()
	if len(pubKey) != 32 {
		t.Errorf("expected public key length 32, got %d", len(pubKey))
	}

	privKey := keyPair.PrivateKey()
	if len(privKey) != 64 {
		t.Errorf("expected private key length 64, got %d", len(privKey))
	}
}

// TestSessionSigningKeyPairForSigning verifies SigningKeyPair() can be used for signing
func TestSessionSigningKeyPairForSigning(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error getting signing key pair: %v", err)
	}

	// Test data to sign (simulating a packet)
	testData := []byte("test packet data for I2P streaming protocol")

	// Sign the data
	signature, err := keyPair.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// Verify the signature
	valid := keyPair.Verify(testData, signature)
	if !valid {
		t.Error("signature verification failed for data signed with same key pair")
	}

	// Verify with wrong data fails
	wrongData := []byte("wrong data")
	valid = keyPair.Verify(wrongData, signature)
	if valid {
		t.Error("signature verification should fail for wrong data")
	}
}

// TestSessionSigningKeyPairNilConfig verifies error handling when config is nil
func TestSessionSigningKeyPairNilConfig(t *testing.T) {
	// Create session with nil config (simulating uninitialized state)
	session := &Session{}

	keyPair, err := session.SigningKeyPair()
	if err == nil {
		t.Error("expected error when session config is nil")
	}

	if keyPair != nil {
		t.Error("expected nil key pair when session config is nil")
	}

	if err != ErrSessionNotInitialized {
		t.Errorf("expected ErrSessionNotInitialized, got: %v", err)
	}
}

// TestSessionSigningKeyPairNilDestination verifies error handling when destination is nil
func TestSessionSigningKeyPairNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Manually set destination to nil to test error handling
	session.mu.Lock()
	session.config.destination = nil
	session.mu.Unlock()

	keyPair, err := session.SigningKeyPair()
	if err == nil {
		t.Error("expected error when destination is nil")
	}

	if keyPair != nil {
		t.Error("expected nil key pair when destination is nil")
	}

	expectedError := "session has no destination"
	if err.Error() != expectedError {
		t.Errorf("expected error '%s', got: %v", expectedError, err)
	}
}

// TestSessionSigningKeyPairThreadSafety verifies concurrent access to SigningKeyPair()
func TestSessionSigningKeyPairThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Multiple readers
	for i := 0; i < 100; i++ {
		go func() {
			keyPair, err := session.SigningKeyPair()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if keyPair == nil {
				t.Error("expected non-nil key pair")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_, _ = session.SigningKeyPair()
}

// TestSessionSigningKeyPairConsistency verifies key pair remains consistent across calls
func TestSessionSigningKeyPairConsistency(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get key pair multiple times
	keyPair1, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyPair2, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's the same instance
	if keyPair1 != keyPair2 {
		t.Error("SigningKeyPair() should return the same instance across multiple calls")
	}

	// Verify public keys are identical
	pubKey1 := keyPair1.PublicKey()
	pubKey2 := keyPair2.PublicKey()

	if len(pubKey1) != len(pubKey2) {
		t.Error("public key lengths should match")
	}

	for i := range pubKey1 {
		if pubKey1[i] != pubKey2[i] {
			t.Error("public keys should be identical")
			break
		}
	}
}

// --- merged from session_id_fix_test.go ---

// TestMsgCreateLeaseSetSessionID verifies that msgCreateLeaseSet correctly uses
// the sessionId parameter instead of relying on session.id field
// This test addresses the bug where session.id could be 0 when msgCreateLeaseSet is called
func TestMsgCreateLeaseSetSessionID(t *testing.T) {
	client := NewClient(nil)

	// Create a destination for the session
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Create session with a config
	session := NewSession(client, SessionCallbacks{})
	session.config = &SessionConfig{destination: dest}

	// Intentionally do NOT set session.id to simulate the bug condition
	// where session.id is 0 but we have a valid sessionId from RequestVariableLeaseSet
	if session.id != 0 {
		t.Fatalf("Expected session.id to be 0 initially, got %d", session.id)
	}

	// Create a test lease with minimal data
	var leaseBytes [44]byte
	copy(leaseBytes[:32], []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})
	binary.BigEndian.PutUint32(leaseBytes[32:36], 12345)
	binary.BigEndian.PutUint64(leaseBytes[36:44], 1234567890)
	testLease := Lease(leaseBytes)
	leases := []*Lease{&testLease}

	// Call msgCreateLeaseSet with explicit sessionId (like onMsgReqVariableLease does)
	testSessionId := uint16(42)
	client.msgCreateLeaseSet(testSessionId, session, 1, leases, false)

	// Verify the message was constructed with the correct sessionId
	// The messageStream should have the sessionId written to it
	readStream := NewStream(client.messageStream.Bytes())
	writtenSessionId, err := readStream.ReadUint16()
	if err != nil {
		t.Fatalf("Failed to read sessionId from messageStream: %v", err)
	}

	if writtenSessionId != testSessionId {
		t.Errorf("Expected sessionId %d to be written to message, got %d", testSessionId, writtenSessionId)
	}

	// Verify that session.id is still 0 (wasn't used)
	if session.id != 0 {
		t.Errorf("Session.id should still be 0, but it's %d", session.id)
	}
}

// TestMsgCreateLeaseSetWithSetSessionID verifies msgCreateLeaseSet works correctly
// even when session.id IS set (backward compatibility test)
func TestMsgCreateLeaseSetWithSetSessionID(t *testing.T) {
	client := NewClient(nil)

	// Create a destination for the session
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Create session with a config
	session := NewSession(client, SessionCallbacks{})
	session.config = &SessionConfig{destination: dest}

	// Set session.id to a different value than the parameter
	session.SetID(99)

	// Create a test lease with minimal data
	var leaseBytes2 [44]byte
	copy(leaseBytes2[:32], []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})
	binary.BigEndian.PutUint32(leaseBytes2[32:36], 12345)
	binary.BigEndian.PutUint64(leaseBytes2[36:44], 1234567890)
	testLease2 := Lease(leaseBytes2)
	leases := []*Lease{&testLease2}

	// Call msgCreateLeaseSet with explicit sessionId parameter
	// The parameter should take precedence over session.id
	testSessionId := uint16(42)
	client.msgCreateLeaseSet(testSessionId, session, 1, leases, false)

	// Verify the message was constructed with the PARAMETER sessionId, not session.id
	readStream := NewStream(client.messageStream.Bytes())
	writtenSessionId, err := readStream.ReadUint16()
	if err != nil {
		t.Fatalf("Failed to read sessionId from messageStream: %v", err)
	}

	if writtenSessionId != testSessionId {
		t.Errorf("Expected parameter sessionId %d to be written to message (not session.id=%d), got %d",
			testSessionId, session.id, writtenSessionId)
	}
}
