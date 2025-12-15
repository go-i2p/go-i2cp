package go_i2cp

import (
	"testing"
)

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
	lease := &Lease{
		tunnelGateway: [32]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		},
		tunnelId: 12345,
		endDate:  1234567890,
	}
	leases := []*Lease{lease}

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
	lease := &Lease{
		tunnelGateway: [32]byte{
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		},
		tunnelId: 12345,
		endDate:  1234567890,
	}
	leases := []*Lease{lease}

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
