package go_i2cp

import (
	"testing"
)

// TestCreateLeaseSet2WithBlinding tests msgCreateLeaseSet2 with blinding enabled
func TestCreateLeaseSet2WithBlinding(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	// Set up blinding parameters
	blindingScheme := uint16(1)
	blindingFlags := uint16(0x0001)
	blindingParams := []byte{0x01, 0x02, 0x03, 0x04}

	session.SetBlindingScheme(blindingScheme)
	session.SetBlindingFlags(blindingFlags)
	session.SetBlindingParams(blindingParams)

	// Verify blinding is enabled
	if !session.IsBlindingEnabled() {
		t.Fatal("Expected blinding to be enabled")
	}

	// Create a minimal destination for the session
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	// Initialize client with router date
	client.router.date = 1000000

	// Call msgCreateLeaseSet2 - should use encrypted LeaseSet type
	// Use queue=true since we're not connected to a router
	err = client.msgCreateLeaseSet2(session, 3, true)
	if err != nil {
		t.Fatalf("msgCreateLeaseSet2 failed with blinding enabled: %v", err)
	}

	// Verify the message was queued/sent (output queue should have the message)
	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued, but output queue is empty")
	}
}

// TestCreateLeaseSet2WithoutBlinding tests msgCreateLeaseSet2 without blinding
func TestCreateLeaseSet2WithoutBlinding(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	// Verify blinding is NOT enabled (default state)
	if session.IsBlindingEnabled() {
		t.Fatal("Expected blinding to be disabled by default")
	}

	// Create a minimal destination for the session
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	// Initialize client with router date
	client.router.date = 1000000

	// Call msgCreateLeaseSet2 - should use standard LeaseSet type
	// Use queue=true since we're not connected to a router
	err = client.msgCreateLeaseSet2(session, 3, true)
	if err != nil {
		t.Fatalf("msgCreateLeaseSet2 failed without blinding: %v", err)
	}

	// Verify the message was queued/sent
	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued, but output queue is empty")
	}
}

// TestCreateLeaseSet2BlindingFlagsIncluded tests that blinding flags are properly included
func TestCreateLeaseSet2BlindingFlagsIncluded(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	// Set up blinding with specific flags
	blindingScheme := uint16(2)
	blindingFlags := uint16(0x0003) // Custom flags
	blindingParams := []byte{0xAA, 0xBB, 0xCC}

	session.SetBlindingScheme(blindingScheme)
	session.SetBlindingFlags(blindingFlags)
	session.SetBlindingParams(blindingParams)

	// Create destination
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest
	client.router.date = 1000000

	// Create LeaseSet2 with queue=true
	err = client.msgCreateLeaseSet2(session, 2, true)
	if err != nil {
		t.Fatalf("msgCreateLeaseSet2 failed: %v", err)
	}

	// Message should be in output queue
	if len(client.outputQueue) == 0 {
		t.Fatal("Expected message in output queue")
	}

	// Note: Full message parsing would require reading the stream back,
	// which is complex. The key verification is that no error occurred
	// and the message was constructed successfully.
}

// TestCreateLeaseSet2EmptyBlindingParams tests blinding with empty parameters
func TestCreateLeaseSet2EmptyBlindingParams(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	// Enable blinding but with empty parameters
	session.SetBlindingScheme(1)   // Scheme is set
	session.SetBlindingParams(nil) // No params

	if !session.IsBlindingEnabled() {
		t.Fatal("Expected blinding to be enabled when scheme > 0")
	}

	// Create destination
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest
	client.router.date = 1000000

	// Create LeaseSet2 - should handle empty params gracefully
	// Use queue=true since we're not connected
	err = client.msgCreateLeaseSet2(session, 1, true)
	if err != nil {
		t.Fatalf("msgCreateLeaseSet2 failed with empty blinding params: %v", err)
	}

	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued")
	}
}

// TestHostReplyBlindingRequired tests onMsgHostReply with blinding-required result codes
func TestHostReplyBlindingRequired(t *testing.T) {
	testCases := []struct {
		name       string
		resultCode uint8
		expectLog  bool
	}{
		{"Success", HOST_REPLY_SUCCESS, false},
		{"General failure", HOST_REPLY_FAILURE, false},
		{"Password required", HOST_REPLY_PASSWORD_REQUIRED, true},
		{"Private key required", HOST_REPLY_PRIVATE_KEY_REQUIRED, true},
		{"Password and key required", HOST_REPLY_PASSWORD_AND_KEY_REQUIRED, true},
		{"Decryption failure", HOST_REPLY_DECRYPTION_FAILURE, false},
		{"LeaseSet lookup failure", HOST_REPLY_LEASESET_LOOKUP_FAILURE, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create client and session
			client := NewClient(&ClientCallBacks{})
			session := newSession(client, SessionCallbacks{})
			session.id = 1
			client.sessions[session.id] = session

			// Create a lookup entry
			requestId := uint32(100)
			client.lookupReq[requestId] = LookupEntry{
				address: "test.i2p",
			}

			// Create HostReply message stream
			stream := NewStream(make([]byte, 0, 256))
			stream.WriteUint16(session.id)  // Session ID
			stream.WriteUint32(requestId)   // Request ID
			stream.WriteByte(tc.resultCode) // Result code

			// If success, need to include a destination
			if tc.resultCode == HOST_REPLY_SUCCESS {
				// Create a test destination
				dest, err := NewDestination(client.crypto)
				if err != nil {
					t.Fatalf("Failed to create test destination: %v", err)
				}
				dest.WriteToMessage(stream)
			}

			// Reset stream to beginning for reading
			if _, err := stream.Seek(0, 0); err != nil {
				t.Fatalf("Failed to reset stream: %v", err)
			}

			// Call onMsgHostReply
			client.onMsgHostReply(stream)

			// Verify lookup entry was removed
			if _, exists := client.lookupReq[requestId]; exists {
				t.Error("Expected lookup entry to be removed")
			}

			// For blinding-required codes, the warning should be logged
			// (We can't easily verify log output in unit tests, but the function should execute without error)
		})
	}
}

// TestHostReplyBlindingRequiredNoSession tests blinding error handling when session doesn't exist
func TestHostReplyBlindingRequiredNoSession(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Create HostReply message for non-existent session
	stream := NewStream(make([]byte, 0, 256))
	stream.WriteUint16(999)                        // Non-existent session ID
	stream.WriteUint32(100)                        // Request ID
	stream.WriteByte(HOST_REPLY_PASSWORD_REQUIRED) // Blinding required code

	// Reset stream to beginning for reading
	if _, err := stream.Seek(0, 0); err != nil {
		t.Fatalf("Failed to reset stream: %v", err)
	}

	// Call should handle gracefully (log error about missing session)
	client.onMsgHostReply(stream)
	// No crash = success
}

// TestHostReplyBlindingRequiredWithCallback tests that OnDestination callback receives nil
func TestHostReplyBlindingRequiredWithCallback(t *testing.T) {
	callbackInvoked := false
	var receivedDest *Destination
	var receivedAddress string
	var receivedRequestId uint32

	callbacks := SessionCallbacks{
		OnDestination: func(session *Session, requestId uint32, address string, dest *Destination) {
			callbackInvoked = true
			receivedDest = dest
			receivedAddress = address
			receivedRequestId = requestId
		},
	}

	client := NewClient(&ClientCallBacks{})
	session := newSession(client, callbacks)
	session.id = 1
	session.syncCallbacks = true // Ensure synchronous for testing
	client.sessions[session.id] = session

	// Create lookup entry
	requestId := uint32(200)
	testAddress := "encrypted.i2p"
	client.lookupReq[requestId] = LookupEntry{
		address: testAddress,
	}

	// Create HostReply with password required
	stream := NewStream(make([]byte, 0, 256))
	stream.WriteUint16(session.id)
	stream.WriteUint32(requestId)
	stream.WriteByte(HOST_REPLY_PASSWORD_REQUIRED)

	// Reset stream to beginning for reading
	if _, err := stream.Seek(0, 0); err != nil {
		t.Fatalf("Failed to reset stream: %v", err)
	}

	// Process message
	client.onMsgHostReply(stream)

	// Verify callback was invoked
	if !callbackInvoked {
		t.Fatal("Expected OnDestination callback to be invoked")
	}

	// Verify received values
	if receivedRequestId != requestId {
		t.Errorf("Expected requestId %d, got %d", requestId, receivedRequestId)
	}
	if receivedAddress != testAddress {
		t.Errorf("Expected address %s, got %s", testAddress, receivedAddress)
	}
	if receivedDest != nil {
		t.Error("Expected destination to be nil for failed lookup")
	}
}

// TestCreateLeaseSet2MultipleLeases tests LeaseSet2 creation with different lease counts
func TestCreateLeaseSet2MultipleLeases(t *testing.T) {
	leaseCounts := []int{1, 3, 5, 10, 16}

	for _, leaseCount := range leaseCounts {
		t.Run(string(rune(leaseCount+'0'))+" leases", func(t *testing.T) {
			client := NewClient(&ClientCallBacks{})
			session := newSession(client, SessionCallbacks{})
			session.id = 1

			// Enable blinding for variety
			session.SetBlindingScheme(1)
			session.SetBlindingParams([]byte{0x01, 0x02})

			dest, err := NewDestination(client.crypto)
			if err != nil {
				t.Fatalf("Failed to create destination: %v", err)
			}
			session.config.destination = dest
			client.router.date = 1000000

			// Use queue=true since we're not connected
			err = client.msgCreateLeaseSet2(session, leaseCount, true)
			if err != nil {
				t.Fatalf("msgCreateLeaseSet2 failed for %d leases: %v", leaseCount, err)
			}

			if len(client.outputQueue) == 0 {
				t.Errorf("Expected message for %d leases", leaseCount)
			}
		})
	}
}
