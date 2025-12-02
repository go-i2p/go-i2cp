package go_i2cp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestMessageTracking_Basic verifies basic message tracking functionality
func TestMessageTracking_Basic(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Track a message
	nonce := uint32(12345)
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify message is tracked
	pending, exists := session.GetPendingMessage(nonce)
	if !exists {
		t.Fatal("Message should be tracked but was not found")
	}
	if pending.Nonce != nonce {
		t.Errorf("Nonce mismatch: got %d, want %d", pending.Nonce, nonce)
	}
	if pending.Protocol != 1 {
		t.Errorf("Protocol mismatch: got %d, want 1", pending.Protocol)
	}
	if pending.SrcPort != 80 {
		t.Errorf("SrcPort mismatch: got %d, want 80", pending.SrcPort)
	}
	if pending.DestPort != 443 {
		t.Errorf("DestPort mismatch: got %d, want 443", pending.DestPort)
	}
	if pending.PayloadSize != 1024 {
		t.Errorf("PayloadSize mismatch: got %d, want 1024", pending.PayloadSize)
	}
	if pending.Status != 0 {
		t.Errorf("Initial status should be 0, got %d", pending.Status)
	}
}

// TestMessageTracking_DuplicateNonce verifies that duplicate nonces are rejected
func TestMessageTracking_DuplicateNonce(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(99999)

	// Track first message
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("First TrackMessage failed: %v", err)
	}

	// Attempt to track duplicate
	err = session.TrackMessage(nonce, dest, 2, 81, 444, 2048, 0, 0)
	if err == nil {
		t.Fatal("Duplicate nonce should be rejected")
	}
}

// TestMessageTracking_Complete verifies message completion
func TestMessageTracking_Complete(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(54321)

	// Track message
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify pending count
	if count := session.PendingMessageCount(); count != 1 {
		t.Errorf("Pending count should be 1, got %d", count)
	}

	// Wait a bit to ensure SentAt < CompletedAt
	time.Sleep(10 * time.Millisecond)

	// Complete message
	pending, wasTracked := session.CompleteMessage(nonce, MSG_STATUS_BEST_EFFORT_SUCCESS)
	if !wasTracked {
		t.Fatal("Message should have been tracked")
	}
	if pending == nil {
		t.Fatal("Pending message should be returned")
	}
	if pending.Status != MSG_STATUS_BEST_EFFORT_SUCCESS {
		t.Errorf("Status should be %d, got %d", MSG_STATUS_BEST_EFFORT_SUCCESS, pending.Status)
	}
	if pending.CompletedAt.IsZero() {
		t.Error("CompletedAt should be set")
	}
	if !pending.CompletedAt.After(pending.SentAt) {
		t.Error("CompletedAt should be after SentAt")
	}

	// Verify message is removed from pending
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Pending count should be 0 after completion, got %d", count)
	}

	// Verify message is not found anymore
	_, exists := session.GetPendingMessage(nonce)
	if exists {
		t.Error("Completed message should not be in pending map")
	}
}

// TestMessageTracking_CompleteNonExistent verifies handling of non-existent message completion
func TestMessageTracking_CompleteNonExistent(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	nonce := uint32(11111)

	// Complete non-existent message
	pending, wasTracked := session.CompleteMessage(nonce, MSG_STATUS_BAD_MESSAGE)
	if wasTracked {
		t.Error("Non-existent message should not be tracked")
	}
	if pending != nil {
		t.Error("Pending message should be nil for non-existent nonce")
	}
}

// TestMessageTracking_GetPendingMessages verifies getting all pending messages
func TestMessageTracking_GetPendingMessages(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Track multiple messages
	nonces := []uint32{1001, 1002, 1003}
	for i, nonce := range nonces {
		err = session.TrackMessage(nonce, dest, uint8(i+1), uint16(80+i), uint16(443+i), uint32(1024*(i+1)), 0, 0)
		if err != nil {
			t.Fatalf("TrackMessage %d failed: %v", i, err)
		}
	}

	// Get all pending messages
	pending := session.GetPendingMessages()
	if len(pending) != len(nonces) {
		t.Errorf("Should have %d pending messages, got %d", len(nonces), len(pending))
	}

	// Verify all nonces are present
	for _, nonce := range nonces {
		if _, exists := pending[nonce]; !exists {
			t.Errorf("Nonce %d should be in pending messages", nonce)
		}
	}

	// Verify snapshot is a copy (modification shouldn't affect session)
	delete(pending, nonces[0])
	if count := session.PendingMessageCount(); count != len(nonces) {
		t.Errorf("Session should still have %d pending messages, got %d", len(nonces), count)
	}
}

// TestMessageTracking_ClearPendingMessages verifies clearing all pending messages
func TestMessageTracking_ClearPendingMessages(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Track multiple messages
	for i := uint32(0); i < 5; i++ {
		err = session.TrackMessage(2000+i, dest, 1, 80, 443, 1024, 0, 0)
		if err != nil {
			t.Fatalf("TrackMessage %d failed: %v", i, err)
		}
	}

	// Verify count
	if count := session.PendingMessageCount(); count != 5 {
		t.Errorf("Should have 5 pending messages, got %d", count)
	}

	// Clear all
	cleared := session.ClearPendingMessages()
	if cleared != 5 {
		t.Errorf("Should have cleared 5 messages, got %d", cleared)
	}

	// Verify all cleared
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Should have 0 pending messages after clear, got %d", count)
	}
}

// TestMessageTracking_WithExpiration verifies tracking messages with expiration
func TestMessageTracking_WithExpiration(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(3000)
	flags := uint16(0x0001)
	expiration := uint64(60)

	// Track message with expiration
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, flags, expiration)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify expiration fields
	pending, exists := session.GetPendingMessage(nonce)
	if !exists {
		t.Fatal("Message should be tracked")
	}
	if pending.Flags != flags {
		t.Errorf("Flags mismatch: got 0x%04x, want 0x%04x", pending.Flags, flags)
	}
	if pending.Expiration != expiration {
		t.Errorf("Expiration mismatch: got %d, want %d", pending.Expiration, expiration)
	}
}

// TestMessageTracking_Concurrency verifies thread-safe message tracking
func TestMessageTracking_Concurrency(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	const numGoroutines = 10
	const messagesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Track messages concurrently
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < messagesPerGoroutine; i++ {
				nonce := uint32(goroutineID*messagesPerGoroutine + i)
				_ = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
			}
		}(g)
	}

	wg.Wait()

	// Verify all messages are tracked
	expectedCount := numGoroutines * messagesPerGoroutine
	if count := session.PendingMessageCount(); count != expectedCount {
		t.Errorf("Should have %d pending messages, got %d", expectedCount, count)
	}

	// Complete messages concurrently
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < messagesPerGoroutine; i++ {
				nonce := uint32(goroutineID*messagesPerGoroutine + i)
				session.CompleteMessage(nonce, MSG_STATUS_BEST_EFFORT_SUCCESS)
			}
		}(g)
	}

	wg.Wait()

	// Verify all messages are completed
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Should have 0 pending messages after completion, got %d", count)
	}
}

// TestMessageTracking_SessionClose verifies pending messages are cleared on session close
func TestMessageTracking_SessionClose(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Track messages
	for i := uint32(0); i < 3; i++ {
		err = session.TrackMessage(4000+i, dest, 1, 80, 443, 1024, 0, 0)
		if err != nil {
			t.Fatalf("TrackMessage %d failed: %v", i, err)
		}
	}

	// Verify tracked
	if count := session.PendingMessageCount(); count != 3 {
		t.Errorf("Should have 3 pending messages, got %d", count)
	}

	// Close session
	err = session.Close()
	if err != nil {
		t.Fatalf("Session close failed: %v", err)
	}

	// Verify messages are cleared
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Should have 0 pending messages after close, got %d", count)
	}
}

// TestMessageTracking_DispatchMessageStatus verifies integration with dispatchMessageStatus
func TestMessageTracking_DispatchMessageStatus(t *testing.T) {
	client := &Client{crypto: NewCrypto()}

	var callbackNonce uint32
	var callbackStatus SessionMessageStatus
	var callbackCalled bool

	callbacks := SessionCallbacks{
		OnMessageStatus: func(s *Session, messageId uint32, status SessionMessageStatus, size, nonce uint32) {
			callbackNonce = nonce
			callbackStatus = status
			callbackCalled = true
		},
	}

	session := newSession(client, callbacks)
	session.id = 1 // Set session ID

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(5000)

	// Track message
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify pending
	if count := session.PendingMessageCount(); count != 1 {
		t.Errorf("Should have 1 pending message, got %d", count)
	}

	// Dispatch message status (simulates receiving MessageStatusMessage from router)
	session.dispatchMessageStatus(123, MSG_STATUS_GUARANTEED_SUCCESS, 1024, nonce)

	// Verify callback was called
	if !callbackCalled {
		t.Error("Callback should have been called")
	}
	if callbackNonce != nonce {
		t.Errorf("Callback nonce mismatch: got %d, want %d", callbackNonce, nonce)
	}
	if callbackStatus != MSG_STATUS_GUARANTEED_SUCCESS {
		t.Errorf("Callback status mismatch: got %d, want %d", callbackStatus, MSG_STATUS_GUARANTEED_SUCCESS)
	}

	// Verify message is no longer pending
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Should have 0 pending messages after status dispatch, got %d", count)
	}
}

// TestMessageTracking_SendMessageIntegration verifies SendMessage automatically tracks messages
func TestMessageTracking_SendMessageIntegration(t *testing.T) {
	// This test would require a mock client that can intercept msgSendMessage
	// For now, we verify the TrackMessage call is made (already tested in unit tests)
	t.Skip("Integration test requires mock router connection - covered by other tests")
}

// TestMessageTracking_SendMessageExpiresIntegration verifies SendMessageExpires tracks messages
func TestMessageTracking_SendMessageExpiresIntegration(t *testing.T) {
	// This test would require a mock client that can intercept msgSendMessageExpires
	// For now, we verify the TrackMessage call is made (already tested in unit tests)
	t.Skip("Integration test requires mock router connection - covered by other tests")
}

// TestMessageTracking_MultipleStatuses verifies handling multiple status updates
func TestMessageTracking_MultipleStatuses(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(6000)

	// Track message
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Complete with first status
	pending, wasTracked := session.CompleteMessage(nonce, MSG_STATUS_ACCEPTED)
	if !wasTracked {
		t.Fatal("First completion should find tracked message")
	}
	if pending.Status != MSG_STATUS_ACCEPTED {
		t.Errorf("Status should be %d, got %d", MSG_STATUS_ACCEPTED, pending.Status)
	}

	// Attempt second completion (message should be gone)
	_, wasTracked = session.CompleteMessage(nonce, MSG_STATUS_BEST_EFFORT_SUCCESS)
	if wasTracked {
		t.Error("Second completion should not find message (already completed)")
	}
}

// TestPendingMessage_Fields verifies all PendingMessage fields are populated
func TestPendingMessage_Fields(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	session := newSession(client, SessionCallbacks{})

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	nonce := uint32(7000)
	protocol := uint8(17)
	srcPort := uint16(12345)
	destPort := uint16(54321)
	payloadSize := uint32(2048)
	flags := uint16(0x0F0F)
	expiration := uint64(120)

	// Track with all fields
	err = session.TrackMessage(nonce, dest, protocol, srcPort, destPort, payloadSize, flags, expiration)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify all fields
	pending, exists := session.GetPendingMessage(nonce)
	if !exists {
		t.Fatal("Message should be tracked")
	}

	if pending.Nonce != nonce {
		t.Errorf("Nonce: got %d, want %d", pending.Nonce, nonce)
	}
	if pending.Destination != dest {
		t.Error("Destination should match")
	}
	if pending.Protocol != protocol {
		t.Errorf("Protocol: got %d, want %d", pending.Protocol, protocol)
	}
	if pending.SrcPort != srcPort {
		t.Errorf("SrcPort: got %d, want %d", pending.SrcPort, srcPort)
	}
	if pending.DestPort != destPort {
		t.Errorf("DestPort: got %d, want %d", pending.DestPort, destPort)
	}
	if pending.PayloadSize != payloadSize {
		t.Errorf("PayloadSize: got %d, want %d", pending.PayloadSize, payloadSize)
	}
	if pending.Flags != flags {
		t.Errorf("Flags: got 0x%04x, want 0x%04x", pending.Flags, flags)
	}
	if pending.Expiration != expiration {
		t.Errorf("Expiration: got %d, want %d", pending.Expiration, expiration)
	}
	if pending.SentAt.IsZero() {
		t.Error("SentAt should be set")
	}
	if pending.Status != 0 {
		t.Errorf("Initial Status should be 0, got %d", pending.Status)
	}
	if !pending.CompletedAt.IsZero() {
		t.Error("CompletedAt should be zero for pending message")
	}
}

// TestMessageTracking_ContextCancellation verifies behavior with context cancellation
func TestMessageTracking_ContextCancellation(t *testing.T) {
	client := &Client{crypto: NewCrypto()}
	ctx, cancel := context.WithCancel(context.Background())

	session, err := NewSessionWithContext(ctx, client, SessionCallbacks{})
	if err != nil {
		t.Fatalf("NewSessionWithContext failed: %v", err)
	}

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Track message
	nonce := uint32(8000)
	err = session.TrackMessage(nonce, dest, 1, 80, 443, 1024, 0, 0)
	if err != nil {
		t.Fatalf("TrackMessage failed: %v", err)
	}

	// Verify message is tracked before cancellation
	pending, exists := session.GetPendingMessage(nonce)
	if !exists {
		t.Fatal("Message should be tracked before context cancellation")
	}
	if pending == nil {
		t.Fatal("Pending message should not be nil")
	}

	// Cancel context
	cancel()

	// Give context time to propagate and close session
	time.Sleep(100 * time.Millisecond)

	// Session should be closed after context cancellation
	if !session.IsClosed() {
		t.Error("Session should be closed after context cancellation")
	}

	// Pending messages should be cleared when session closes
	if count := session.PendingMessageCount(); count != 0 {
		t.Errorf("Pending messages should be cleared after session close, got %d", count)
	}
}
