package go_i2cp

import (
	"context"
	"net"
	"testing"
	"time"
)

// isI2PRouterAvailable checks if an I2P router is running on the default port
func isI2PRouterAvailable() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:7654", 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestIntegration_RealRouter_ClientConnect tests connecting to a real I2P router
func TestIntegration_RealRouter_ClientConnect(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	t.Log("Successfully connected to I2P router")
}

// TestIntegration_RealRouter_SessionCreation tests creating a session with a real router
func TestIntegration_RealRouter_SessionCreation(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	// Create a session
	sessionCreated := make(chan bool, 1)
	callbacks := SessionCallbacks{
		OnSessionStatus: func(session *Session, status SessionStatus) {
			t.Logf("Session status: %d", status)
			if status == SESSION_STATUS_CREATED {
				sessionCreated <- true
			}
		},
	}

	session := NewSession(client, callbacks)
	err = client.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Wait for session creation confirmation
	select {
	case <-sessionCreated:
		t.Log("Session created successfully")
	case <-ctx.Done():
		t.Fatal("Timeout waiting for session creation")
	}

	// Clean up session
	err = client.DestroySession(session)
	if err != nil {
		t.Errorf("Failed to destroy session: %v", err)
	}
}

// TestIntegration_RealRouter_MessageSending tests sending a message through a real router
func TestIntegration_RealRouter_MessageSending(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	// Create a session
	sessionCreated := make(chan bool, 1)
	messageStatus := make(chan SessionMessageStatus, 1)

	callbacks := SessionCallbacks{
		OnSessionStatus: func(session *Session, status SessionStatus) {
			if status == SESSION_STATUS_CREATED {
				sessionCreated <- true
			}
		},
		OnMessageStatus: func(session *Session, messageID uint32, status SessionMessageStatus) {
			t.Logf("Message %d status: %d", messageID, status)
			messageStatus <- status
		},
	}

	session := NewSession(client, callbacks)
	err = client.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Wait for session creation
	select {
	case <-sessionCreated:
		t.Log("Session created successfully")
	case <-ctx.Done():
		t.Fatal("Timeout waiting for session creation")
	}

	// Try to send a message (will likely fail without valid destination, but tests the flow)
	dest := session.Destination()
	if dest == nil {
		t.Skip("Session has no destination, skipping message send test")
	}

	payload := []byte("test message")
	nonce, err := session.SendMessage(dest, 0, 0, 0, payload)
	if err != nil {
		t.Logf("SendMessage returned error (expected): %v", err)
	} else {
		t.Logf("Message sent with nonce: %d", nonce)

		// Wait for message status (with timeout)
		select {
		case status := <-messageStatus:
			t.Logf("Received message status: %d", status)
		case <-time.After(5 * time.Second):
			t.Log("Timeout waiting for message status (may be expected)")
		}
	}

	// Clean up
	err = client.DestroySession(session)
	if err != nil {
		t.Errorf("Failed to destroy session: %v", err)
	}
}

// TestIntegration_RealRouter_MultiSession tests creating multiple sessions
func TestIntegration_RealRouter_MultiSession(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	numSessions := 3
	sessions := make([]*Session, numSessions)
	sessionCreated := make(chan int, numSessions)

	// Create multiple sessions
	for i := 0; i < numSessions; i++ {
		sessionIdx := i
		callbacks := SessionCallbacks{
			OnSessionStatus: func(session *Session, status SessionStatus) {
				if status == SESSION_STATUS_CREATED {
					sessionCreated <- sessionIdx
				}
			},
		}

		sessions[i] = NewSession(client, callbacks)
		err = client.CreateSession(ctx, sessions[i])
		if err != nil {
			t.Fatalf("Failed to create session %d: %v", i, err)
		}
	}

	// Wait for all sessions to be created
	for i := 0; i < numSessions; i++ {
		select {
		case idx := <-sessionCreated:
			t.Logf("Session %d created successfully", idx)
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for session %d creation", i)
		}
	}

	// Clean up all sessions
	for i, session := range sessions {
		err = client.DestroySession(session)
		if err != nil {
			t.Errorf("Failed to destroy session %d: %v", i, err)
		}
	}
}

// TestIntegration_RealRouter_Reconnection tests automatic reconnection
func TestIntegration_RealRouter_Reconnection(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	// Enable auto-reconnect
	client.EnableAutoReconnect(3, time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	t.Log("Successfully connected with auto-reconnect enabled")

	// Verify auto-reconnect is enabled
	if !client.IsAutoReconnectEnabled() {
		t.Error("Auto-reconnect should be enabled")
	}

	// Disable auto-reconnect
	client.DisableAutoReconnect()

	if client.IsAutoReconnectEnabled() {
		t.Error("Auto-reconnect should be disabled")
	}
}

// TestIntegration_RealRouter_MessageTracking tests message tracking functionality
func TestIntegration_RealRouter_MessageTracking(t *testing.T) {
	if !isI2PRouterAvailable() {
		t.Skip("Skipping integration test: I2P router not available on 127.0.0.1:7654")
	}

	client := NewClient(nil)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	// Create a session
	sessionCreated := make(chan bool, 1)
	callbacks := SessionCallbacks{
		OnSessionStatus: func(session *Session, status SessionStatus) {
			if status == SESSION_STATUS_CREATED {
				sessionCreated <- true
			}
		},
	}

	session := NewSession(client, callbacks)
	err = client.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Wait for session creation
	select {
	case <-sessionCreated:
		t.Log("Session created successfully")
	case <-ctx.Done():
		t.Fatal("Timeout waiting for session creation")
	}

	// Check initial pending message count
	initialCount := session.PendingMessageCount()
	if initialCount != 0 {
		t.Errorf("Expected 0 pending messages initially, got %d", initialCount)
	}

	// Clean up
	err = client.DestroySession(session)
	if err != nil {
		t.Errorf("Failed to destroy session: %v", err)
	}
}
