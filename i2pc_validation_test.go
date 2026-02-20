package go_i2cp

import (
	"strings"
	"testing"
)

// TestMessageSizeValidation verifies that SendMessage enforces I2CP 64KB payload limit
func TestMessageSizeValidation(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Create a destination
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	t.Run("payload exceeds 64KB limit", func(t *testing.T) {
		// Create a payload larger than 64KB (65536 bytes)
		largePayload := make([]byte, 70000)
		stream := NewStream(largePayload)

		err := session.SendMessage(dest, 0, 0, 0, stream, 12345)
		if err == nil {
			t.Fatal("Expected error for oversized message, got nil")
		}

		expectedMsg := "exceeds I2CP maximum"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("Expected error containing '%s', got: %v", expectedMsg, err)
		}

		t.Logf("✓ Correctly rejected oversized message: %v", err)
	})

	t.Run("payload at 64KB limit", func(t *testing.T) {
		// Create a payload exactly at 64KB
		exactPayload := make([]byte, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
		stream := NewStream(exactPayload)

		err := session.SendMessage(dest, 0, 0, 0, stream, 12346)
		// Should not error due to size (but may error for other reasons like no connection)
		if err != nil && strings.Contains(err.Error(), "exceeds I2CP maximum") {
			t.Errorf("Should accept message at 64KB limit, got size error: %v", err)
		}

		t.Logf("✓ Accepted message at 64KB limit")
	})

	t.Run("payload below 64KB limit", func(t *testing.T) {
		// Create a payload smaller than 64KB
		smallPayload := make([]byte, 60000)
		stream := NewStream(smallPayload)

		err := session.SendMessage(dest, 0, 0, 0, stream, 12347)
		// Should not error due to size (but may error for other reasons like no connection)
		if err != nil && strings.Contains(err.Error(), "exceeds I2CP maximum") {
			t.Errorf("Should accept message under 64KB limit, got size error: %v", err)
		}

		t.Logf("✓ Accepted message under 64KB limit")
	})
}
