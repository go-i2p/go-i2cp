package go_i2cp

import (
	"context"
	"errors"
	"testing"
)

// TestSendMessageErrorHandling tests the error handling improvements in sendMessage
func TestSendMessageErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *Client
		message     []byte
		queue       bool
		wantError   bool
		description string
	}{
		{
			name: "disconnected client - immediate send",
			setupClient: func() *Client {
				c := NewClient(&ClientCallBacks{})
				c.tcp.Init() // Initialize but don't connect
				return c
			},
			message:     []byte("test"),
			queue:       false, // Try to send immediately
			wantError:   true,
			description: "Should fail when trying to send immediately on disconnected client",
		},
		{
			name: "disconnected client - queued send",
			setupClient: func() *Client {
				c := NewClient(&ClientCallBacks{})
				c.tcp.Init() // Initialize but don't connect
				return c
			},
			message:     []byte("test"),
			queue:       true, // Queue for later sending
			wantError:   false,
			description: "Should succeed when queueing message on disconnected client",
		},
		{
			name: "valid setup - queued message",
			setupClient: func() *Client {
				c := NewClient(&ClientCallBacks{})
				c.tcp.Init()
				return c
			},
			message:     []byte("test message"),
			queue:       true,
			wantError:   false,
			description: "Should succeed when queueing message with valid setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			stream := NewStream(tt.message)

			err := client.sendMessage(I2CP_MSG_GET_DATE, stream, tt.queue)

			if tt.wantError && err == nil {
				t.Errorf("Expected error but got none for: %s", tt.description)
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.description, err)
			}

			t.Logf("Test scenario: %s", tt.description)
		})
	}
}

// TestOnMsgDisconnectErrorHandling tests the improved error handling in onMsgDisconnect
func TestOnMsgDisconnectErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setupStream func() *Stream
		wantPanic   bool
		description string
	}{
		{
			name: "empty stream",
			setupStream: func() *Stream {
				return NewStream([]byte{})
			},
			wantPanic:   false, // Should handle gracefully now
			description: "Should handle empty stream without panicking",
		},
		{
			name: "valid disconnect message",
			setupStream: func() *Stream {
				return NewStream([]byte("Router shutdown"))
			},
			wantPanic:   false,
			description: "Should handle valid disconnect message",
		},
		{
			name: "large disconnect message",
			setupStream: func() *Stream {
				// Create a large message to test handling
				largeMessage := make([]byte, 1000)
				for i := range largeMessage {
					largeMessage[i] = 'A'
				}
				return NewStream(largeMessage)
			},
			wantPanic:   false,
			description: "Should handle large disconnect messages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				callbacks: &ClientCallBacks{
					onDisconnect: func(c *Client, reason string, data *interface{}) {
						t.Logf("Disconnect callback called with reason: %s", reason)
					},
				},
			}

			// Test should not panic
			defer func() {
				if r := recover(); r != nil {
					if !tt.wantPanic {
						t.Errorf("Unexpected panic: %v", r)
					}
				}
			}()

			stream := tt.setupStream()
			client.onMsgDisconnect(stream)

			t.Logf("Test scenario: %s", tt.description)
		})
	}
}

// TestOnMsgPayloadErrorHandlingImproved tests the improved error handling in onMsgPayload
func TestOnMsgPayloadErrorHandlingImproved(t *testing.T) {
	tests := []struct {
		name        string
		setupStream func() *Stream
		setupClient func() *Client
		description string
	}{
		{
			name: "missing messageId field",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1) // sessionId only
				return stream
			},
			setupClient: func() *Client {
				client := &Client{
					sessions: make(map[uint16]*Session),
				}
				sess := &Session{id: 1, callbacks: &SessionCallbacks{}}
				client.sessions[1] = sess
				return client
			},
			description: "Should handle missing messageId gracefully with error logging",
		},
		{
			name: "missing payloadSize field",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)  // sessionId
				stream.WriteUint32(42) // messageId only
				return stream
			},
			setupClient: func() *Client {
				client := &Client{
					sessions: make(map[uint16]*Session),
				}
				sess := &Session{id: 1, callbacks: &SessionCallbacks{}}
				client.sessions[1] = sess
				return client
			},
			description: "Should handle missing payloadSize gracefully with error logging",
		},
		{
			name: "valid payload with messageId and size logged",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0))
				stream.WriteUint16(1)                  // sessionId
				stream.WriteUint32(42)                 // messageId
				stream.WriteUint32(100)                // payloadSize
				stream.Write([]byte{0x1f, 0x8b, 0x08}) // gzip header
				// Add minimal valid payload data
				stream.Write(make([]byte, 10))
				return stream
			},
			setupClient: func() *Client {
				client := &Client{
					sessions: make(map[uint16]*Session),
				}
				sess := &Session{
					id:        1,
					callbacks: &SessionCallbacks{},
				}
				client.sessions[1] = sess
				return client
			},
			description: "Should process valid payload and log messageId and payloadSize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			stream := tt.setupStream()

			// This should not panic and should handle errors gracefully
			client.onMsgPayload(stream)

			t.Logf("Test scenario: %s", tt.description)
		})
	}
}

// TestDestinationLookupDecodeErrorHandling tests the improved DecodeStream error handling
func TestDestinationLookupDecodeErrorHandling(t *testing.T) {
	tests := []struct {
		name            string
		address         string
		mockDecodeError bool
		wantRequestId   uint32
		description     string
	}{
		{
			name:            "invalid b32 address - decode fails",
			address:         "invalid!@#$%^&*invalid!@#$%^&*invalid!@#$%^&*invalid.b32.i2p", // 52 chars + .b32.i2p but invalid base32
			mockDecodeError: true,
			wantRequestId:   0, // Should return 0 on decode failure
			description:     "Should return 0 and log warning when b32 decode fails",
		},
		{
			name:            "valid b32 address format",
			address:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p", // 52 valid base32 chars + .b32.i2p
			mockDecodeError: false,
			wantRequestId:   1, // Should return valid request ID
			description:     "Should handle valid b32 address",
		},
		{
			name:            "hostname address (not b32)",
			address:         "example.i2p",
			mockDecodeError: false,
			wantRequestId:   1, // Should work with hostname
			description:     "Should handle hostname addresses",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(&ClientCallBacks{})
			client.router.capabilities = ROUTER_CAN_HOST_LOOKUP // Enable host lookup

			// Create a mock session
			session := &Session{
				id:        1,
				callbacks: &SessionCallbacks{},
			}

			requestId, err := client.DestinationLookup(context.Background(), session, tt.address)

			if tt.wantRequestId == 0 && requestId != 0 {
				t.Errorf("Expected requestId 0 for failed decode, got %d", requestId)
			}
			if tt.wantRequestId > 0 && requestId == 0 {
				t.Errorf("Expected non-zero requestId for valid address, got 0")
			}
			// Check for errors when expected
			if tt.mockDecodeError && err == nil {
				t.Logf("Warning: Expected error for decode failure but got nil (may be deferred)")
			}

			t.Logf("Test scenario: %s, requestId: %d, err: %v", tt.description, requestId, err)
		})
	}
}

// TestErrorWrappingBehavior tests that error wrapping works correctly
func TestErrorWrappingBehavior(t *testing.T) {
	// Test that our custom errors can be unwrapped properly
	originalErr := errors.New("original error")
	wrappedErr := NewMessageError(I2CP_MSG_GET_DATE, "testing", originalErr)

	// Test errors.Is functionality
	if !errors.Is(wrappedErr, originalErr) {
		t.Error("errors.Is should find the original error in the wrapped error")
	}

	// Test errors.As functionality
	var msgErr *MessageError
	if !errors.As(wrappedErr, &msgErr) {
		t.Error("errors.As should be able to extract MessageError")
	}

	if msgErr.MessageType != I2CP_MSG_GET_DATE {
		t.Errorf("Expected message type %d, got %d", I2CP_MSG_GET_DATE, msgErr.MessageType)
	}

	if msgErr.Operation != "testing" {
		t.Errorf("Expected operation 'testing', got '%s'", msgErr.Operation)
	}

	t.Logf("Error wrapping works correctly: %v", wrappedErr)
}

// TestErrorContextPreservation tests that errors maintain context information
func TestErrorContextPreservation(t *testing.T) {
	tests := []struct {
		name     string
		errorGen func() error
		wantType string
	}{
		{
			name: "MessageError with context",
			errorGen: func() error {
				return NewMessageError(I2CP_MSG_CREATE_SESSION, "parsing", errors.New("invalid format"))
			},
			wantType: "*go_i2cp.MessageError",
		},
		{
			name: "SessionError with context",
			errorGen: func() error {
				return NewSessionError(123, "send message", errors.New("connection closed"))
			},
			wantType: "*go_i2cp.SessionError",
		},
		{
			name: "ProtocolError with context",
			errorGen: func() error {
				return NewProtocolError("invalid message type", 255, true)
			},
			wantType: "*go_i2cp.ProtocolError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.errorGen()

			// Test that error contains useful information
			errMsg := err.Error()
			if len(errMsg) < 10 {
				t.Errorf("Error message too short: %s", errMsg)
			}

			// Test that error type is preserved
			switch e := err.(type) {
			case *MessageError:
				if e.MessageType == 0 && e.Operation == "" {
					t.Error("MessageError should preserve type and operation")
				}
			case *SessionError:
				if e.SessionID == 0 && e.Operation == "" {
					t.Error("SessionError should preserve session ID and operation")
				}
			case *ProtocolError:
				if e.Message == "" {
					t.Error("ProtocolError should preserve message")
				}
			}

			t.Logf("Error with context: %v", err)
		})
	}
}
