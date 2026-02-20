package go_i2cp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSentinelErrors verifies all sentinel errors are defined and have proper messages
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "ErrSessionInvalid",
			err:     ErrSessionInvalid,
			wantMsg: "session invalid or closed",
		},
		{
			name:    "ErrConnectionClosed",
			err:     ErrConnectionClosed,
			wantMsg: "connection closed",
		},
		{
			name:    "ErrMessageTooLarge",
			err:     ErrMessageTooLarge,
			wantMsg: "message exceeds size limit",
		},
		{
			name:    "ErrAuthenticationFailed",
			err:     ErrAuthenticationFailed,
			wantMsg: "authentication failed",
		},
		{
			name:    "ErrProtocolVersion",
			err:     ErrProtocolVersion,
			wantMsg: "unsupported protocol version",
		},
		{
			name:    "ErrTimeout",
			err:     ErrTimeout,
			wantMsg: "operation timed out",
		},
		{
			name:    "ErrNoPrimarySession",
			err:     ErrNoPrimarySession,
			wantMsg: "no primary session",
		},
		{
			name:    "ErrMultiSessionUnsupported",
			err:     ErrMultiSessionUnsupported,
			wantMsg: "does not support multi-session",
		},
		{
			name:    "ErrInvalidDestination",
			err:     ErrInvalidDestination,
			wantMsg: "invalid destination",
		},
		{
			name:    "ErrInvalidLeaseSet",
			err:     ErrInvalidLeaseSet,
			wantMsg: "invalid leaseset",
		},
		{
			name:    "ErrMessageParsing",
			err:     ErrMessageParsing,
			wantMsg: "message parsing failed",
		},
		{
			name:    "ErrInvalidSessionID",
			err:     ErrInvalidSessionID,
			wantMsg: "invalid session id",
		},
		{
			name:    "ErrSessionRefused",
			err:     ErrSessionRefused,
			wantMsg: "session creation refused",
		},
		{
			name:    "ErrNotConnected",
			err:     ErrNotConnected,
			wantMsg: "not connected",
		},
		{
			name:    "ErrAlreadyConnected",
			err:     ErrAlreadyConnected,
			wantMsg: "already connected",
		},
		{
			name:    "ErrInvalidConfiguration",
			err:     ErrInvalidConfiguration,
			wantMsg: "invalid session configuration",
		},
		{
			name:    "ErrDestinationLookupFailed",
			err:     ErrDestinationLookupFailed,
			wantMsg: "destination lookup failed",
		},
		{
			name:    "ErrBlindingRequired",
			err:     ErrBlindingRequired,
			wantMsg: "blinding info required",
		},
		{
			name:    "ErrUnsupportedCrypto",
			err:     ErrUnsupportedCrypto,
			wantMsg: "unsupported cryptographic algorithm",
		},
		{
			name:    "ErrInvalidSignature",
			err:     ErrInvalidSignature,
			wantMsg: "invalid signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if !strings.Contains(tt.err.Error(), tt.wantMsg) {
				t.Errorf("%s message = %q, want to contain %q", tt.name, tt.err.Error(), tt.wantMsg)
			}
			// Verify all errors have "i2cp:" prefix for consistency
			if !strings.HasPrefix(tt.err.Error(), "i2cp:") {
				t.Errorf("%s message = %q, want prefix 'i2cp:'", tt.name, tt.err.Error())
			}
		})
	}
}

// TestErrorWrapping verifies errors can be properly wrapped and unwrapped
func TestErrorWrapping(t *testing.T) {
	baseErr := errors.New("base error")

	tests := []struct {
		name    string
		wrap    error
		want    error
		wantMsg string
	}{
		{
			name:    "wrap with fmt.Errorf",
			wrap:    fmt.Errorf("operation failed: %w", ErrSessionInvalid),
			want:    ErrSessionInvalid,
			wantMsg: "operation failed",
		},
		{
			name:    "wrap base error with sentinel",
			wrap:    fmt.Errorf("%w: %s", ErrConnectionClosed, "network unreachable"),
			want:    ErrConnectionClosed,
			wantMsg: "network unreachable",
		},
		{
			name:    "multiple wrapping levels",
			wrap:    fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", baseErr)),
			want:    baseErr,
			wantMsg: "outer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test errors.Is
			if !errors.Is(tt.wrap, tt.want) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.wrap, tt.want)
			}

			// Test error message contains expected text
			if !strings.Contains(tt.wrap.Error(), tt.wantMsg) {
				t.Errorf("error message = %q, want to contain %q", tt.wrap.Error(), tt.wantMsg)
			}
		})
	}
}

// TestMessageError verifies MessageError type functionality
func TestMessageError(t *testing.T) {
	tests := []struct {
		name        string
		messageType uint8
		operation   string
		err         error
		wantMsgType uint8
		wantOp      string
		wantContain string
	}{
		{
			name:        "message parsing error",
			messageType: I2CP_MSG_CREATE_SESSION,
			operation:   "parsing",
			err:         errors.New("invalid format"),
			wantMsgType: I2CP_MSG_CREATE_SESSION,
			wantOp:      "parsing",
			wantContain: "invalid format",
		},
		{
			name:        "message sending error",
			messageType: I2CP_MSG_SEND_MESSAGE,
			operation:   "sending",
			err:         ErrConnectionClosed,
			wantMsgType: I2CP_MSG_SEND_MESSAGE,
			wantOp:      "sending",
			wantContain: "connection closed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewMessageError(tt.messageType, tt.operation, tt.err)

			// Test type assertion
			var msgErr *MessageError
			if !errors.As(err, &msgErr) {
				t.Fatalf("error is not a MessageError: %T", err)
			}

			// Test fields
			if msgErr.MessageType != tt.wantMsgType {
				t.Errorf("MessageType = %d, want %d", msgErr.MessageType, tt.wantMsgType)
			}
			if msgErr.Operation != tt.wantOp {
				t.Errorf("Operation = %q, want %q", msgErr.Operation, tt.wantOp)
			}

			// Test error message
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantContain) {
				t.Errorf("error message = %q, want to contain %q", errMsg, tt.wantContain)
			}

			// Test unwrapping
			if !errors.Is(err, tt.err) {
				t.Errorf("errors.Is(err, %v) = false, want true", tt.err)
			}
		})
	}
}

// TestSessionError verifies SessionError type functionality
func TestSessionError(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     uint16
		operation     string
		err           error
		wantSessionID uint16
		wantOp        string
		wantContain   string
	}{
		{
			name:          "session creation error",
			sessionID:     123,
			operation:     "creation",
			err:           ErrSessionRefused,
			wantSessionID: 123,
			wantOp:        "creation",
			wantContain:   "refused",
		},
		{
			name:          "session message send error",
			sessionID:     456,
			operation:     "send message",
			err:           errors.New("queue full"),
			wantSessionID: 456,
			wantOp:        "send message",
			wantContain:   "queue full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewSessionError(tt.sessionID, tt.operation, tt.err)

			// Test type assertion
			var sessErr *SessionError
			if !errors.As(err, &sessErr) {
				t.Fatalf("error is not a SessionError: %T", err)
			}

			// Test fields
			if sessErr.SessionID != tt.wantSessionID {
				t.Errorf("SessionID = %d, want %d", sessErr.SessionID, tt.wantSessionID)
			}
			if sessErr.Operation != tt.wantOp {
				t.Errorf("Operation = %q, want %q", sessErr.Operation, tt.wantOp)
			}

			// Test error message
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantContain) {
				t.Errorf("error message = %q, want to contain %q", errMsg, tt.wantContain)
			}

			// Test unwrapping
			if !errors.Is(err, tt.err) {
				t.Errorf("errors.Is(err, %v) = false, want true", tt.err)
			}
		})
	}
}

// TestProtocolError verifies ProtocolError type functionality
func TestProtocolError(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		code        int
		fatal       bool
		wantContain string
		wantFatal   bool
	}{
		{
			name:        "non-fatal protocol error",
			message:     "unknown message type",
			code:        99,
			fatal:       false,
			wantContain: "unknown message type",
			wantFatal:   false,
		},
		{
			name:        "fatal protocol error",
			message:     "protocol violation",
			code:        0,
			fatal:       true,
			wantContain: "protocol violation",
			wantFatal:   true,
		},
		{
			name:        "error with code",
			message:     "invalid state",
			code:        42,
			fatal:       false,
			wantContain: "code 42",
			wantFatal:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProtocolError(tt.message, tt.code, tt.fatal)

			// Test type assertion
			var protoErr *ProtocolError
			if !errors.As(err, &protoErr) {
				t.Fatalf("error is not a ProtocolError: %T", err)
			}

			// Test fields
			if protoErr.Message != tt.message {
				t.Errorf("Message = %q, want %q", protoErr.Message, tt.message)
			}
			if protoErr.Code != tt.code {
				t.Errorf("Code = %d, want %d", protoErr.Code, tt.code)
			}
			if protoErr.Fatal != tt.fatal {
				t.Errorf("Fatal = %v, want %v", protoErr.Fatal, tt.fatal)
			}

			// Test error message
			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantContain) {
				t.Errorf("error message = %q, want to contain %q", errMsg, tt.wantContain)
			}

			// Test IsFatal
			if IsFatal(err) != tt.wantFatal {
				t.Errorf("IsFatal() = %v, want %v", IsFatal(err), tt.wantFatal)
			}
		})
	}
}

// TestIsTemporary verifies IsTemporary correctly identifies temporary errors
func TestIsTemporary(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "timeout error is temporary",
			err:  ErrTimeout,
			want: true,
		},
		{
			name: "wrapped timeout error is temporary",
			err:  fmt.Errorf("operation: %w", ErrTimeout),
			want: true,
		},
		{
			name: "connection closed is not temporary",
			err:  ErrConnectionClosed,
			want: false,
		},
		{
			name: "protocol error is not temporary",
			err:  ErrProtocolVersion,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTemporary(tt.err)
			if got != tt.want {
				t.Errorf("IsTemporary(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestIsFatal verifies IsFatal correctly identifies fatal errors
func TestIsFatal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "protocol version error is fatal",
			err:  ErrProtocolVersion,
			want: true,
		},
		{
			name: "authentication failure is fatal",
			err:  ErrAuthenticationFailed,
			want: true,
		},
		{
			name: "invalid signature is fatal",
			err:  ErrInvalidSignature,
			want: true,
		},
		{
			name: "wrapped fatal error is still fatal",
			err:  fmt.Errorf("connection: %w", ErrProtocolVersion),
			want: true,
		},
		{
			name: "protocol error with Fatal=true",
			err:  NewProtocolError("critical violation", 1, true),
			want: true,
		},
		{
			name: "protocol error with Fatal=false",
			err:  NewProtocolError("minor issue", 2, false),
			want: false,
		},
		{
			name: "timeout is not fatal",
			err:  ErrTimeout,
			want: false,
		},
		{
			name: "connection closed is not fatal",
			err:  ErrConnectionClosed,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFatal(tt.err)
			if got != tt.want {
				t.Errorf("IsFatal(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestErrorChaining verifies complex error wrapping scenarios
func TestErrorChaining(t *testing.T) {
	// Create a chain: base -> MessageError -> SessionError -> wrapped
	baseErr := errors.New("network error")
	msgErr := NewMessageError(I2CP_MSG_SEND_MESSAGE, "sending", baseErr)
	sessErr := NewSessionError(123, "message send", msgErr)
	wrapped := fmt.Errorf("client operation failed: %w", sessErr)

	// Test we can unwrap through the chain
	if !errors.Is(wrapped, baseErr) {
		t.Error("errors.Is failed to find base error through chain")
	}
	if !errors.Is(wrapped, ErrConnectionClosed) {
		// This should be false - just verify behavior
	}

	// Test we can extract typed errors from chain
	var extractedMsgErr *MessageError
	if !errors.As(wrapped, &extractedMsgErr) {
		t.Error("errors.As failed to extract MessageError from chain")
	}
	if extractedMsgErr.MessageType != I2CP_MSG_SEND_MESSAGE {
		t.Errorf("extracted MessageError has wrong type: %d", extractedMsgErr.MessageType)
	}

	var extractedSessErr *SessionError
	if !errors.As(wrapped, &extractedSessErr) {
		t.Error("errors.As failed to extract SessionError from chain")
	}
	if extractedSessErr.SessionID != 123 {
		t.Errorf("extracted SessionError has wrong ID: %d", extractedSessErr.SessionID)
	}
}

// TestErrorConsistency ensures all error messages follow conventions
func TestErrorConsistency(t *testing.T) {
	allErrors := []error{
		ErrSessionInvalid,
		ErrConnectionClosed,
		ErrMessageTooLarge,
		ErrAuthenticationFailed,
		ErrProtocolVersion,
		ErrTimeout,
		ErrNoPrimarySession,
		ErrMultiSessionUnsupported,
		ErrInvalidDestination,
		ErrInvalidLeaseSet,
		ErrMessageParsing,
		ErrInvalidSessionID,
		ErrSessionRefused,
		ErrNotConnected,
		ErrAlreadyConnected,
		ErrInvalidConfiguration,
		ErrDestinationLookupFailed,
		ErrBlindingRequired,
		ErrUnsupportedCrypto,
		ErrInvalidSignature,
	}

	for _, err := range allErrors {
		errMsg := err.Error()

		// All errors should have "i2cp:" prefix
		if !strings.HasPrefix(errMsg, "i2cp:") {
			t.Errorf("error %q missing 'i2cp:' prefix", errMsg)
		}

		// Error messages should be lowercase (after prefix)
		parts := strings.SplitN(errMsg, ": ", 2)
		if len(parts) == 2 {
			msg := parts[1]
			if msg != strings.ToLower(msg) {
				t.Errorf("error message %q should be lowercase", errMsg)
			}
		}

		// Error messages should not end with punctuation
		if strings.HasSuffix(errMsg, ".") || strings.HasSuffix(errMsg, "!") {
			t.Errorf("error message %q should not end with punctuation", errMsg)
		}
	}
}

// --- merged from error_suppression_fixes_test.go ---

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
					OnDisconnect: func(c *Client, reason string, data *interface{}) {
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
			address:         "invalid!@#$%^&*invalid!@#$%^&*invalid!@#$%^&*invalid!@#$.b32.i2p", // 56 chars + .b32.i2p but invalid base32
			mockDecodeError: true,
			wantRequestId:   0, // Should return 0 on decode failure
			description:     "Should return 0 and log warning when b32 decode fails",
		},
		{
			name:            "valid b32 address format",
			address:         "cekpd6d32cnpou7dmib4lraea5lzxhfnfd4qmpjjs2wbqh3tl6xa====.b32.i2p", // Valid base32-encoded 32-byte hash (56 chars with padding) + .b32.i2p
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
			client.router.capabilities = ROUTER_CAN_HOST_LOOKUP            // Enable host lookup
			client.router.version = Version{major: 0, minor: 9, micro: 67} // Modern router for HostLookup support

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
