package go_i2cp

import (
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
