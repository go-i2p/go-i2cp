package go_i2cp

import (
	"errors"
	"fmt"
)

// Standard I2CP Error Types
//
// These errors follow Go 1.13+ error wrapping conventions and can be
// checked using errors.Is() and errors.As(). All errors include context
// about the operation that failed and the underlying cause.
//
// Design rationale:
// - Use sentinel errors for common, expected error conditions
// - Use error types for errors that need additional context
// - All errors are safe for error wrapping with fmt.Errorf("%w", err)

// Sentinel errors for common I2CP protocol violations and failures
var (
	// ErrSessionInvalid indicates an operation was attempted on an invalid or closed session.
	// This typically occurs when trying to use a session ID that doesn't exist or has been destroyed.
	// I2CP spec: SessionStatusMessage status code 3 (Invalid)
	ErrSessionInvalid = errors.New("i2cp: session invalid or closed")

	// ErrConnectionClosed indicates the TCP connection to the I2P router was closed.
	// This may occur due to network issues, router shutdown, or explicit disconnect.
	ErrConnectionClosed = errors.New("i2cp: connection closed")

	// ErrMessageTooLarge indicates a message exceeds the I2CP protocol size limit.
	// I2CP spec: Maximum message size is approximately 64 KB (0xFFFF bytes)
	ErrMessageTooLarge = errors.New("i2cp: message exceeds size limit")

	// ErrAuthenticationFailed indicates authentication with the router failed.
	// This may occur with username/password, TLS certificate, or per-client authentication.
	// I2CP spec: Authentication support added in protocol version 0.9.11+
	ErrAuthenticationFailed = errors.New("i2cp: authentication failed")

	// ErrProtocolVersion indicates an unsupported I2CP protocol version was detected.
	// The client should gracefully degrade or refuse connection.
	// I2CP spec: Supports versions 0.6.5 through 0.9.66
	ErrProtocolVersion = errors.New("i2cp: unsupported protocol version")

	// ErrTimeout indicates an operation exceeded its allowed time limit.
	// Operations should respect context.Context deadlines when provided.
	ErrTimeout = errors.New("i2cp: operation timed out")

	// ErrNoPrimarySession indicates a subsession operation was attempted without a primary session.
	// I2CP spec: Multi-session support added in protocol version 0.9.21+
	ErrNoPrimarySession = errors.New("i2cp: no primary session exists for subsession creation")

	// ErrMultiSessionUnsupported indicates the router doesn't support multiple sessions.
	// I2CP spec: Check router version >= 0.9.21 before creating subsessions
	ErrMultiSessionUnsupported = errors.New("i2cp: router does not support multi-session")

	// ErrInvalidDestination indicates a malformed or invalid destination was provided.
	// Destinations must contain valid cryptographic keys and certificates.
	ErrInvalidDestination = errors.New("i2cp: invalid destination format")

	// ErrInvalidLeaseSet indicates a malformed or invalid LeaseSet was received.
	// LeaseSets must contain valid leases, signatures, and cryptographic data.
	ErrInvalidLeaseSet = errors.New("i2cp: invalid leaseset format")

	// ErrMessageParsing indicates a failure to parse an incoming I2CP message.
	// This typically indicates protocol violations or corrupted data.
	ErrMessageParsing = errors.New("i2cp: message parsing failed")

	// ErrInvalidSessionID indicates an invalid session ID was used.
	// Session IDs must be 2-byte integers assigned by the router.
	// Session ID 0xFFFF is reserved for no-session operations.
	ErrInvalidSessionID = errors.New("i2cp: invalid session id")

	// ErrSessionRefused indicates the router refused to create the session.
	// This may occur due to resource limits or configuration issues.
	// I2CP spec: SessionStatusMessage status code 4 (Refused) added in 0.9.12
	ErrSessionRefused = errors.New("i2cp: session creation refused by router")

	// ErrNotConnected indicates an operation requires an active connection but none exists.
	ErrNotConnected = errors.New("i2cp: not connected to router")

	// ErrAlreadyConnected indicates Connect() was called on an already-connected client.
	ErrAlreadyConnected = errors.New("i2cp: already connected")

	// ErrInvalidConfiguration indicates the session configuration is invalid.
	// Configuration must include valid destination, options, and signature.
	ErrInvalidConfiguration = errors.New("i2cp: invalid session configuration")

	// ErrDestinationLookupFailed indicates a destination lookup operation failed.
	// This is equivalent to a DNS lookup failure in the I2P network.
	// I2CP spec: MessageStatusMessage status code 21 (No Leaseset)
	ErrDestinationLookupFailed = errors.New("i2cp: destination lookup failed")

	// ErrBlindingRequired indicates a blinded destination requires BlindingInfo.
	// Blinded destinations (b33 addresses) need authentication parameters.
	// I2CP spec: BlindingInfoMessage support added in protocol version 0.9.43+
	ErrBlindingRequired = errors.New("i2cp: blinding info required for encrypted leaseset")

	// ErrUnsupportedCrypto indicates an unsupported cryptographic algorithm was encountered.
	// The library supports DSA, ECDSA, EdDSA, ElGamal, and ECIES-X25519.
	ErrUnsupportedCrypto = errors.New("i2cp: unsupported cryptographic algorithm")

	// ErrInvalidSignature indicates a cryptographic signature verification failed.
	// This typically indicates data corruption or a security issue.
	ErrInvalidSignature = errors.New("i2cp: invalid signature")

	// ErrMaxSessionsReached indicates the maximum number of sessions per client has been reached.
	// I2CP spec: Maximum sessions per client is defined by I2CP_MAX_SESSIONS_PER_CLIENT
	ErrMaxSessionsReached = errors.New("i2cp: maximum sessions per client reached")

	// ErrClientClosed indicates an operation was attempted on a closed client.
	// All operations will fail after Close() has been called.
	ErrClientClosed = errors.New("i2cp: client is closed")

	// ErrClientNotInitialized indicates an operation was attempted on an uninitialized client.
	// Clients must be created using NewClient() to ensure proper initialization.
	// Zero-value Client{} instances are not safe to use.
	ErrClientNotInitialized = errors.New("i2cp: client not initialized (use NewClient)")

	// ErrSessionNotInitialized indicates an operation was attempted on an uninitialized session.
	// Sessions must be created using NewSession() or NewSessionWithContext() to ensure proper initialization.
	// Zero-value Session{} instances are not safe to use.
	ErrSessionNotInitialized = errors.New("i2cp: session not initialized (use NewSession)")

	// ErrInvalidArgument indicates a nil or invalid argument was passed to a public API method.
	// All public methods validate their parameters and return this error for nil values.
	ErrInvalidArgument = errors.New("i2cp: invalid argument (nil or empty value)")
)

// MessageError represents an error related to I2CP message processing.
// It includes the message type and additional context about what failed.
type MessageError struct {
	MessageType uint8  // I2CP message type constant
	Operation   string // What operation failed (e.g., "parsing", "sending")
	Err         error  // Underlying error
}

func (e *MessageError) Error() string {
	return fmt.Sprintf("i2cp: message type %d %s failed: %v", e.MessageType, e.Operation, e.Err)
}

func (e *MessageError) Unwrap() error {
	return e.Err
}

// NewMessageError creates a MessageError with the given parameters.
// Use this to wrap errors that occur during message processing.
//
// Example:
//
//	if err := parseMessage(stream); err != nil {
//	    return NewMessageError(I2CP_MSG_CREATE_SESSION, "parsing", err)
//	}
func NewMessageError(messageType uint8, operation string, err error) error {
	return &MessageError{
		MessageType: messageType,
		Operation:   operation,
		Err:         err,
	}
}

// SessionError represents an error related to session operations.
// It includes the session ID for debugging and tracing.
type SessionError struct {
	SessionID uint16 // I2CP session ID (2-byte integer)
	Operation string // What operation failed
	Err       error  // Underlying error
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("i2cp: session %d %s failed: %v", e.SessionID, e.Operation, e.Err)
}

func (e *SessionError) Unwrap() error {
	return e.Err
}

// NewSessionError creates a SessionError with the given parameters.
// Use this to wrap errors that occur during session operations.
//
// Example:
//
//	if err := session.sendMessage(); err != nil {
//	    return NewSessionError(session.id, "send message", err)
//	}
func NewSessionError(sessionID uint16, operation string, err error) error {
	return &SessionError{
		SessionID: sessionID,
		Operation: operation,
		Err:       err,
	}
}

// ProtocolError represents a protocol-level error with detailed information.
// Use this for serious protocol violations that may indicate bugs or attacks.
type ProtocolError struct {
	Message string // Human-readable error description
	Code    int    // Optional error code for programmatic handling
	Fatal   bool   // Whether this error should terminate the connection
}

func (e *ProtocolError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("i2cp protocol error (code %d): %s", e.Code, e.Message)
	}
	return fmt.Sprintf("i2cp protocol error: %s", e.Message)
}

// NewProtocolError creates a ProtocolError for serious protocol violations.
//
// Example:
//
//	if msgType > 42 {
//	    return NewProtocolError("unknown message type", int(msgType), false)
//	}
func NewProtocolError(message string, code int, fatal bool) error {
	return &ProtocolError{
		Message: message,
		Code:    code,
		Fatal:   fatal,
	}
}

// IsTemporary returns true if the error is temporary and the operation can be retried.
// This checks for specific error types that indicate transient failures.
func IsTemporary(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific temporary errors
	if errors.Is(err, ErrTimeout) {
		return true
	}

	// Check for network temporary errors
	type temporary interface {
		Temporary() bool
	}
	if te, ok := err.(temporary); ok {
		return te.Temporary()
	}

	return false
}

// IsFatal returns true if the error is fatal and the connection should be closed.
// Fatal errors indicate serious protocol violations or unrecoverable states.
func IsFatal(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific fatal errors
	if errors.Is(err, ErrProtocolVersion) ||
		errors.Is(err, ErrAuthenticationFailed) ||
		errors.Is(err, ErrInvalidSignature) {
		return true
	}

	// Check for ProtocolError with Fatal flag
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.Fatal
	}

	return false
}
