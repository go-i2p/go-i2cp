# Contributing to go-i2cp

Welcome to the go-i2cp project! This guide helps new contributors understand our codebase structure, coding conventions, and development workflows. We appreciate your interest in improving I2P Client Protocol implementation in Go.

## Project Description

go-i2cp is a low-level Go implementation of the I2P Client Protocol (I2CP) for developing anonymous services and applications. The library provides cryptographically secure primitives for establishing I2P destinations and managing end-to-end encrypted communication sessions within the I2P anonymity network.

Current development goals include:
- Completing all 25+ I2CP message type handlers for full protocol compliance
- Modernizing error handling patterns and adding context-aware operations  
- Implementing modern cryptographic algorithms (Ed25519, ECIES-X25519, ChaCha20-Poly1305)

Target users are Go developers building privacy-focused applications requiring anonymous networking capabilities, particularly those needing direct I2CP integration without higher-level abstractions.

## Coding Style

We follow standard Go conventions with specific preferences for this cryptographic networking library:

**Naming Conventions**: Prefer descriptive names with I2CP protocol references. Use typed constants for protocol values (e.g., `I2CP_MSG_CREATE_SESSION` instead of magic numbers). Structure names should reflect I2CP terminology: `SessionConfig`, `LeaseSet2Message`, `BlindingInfoFlags`.

**Error Handling**: Replace legacy `_ = err` patterns with proper error wrapping using `fmt.Errorf("%w", err)`. Include contextual information in error messages, especially protocol-specific details like session IDs and message types.

**Documentation**: Document all exported functions with I2CP protocol references and specification section numbers. Include parameter descriptions and usage examples for complex functions.

**Example preferred patterns**:
```go
// Preferred: Descriptive constant with protocol reference
const I2CP_MSG_CREATE_LEASE_SET2 uint8 = 41

// Preferred: Proper error wrapping with context
if err := c.sendMessage(msgType, stream, true); err != nil {
    return fmt.Errorf("failed to send CreateLeaseSet2Message for session %d: %w", sess.id, err)
}

// Preferred: Structured logging with consistent field names
Debug(TAG|PROTOCOL, "Received HostLookupMessage for session %d: requestId=%d, type=%d", 
      sessionId, requestId, lookupType)
```

## Project Structure

```
├── client.go              # Core I2CP client implementation and message handlers
├── client_test.go          # Integration tests for client functionality
├── constants.go           # I2CP protocol constants, message types, and status codes
├── session.go             # Session management and message dispatch logic
├── session_test.go        # Unit tests for session functionality
├── session_struct.go      # Session struct definition
├── session_config.go      # Session configuration properties and parsing
├── router_info.go         # Router information structure
├── tcp.go                 # TCP connection handling with optional TLS support
├── stream.go              # Stream operations for I2CP message serialization
├── utils.go               # Utility functions for logging, config parsing, and crypto
├── log.go                 # Logger instance initialization
├── i2pc.go               # Package placeholder
├── go.mod                # Go module definition with dependencies
├── README.md             # Project documentation and usage examples
└── .github/
    └── copilot-instructions.md  # Development guidelines and protocol specifications
```

**Core functionality** resides in `client.go` (protocol implementation), `session.go` (session management), and `constants.go` (protocol definitions). **Supporting functionality** includes TCP handling (`tcp.go`), stream operations (`stream.go`), configuration management (`session_config.go`), and utilities (`utils.go`).

## Examples

**Adding a New Message Handler**: The most common contribution involves implementing missing I2CP message handlers. For example, to add support for `GetBandwidthLimitsMessage` (type 8):

1. Add the message sending function in `client.go`:
```go
func (c *Client) msgGetBandwidthLimits(queue bool) error {
    c.messageStream.Reset()
    return c.sendMessage(I2CP_MSG_GET_BANDWIDTH_LIMITS, c.messageStream, queue)
}
```

2. Update the `onMessage` switch statement to handle the response
3. Add corresponding test cases in `client_test.go`

**Extending Session Configuration**: To add new session properties, modify `session_config.go` by adding the property constant to the enum, updating the `sessionOptions` array, and implementing validation logic in the session configuration functions.

**Modernizing Error Handling**: Throughout the codebase, replace patterns like `_ = err // currently unused` with proper error handling. Focus on functions in `client.go` that suppress errors, adding contextual information specific to I2CP operations like session IDs, message types, and protocol state.

When contributing, prioritize security, maintainability, and test coverage while preserving I2CP protocol semantics. All message handlers should include comprehensive error handling, proper logging with structured field names, and validation against the I2CP specification versions 0.6.5 through 0.9.66.
