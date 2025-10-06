# go-i2cp

A low-level Go implementation of the I2P Client Protocol (I2CP) focused on developing anonymous services and applications. This library provides cryptographically secure primitives for establishing I2P destinations and managing end-to-end encrypted communication sessions.

## Features

- Pure Go I2CP client implementation with minimal dependencies
- Core I2CP client functionality (session management, messaging, destination lookup)
- Secure session establishment and management
- Cryptographic operations (DSA/SHA1/SHA256, Ed25519, X25519, ChaCha20-Poly1305)
- Stream-based encrypted messaging 
- Anonymous addressing (Base32/Base64)
- Comprehensive test coverage
- I2CP connections (TLS support available)

## Requirements

- Go 1.19+
- Running I2P router with I2CP enabled (default port 7654)

## Installation

```bash
go get github.com/go-i2p/go-i2cp
```

## Basic Usage

```go
package main

import (
    "log"
    go_i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
    // Create I2CP client with callbacks
    client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

    // Connect to local I2P router
    if err := client.Connect(); err != nil {
        log.Fatal(err)
    }
    defer client.Disconnect()

    // Create session with callbacks
    session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{})

    // Configure session properties
    session.Destination().config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "example")
    session.Destination().config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")

    // Create session
    if err := client.CreateSession(session); err != nil {
        log.Fatal(err) 
    }

    // Process I/O
    for {
        if err := client.ProcessIO(); err != nil {
            break
        }
    }
}
```

## Session Configuration

Configure session properties for privacy tuning:

```go
// Security settings
config := session.Destination().config
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")          // Tunnel length
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")         
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "4")        // Number of tunnels
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY, "2") // Backup tunnels
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY, "2")
```

## Error Handling

The library provides comprehensive error handling with Go 1.13+ error wrapping:

```go
import (
    "errors"
    go_i2cp "github.com/go-i2p/go-i2cp"
)

// Check for specific errors
if err := client.Connect(); err != nil {
    if errors.Is(err, go_i2cp.ErrConnectionClosed) {
        // Handle connection closed
    } else if errors.Is(err, go_i2cp.ErrAuthenticationFailed) {
        // Handle auth failure
    }
}

// Extract typed errors for context
var msgErr *go_i2cp.MessageError
if errors.As(err, &msgErr) {
    log.Printf("Message type %d failed: %v", msgErr.MessageType, msgErr.Err)
}

// Check if errors are temporary (retryable)
if go_i2cp.IsTemporary(err) {
    // Retry operation
}

// Check if errors are fatal (connection should close)
if go_i2cp.IsFatal(err) {
    client.Disconnect()
}
```

Available sentinel errors:
- `ErrSessionInvalid` - Session invalid or closed
- `ErrConnectionClosed` - TCP connection closed
- `ErrAuthenticationFailed` - Authentication failure
- `ErrTimeout` - Operation timeout
- `ErrNotConnected` - Not connected to router
- And 15+ more covering all I2CP scenarios

See `errors.go` for the complete list of error types and utilities.

## Current Implementation Status

### Implemented Features

- ✅ Basic I2CP client connection and authentication
- ✅ Session creation and management
- ✅ Message sending and receiving
- ✅ Destination lookup (both hash and hostname)
- ✅ Stream-based messaging with compression
- ✅ DSA/SHA1/SHA256 cryptographic operations
- ✅ Base32/Base64 destination encoding
- ✅ Session configuration properties
- ✅ **NEW:** Comprehensive error handling with 20+ error types (96.2% test coverage)

### In Development

- 🔄 Modern cryptographic algorithms (Ed25519, X25519, ChaCha20-Poly1305)
- 🔄 TLS support for I2CP connections
- 🔄 Enhanced session persistence
- 🔄 Advanced tunnel configuration
- 🔄 Context-aware operations with cancellation support

## Testing

```bash
go test -v ./...
```

Note: Tests require a running I2P router with I2CP enabled on localhost:7654.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add enhancement'`)
4. Push to branch (`git push origin feature/enhancement`) 
5. Open a Pull Request

## License

MIT License - See LICENSE file

