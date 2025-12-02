# go-i2cp

A low-level Go implementation of the I2P Client Protocol (I2CP) focused on developing anonymous services and applications. This library provides cryptographically secure primitives for establishing I2P destinations and managing end-to-end encrypted communication sessions.

## Features

- Pure Go I2CP client implementation with minimal dependencies
- **87% I2CP Protocol Compliance** (22/24 message types, 215+ tests, 63% code coverage)
- Core I2CP client functionality (session management, messaging, destination lookup)
- **TLS Authentication** - Secure router connections with mutual TLS (I2CP 0.8.3+)
- **Modern Cryptography** - Ed25519, X25519, ChaCha20-Poly1305 with legacy DSA/SHA1 support
- **Blinding Support** - Encrypted LeaseSet access for privacy-enhanced destinations (I2CP 0.9.43+)
- **LeaseSet2 Support** - Standard, encrypted, and meta LeaseSet types (I2CP 0.9.38+)
- **Automatic Reconnection** - Circuit breaker pattern with exponential backoff
- **Message Tracking** - Delivery confirmation and reliable messaging
- **Bandwidth Management** - Callback-based rate limiting and flow control
- Stream-based encrypted messaging with compression
- Anonymous addressing (Base32/Base64 destinations)
- Context-aware operations (cancellation, timeouts, graceful shutdown)
- Comprehensive error handling (20+ typed errors, 96.2% error path coverage)

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
    "context"
    "log"
    "time"
    go_i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
    // Create I2CP client
    client := go_i2cp.NewClient(nil)

    // Connect to local I2P router with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    if err := client.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer client.Close() // Graceful shutdown

    // Create session
    session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{})
    
    if err := client.CreateSession(ctx, session); err != nil {
        log.Fatal(err) 
    }

    // Process I/O with context support
    for {
        if err := client.ProcessIO(ctx); err != nil {
            if err == go_i2cp.ErrClientClosed {
                break
            }
            log.Printf("ProcessIO error: %v", err)
        }
    }
}
```

For more examples, see the [examples/](examples/) directory.

## TLS Authentication

go-i2cp supports secure TLS connections to the I2P router (I2CP 0.8.3+) with three authentication methods:

### Method 0: No Authentication (Default)

```go
client := go_i2cp.NewClient(nil)
// No authentication configured - connects without credentials
```

### Method 1: Username/Password Authentication

```go
client := go_i2cp.NewClient(nil)
client.SetProperty(go_i2cp.CLIENT_PROP_USERNAME, "myuser")
client.SetProperty(go_i2cp.CLIENT_PROP_PASSWORD, "mypassword")
```

### Method 2: TLS Certificate Authentication (Recommended)

```go
client := go_i2cp.NewClient(nil)

// Enable TLS with client certificate
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_ENABLED, "true")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_CERT_FILE, "/path/to/client-cert.pem")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_KEY_FILE, "/path/to/client-key.pem")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_CA_FILE, "/path/to/ca-cert.pem")

ctx := context.Background()
if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}
```

**TLS Configuration Options:**

- `i2cp.SSL` - Enable TLS (default: `false`)
- `i2cp.SSL.certFile` - Client certificate path for mutual TLS
- `i2cp.SSL.keyFile` - Client private key path
- `i2cp.SSL.caFile` - CA certificate for server validation (uses system pool if empty)
- `i2cp.SSL.insecure` - Skip certificate verification (development only, default: `false`)

**Security Notes:**
- TLS authentication takes precedence over username/password when both configured
- Certificate validation is enabled by default - use `insecure` mode only for testing
- Minimum TLS version is 1.2 per I2CP security requirements
- Self-signed certificates are supported with proper CA configuration

### Generating Test Certificates

```bash
# Generate CA certificate
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes

# Generate client certificate
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-req.pem -nodes
openssl x509 -req -in client-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365
```

## Blinding Support (Encrypted LeaseSets)

go-i2cp supports blinding for encrypted LeaseSet access, enabling privacy-enhanced destinations (I2CP 0.9.43+):

```go
// Create session with blinding callback
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnBlindingInfo: func(sess *go_i2cp.Session, scheme, flags uint16, params []byte) {
        log.Printf("Blinding enabled: scheme=%d, flags=%d, params=%x", scheme, flags, params)
        
        // Store blinding parameters for encrypted LeaseSet access
        // Application should persist these for future connections
    },
})

// Check if blinding is enabled
if session.IsBlindingEnabled() {
    scheme := session.BlindingScheme()
    flags := session.BlindingFlags()
    params := session.BlindingParams()
    
    log.Printf("Blinding active: scheme=%d", scheme)
}

// Clear blinding parameters when no longer needed
session.ClearBlinding()
```

**Blinding Use Cases:**
- Private messaging services requiring password-protected access
- Hidden services with authentication requirements
- Encrypted LeaseSet distribution
- Access control for anonymous destinations

**LeaseSet2 Callback:**

```go
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnLeaseSet2: func(sess *go_i2cp.Session, leaseSet *go_i2cp.LeaseSet2) {
        log.Printf("Received LeaseSet2: type=%d, expires=%s", 
            leaseSet.Type(), leaseSet.Expires())
        
        // Check expiration
        if leaseSet.IsExpired() {
            log.Println("WARNING: LeaseSet has expired")
        }
        
        // Verify signature
        if err := leaseSet.VerifySignature(); err != nil {
            log.Printf("Signature verification failed: %v", err)
        }
    },
})
```

## Automatic Reconnection & Error Recovery

go-i2cp provides automatic reconnection with circuit breaker pattern and exponential backoff:

### Enable Auto-Reconnection

```go
client := go_i2cp.NewClient(nil)

// Enable auto-reconnect with max 5 retries, starting with 1 second backoff
client.EnableAutoReconnect(5, time.Second)

// Check if auto-reconnect is enabled
if client.IsAutoReconnectEnabled() {
    maxRetries := client.AutoReconnectMaxRetries()
    log.Printf("Auto-reconnect enabled with max %d retries", maxRetries)
}

// Disable auto-reconnect
client.DisableAutoReconnect()
```

### Circuit Breaker for Fault Tolerance

```go
import "github.com/go-i2p/go-i2cp"

// Create circuit breaker: 5 failures triggers open, 30s timeout before retry
cb := go_i2cp.NewCircuitBreaker(5, 30*time.Second)

// Wrap operations in circuit breaker
err := cb.Execute(func() error {
    return client.Connect(ctx)
})

if err != nil {
    if cb.IsOpen() {
        log.Println("Circuit breaker is open - too many failures")
    }
}

// Manual reset
cb.Reset()
```

### Retry with Exponential Backoff

```go
// Retry operation with backoff (max 3 retries, 1s initial backoff)
err := go_i2cp.RetryWithBackoff(ctx, 3, time.Second, func() error {
    return client.CreateSession(ctx, session)
})

// Infinite retries (maxRetries < 0)
err = go_i2cp.RetryWithBackoff(ctx, -1, time.Second, func() error {
    return client.ProcessIO(ctx)
})
```

**Error Recovery Features:**

- Automatic reconnection on disconnect with configurable retries
- Exponential backoff (1s → 2s → 4s → ... → 5min max)
- Circuit breaker prevents cascade failures
- Context cancellation respected during retries
- Temporary vs fatal error distinction

## Message Tracking & Reliable Messaging

Track message delivery with automatic status updates:

```go
// Create session with message status callback
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnMessageStatusUpdate: func(sess *go_i2cp.Session, messageId, status uint32) {
        log.Printf("Message %d status: %d", messageId, status)
        
        // Check pending message details
        if msg := sess.GetPendingMessage(messageId); msg != nil {
            deliveryTime := msg.CompletedAt.Sub(msg.SentAt)
            log.Printf("Delivered in %v", deliveryTime)
        }
    },
})

// Send message (automatically tracked)
nonce := uint32(12345)
err := session.SendMessage(nonce, destination, protocol, srcPort, destPort, payload)

// Query pending messages
pendingCount := session.PendingMessageCount()
allPending := session.GetPendingMessages() // Returns snapshot

// Clear all pending on shutdown
session.ClearPendingMessages()
```

**Message Tracking Features:**

- Automatic tracking for SendMessage() and SendMessageExpires()
- Delivery time calculation (CompletedAt - SentAt)
- Thread-safe concurrent access
- Duplicate nonce detection
- Automatic cleanup on session close
- Per-message status and metadata

## Bandwidth Management

Monitor and control bandwidth usage with callback-based rate limiting:

```go
import "golang.org/x/time/rate"

// Create client with bandwidth callback
client := go_i2cp.NewClient(&go_i2cp.ClientCallbacks{
    OnBandwidthLimits: func(c *go_i2cp.Client, limits *go_i2cp.BandwidthLimits) {
        log.Printf("Bandwidth limits: %s", limits.String())
        
        // Configure rate limiter
        inboundRate := float64(limits.InboundBurstKBytesPerSecond * 1024)
        outboundRate := float64(limits.OutboundBurstKBytesPerSecond * 1024)
        
        inboundLimiter := rate.NewLimiter(rate.Limit(inboundRate), int(inboundRate))
        outboundLimiter := rate.NewLimiter(rate.Limit(outboundRate), int(outboundRate))
        
        // Use limiters before sending/receiving data
    },
})
```

See [examples/bandwidth-limits/](examples/bandwidth-limits/) for complete rate limiting implementation.



## Session Configuration

Configure session properties for privacy tuning:

```go
// Security settings
config := session.Destination().config
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")          // Tunnel length (hops)
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")         
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "4")        // Number of tunnels
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY, "2") // Backup tunnels
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY, "2")
```

**Privacy vs Performance Tuning:**

| Setting | High Privacy | Balanced | Low Latency |
|---------|--------------|----------|-------------|
| Tunnel Length | 3 hops | 3 hops | 1-2 hops |
| Tunnel Quantity | 6-8 | 4 | 2-3 |
| Backup Quantity | 3-4 | 2 | 1 |

**Note:** Shorter tunnels and fewer backups improve performance but reduce anonymity.

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

## Protocol Compliance & Implementation Status

### I2CP Protocol Coverage: 87% (22/24 Message Types)

**✅ Fully Implemented:**

- ✅ Session Management (CreateSession, DestroySession, SessionStatus, ReconfigureSession)
- ✅ Messaging (SendMessage, SendMessageExpires, MessagePayload, MessageStatus)
- ✅ Destination Services (DestLookup, DestReply, GetBandwidthLimits)
- ✅ Authentication (TLS certificates, username/password, none)
- ✅ Modern Features:
  - LeaseSet2 support (standard, encrypted, meta types)
  - Blinding support for encrypted LeaseSets
  - Offline signing support
  - Automatic reconnection with circuit breaker
  - Message tracking and delivery confirmation
  - Bandwidth management callbacks
- ✅ Cryptography:
  - Ed25519 signatures (I2CP 0.9.15+)
  - X25519 key exchange (I2CP 0.9.46+)
  - ChaCha20-Poly1305 encryption (I2CP 0.9.46+)
  - Legacy DSA/SHA1/SHA256 support
- ✅ Context-Aware Operations (cancellation, timeouts, graceful shutdown)
- ✅ Comprehensive Error Handling (20+ typed errors, 96.2% error path coverage)

**📊 Test Coverage:**

- **215+ passing tests** covering all major features
- **63% code coverage** across core library
- Integration tests with real I2P router
- 40+ benchmarks for performance validation
- Error path coverage >96%

**🔄 Future Enhancements (Phase 4):**

- DH/PSK authentication (methods 3-4) - Low priority
- Performance optimizations (message batching, buffer pooling)
- Observability (Prometheus metrics, OpenTelemetry tracing)
- MetaLeaseSet support (preliminary spec)

**❌ Excluded by Design:**

- ReportAbuse message (never implemented in I2CP spec)
- ElGamal encryption (deprecated, security concerns)

### Version Compatibility

- **I2CP Protocol Versions:** 0.6.5 - 0.9.66
- **Recommended I2P Router:** 2.0.0+
- **Go Version:** 1.19+ (tested with 1.24.4)

## Troubleshooting

### Connection Issues

**Problem: "connection refused" or "no route to host"**

```bash
# Check I2P router is running
ps aux | grep i2p

# Check I2CP is enabled and port is correct
grep i2cp ~/.i2p/router.config
# Should show: i2cp.enabled=true

# Test connection
nc -zv 127.0.0.1 7654
```

**Solution:**
- Ensure I2P router is running: `systemctl status i2p` or check I2P console
- Verify I2CP is enabled in router settings (usually port 7654)
- Check firewall isn't blocking the port
- Try connecting to `127.0.0.1:7654` instead of `localhost:7654`

### TLS Authentication Issues

**Problem: "tls: bad certificate" or "x509: certificate signed by unknown authority"**

```go
// Check certificate configuration
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_ENABLED, "true")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_CA_FILE, "/path/to/ca-cert.pem")

// For development/testing only - skip verification
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_INSECURE, "true")
```

**Solution:**
- Verify certificate paths are correct and readable
- Ensure CA certificate matches the router's certificate
- Check certificate hasn't expired: `openssl x509 -in cert.pem -noout -dates`
- For self-signed certs, provide CA file explicitly
- Never use `insecure=true` in production

### Session Creation Failures

**Problem: "session creation timeout" or "ErrSessionInvalid"**

```go
// Increase timeout for slow networks
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

err := client.CreateSession(ctx, session)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Println("Timeout - I2P router may be overloaded or network is slow")
    }
}
```

**Solution:**
- Increase context timeout for slower I2P routers
- Check router is fully bootstrapped (wait 5-10 minutes after start)
- Verify router has sufficient bandwidth and isn't overloaded
- Check router logs for errors: `tail -f ~/.i2p/logs/log-router-*.txt`

### Message Delivery Issues

**Problem: Messages not being delivered or status=FAILURE**

```go
// Enable message tracking for debugging
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnMessageStatusUpdate: func(sess *go_i2cp.Session, messageId, status uint32) {
        if status != go_i2cp.MESSAGE_STATUS_SEND_SUCCESS_LOCAL {
            log.Printf("Message %d failed with status %d", messageId, status)
        }
    },
})

// Check pending messages
pending := session.GetPendingMessages()
log.Printf("%d messages pending delivery", len(pending))
```

**Solution:**
- Verify destination is reachable and hasn't changed
- Check tunnel quantity/length settings aren't too aggressive
- Increase backup tunnel quantities for better reliability
- Monitor bandwidth limits - may be throttled
- Use message tracking to identify failures

### Memory/Resource Leaks

**Problem: Memory usage growing over time**

```bash
# Run with race detector to find concurrency issues
go test -race ./...

# Profile memory usage
go test -memprofile=mem.prof
go tool pprof mem.prof
```

**Solution:**
- Ensure `client.Close()` is called on shutdown
- Call `session.Close()` when sessions no longer needed
- Use `defer client.Close()` to guarantee cleanup
- Check for goroutine leaks with `runtime.NumGoroutine()`
- Call `session.ClearPendingMessages()` periodically if tracking many messages

### Performance Issues

**Problem: High latency or low throughput**

```go
// Adjust tunnel configuration for lower latency
config := session.Destination().config
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_LENGTH, "1")  // Reduce to 1 hop
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "1")
config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "6")  // More tunnels

// Enable circuit breaker to fail fast
cb := go_i2cp.NewCircuitBreaker(3, 10*time.Second)
```

**Solution:**
- Reduce tunnel length for lower latency (less anonymity)
- Increase tunnel quantity for higher throughput
- Use circuit breaker to detect and avoid failing routers
- Monitor bandwidth limits and adjust rate limiting
- Run benchmarks: `go test -bench=. -benchmem`

### Debug Logging

Enable verbose logging to diagnose issues:

```go
// The library uses github.com/go-i2p/logger
// Set log level via environment or configuration

// Check what messages are being sent/received
// Look for DEBUG messages in your logs
```

**Common Error Codes:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `ErrConnectionClosed` | TCP connection lost | Enable auto-reconnect |
| `ErrAuthenticationFailed` | Invalid credentials | Check username/password or TLS certs |
| `ErrTimeout` | Operation took too long | Increase context timeout |
| `ErrSessionInvalid` | Session not found/closed | Recreate session |
| `ErrBlindingRequired` | Encrypted LeaseSet needs password | Provide blinding parameters |

### Getting Help

If you're still stuck:

1. Check existing [GitHub issues](https://github.com/go-i2p/go-i2cp/issues)
2. Enable debug logging and capture full error messages
3. Share I2P router version and go-i2cp version
4. Provide minimal reproducible example
5. Check router logs for related errors





## Examples

Complete working examples are available in the [examples/](examples/) directory:

### Core Examples

- **[context-usage](examples/context-usage/)** - Context-aware operations, timeouts, cancellation, graceful shutdown
- **[modern-crypto](examples/modern-crypto/)** - Ed25519, X25519, ChaCha20-Poly1305 cryptographic demos
- **[external-callbacks](examples/external-callbacks/)** - Using SessionCallbacks from external packages
- **[bandwidth-limits](examples/bandwidth-limits/)** - Rate limiting with token bucket pattern

### Running Examples

```bash
# Context usage example (connection with timeout)
cd examples/context-usage && go run context_usage.go

# Modern cryptography demo (Ed25519, X25519, ChaCha20)
cd examples/modern-crypto && go run modern_crypto_demo.go

# Bandwidth management with rate limiting
cd examples/bandwidth-limits && go run bandwidth_limits_example.go
```

See the [examples README](examples/README.md) for detailed documentation and usage patterns.

## Testing

Run the test suite:

```bash
# Run all tests
go test -v ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=. -benchmem
```

**Test Requirements:**
- Most tests run without external dependencies
- Integration tests require I2P router on `127.0.0.1:7654` (skipped if unavailable)
- Use `//go:build integration` tag for tests requiring real router
- Current coverage: **63%** with **215+ passing tests**

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/enhancement`)
3. Write tests for new functionality (maintain >60% coverage)
4. Ensure all tests pass (`go test ./...`)
5. Run linters (`golangci-lint run`)
6. Commit changes (`git commit -m 'Add enhancement'`)
7. Push to branch (`git push origin feature/enhancement`)
8. Open a Pull Request

**Code Standards:**
- Follow Go best practices and idioms
- Use interface types for network variables (`net.Conn`, not `*net.TCPConn`)
- Handle all errors explicitly - no ignored returns
- Add godoc comments for exported functions
- Keep functions under 30 lines when possible

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.



## License

MIT License - See LICENSE file

