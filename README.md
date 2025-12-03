# go-i2cp

A low-level Go implementation of the I2P Client Protocol (I2CP) for building anonymous services and applications.

## Features

- **87% I2CP Protocol Compliance** (22/24 message types)
- Session management, messaging, and destination lookup
- TLS authentication with mutual TLS support
- Modern cryptography: Ed25519, X25519, ChaCha20-Poly1305
- LeaseSet2 and encrypted LeaseSet support
- Automatic reconnection with circuit breaker
- Context-aware operations (cancellation, timeouts)
- Comprehensive error handling

## Requirements

- Go 1.19+
- Running I2P router with I2CP enabled (default port 7654)

## Installation

```bash
go get github.com/go-i2p/go-i2cp
```

## Quick Start

### Simple Synchronous Pattern (Recommended for Testing)

```go
client := go_i2cp.NewClient(nil)
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}
defer client.Close()

session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{})

// CreateSessionSync handles ProcessIO internally and blocks until ready
ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := client.CreateSessionSync(ctx, session); err != nil {
    log.Fatal(err)
}

fmt.Println("Session ready!")
```

### Production Async Pattern

```go
client := go_i2cp.NewClient(nil)
ctx := context.Background()

if err := client.Connect(ctx); err != nil {
    log.Fatal(err)
}
defer client.Close()

// Start ProcessIO loop (required for async pattern)
go func() {
    for {
        if err := client.ProcessIO(ctx); err != nil {
            return
        }
        time.Sleep(100 * time.Millisecond)
    }
}()

// Create session with callback
sessionReady := make(chan bool, 1)
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnStatus: func(s *go_i2cp.Session, status go_i2cp.SessionStatus) {
        if status == go_i2cp.I2CP_SESSION_STATUS_CREATED {
            sessionReady <- true
        }
    },
})

if err := client.CreateSession(ctx, session); err != nil {
    log.Fatal(err)
}

<-sessionReady  // Wait for confirmation
fmt.Println("Session ready!")
```

See [examples/](examples/) for complete working examples.

**IMPORTANT**: If you experience session creation hangs with Java I2P router, see [SESSION_CREATION_FIX.md](SESSION_CREATION_FIX.md) for detailed migration guide.

## Authentication

### Username/Password

```go
client.SetProperty(go_i2cp.CLIENT_PROP_USERNAME, "myuser")
client.SetProperty(go_i2cp.CLIENT_PROP_PASSWORD, "mypassword")
```

### TLS Certificate (Recommended)

```go
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_ENABLED, "true")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_CERT_FILE, "/path/to/client-cert.pem")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_KEY_FILE, "/path/to/client-key.pem")
client.SetProperty(go_i2cp.CLIENT_PROP_TLS_CA_FILE, "/path/to/ca-cert.pem")
```

## Session Callbacks

```go
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    OnBlindingInfo: func(sess *go_i2cp.Session, scheme, flags uint16, params []byte) {
        // Handle blinding for encrypted LeaseSets
    },
    OnLeaseSet2: func(sess *go_i2cp.Session, leaseSet *go_i2cp.LeaseSet2) {
        // Handle LeaseSet updates
    },
    OnMessageStatusUpdate: func(sess *go_i2cp.Session, messageId, status uint32) {
        // Track message delivery status
    },
})
```

## Error Recovery

```go
// Enable auto-reconnect
client.EnableAutoReconnect(5, time.Second)

// Circuit breaker
cb := go_i2cp.NewCircuitBreaker(5, 30*time.Second)
err := cb.Execute(func() error {
    return client.Connect(ctx)
})

// Retry with backoff
err = go_i2cp.RetryWithBackoff(ctx, 3, time.Second, func() error {
    return client.CreateSession(ctx, session)
})
```

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

```go
if err := client.Connect(); err != nil {
    if errors.Is(err, go_i2cp.ErrConnectionClosed) {
        // Handle connection closed
    }
}

// Check if retryable
if go_i2cp.IsTemporary(err) {
    // Retry operation
}
```

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

## Testing

```bash
go test -v ./...
go test -race ./...
go test -bench=. -benchmem
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - See LICENSE file
