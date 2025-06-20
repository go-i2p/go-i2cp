# go-i2cp

A low-level Go implementation of the I2P Client Protocol (I2CP) focused on developing anonymous services and applications. This library provides cryptographically secure primitives for establishing I2P destinations and managing end-to-end encrypted communication sessions.

## Features

- Pure Go I2CP client implementation with minimal dependencies
- Complete I2CP client
- Secure session establishment and management
- Cryptographic operations (DSA/SHA1/SHA256)
- Stream-based encrypted messaging 
- Anonymous addressing (Base32/Base64)
- Comprehensive test coverage
- TLS support for I2CP connections

## Installation

```bash
go get github.com/go-i2p/go-i2cp
```

## Basic Usage

```go
// Create I2CP client with default settings
client := go_i2cp.NewClient(nil)

// Connect to local I2P router
if err := client.Connect(); err != nil {
    log.Fatal(err)
}
defer client.Disconnect()

// Create session with callbacks
session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
    onDestination: func(session *go_i2cp.Session, requestId uint32, 
                       address string, dest *go_i2cp.Destination) {
        // Handle destination lookups
    },
    onStatus: func(session *go_i2cp.Session, status go_i2cp.SessionStatus) {
        // Handle session status changes
    },
    onMessage: func(session *go_i2cp.Session, protocol uint8,
                    srcPort, destPort uint16, payload *go_i2cp.Stream) {
        // Handle incoming messages
    },
})

// Configure session
session.config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "example")
session.config.SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")

// Generate destination
if session.config.destination, err = go_i2cp.NewDestination(); err != nil {
    log.Fatal(err)
}

// Create session
if err := client.CreateSession(session); err != nil {
    log.Fatal(err) 
}
```

## Security Configuration

The library supports extensive session configuration for privacy tuning:

```go
// Security settings
config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")          // Tunnel length
config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")         
config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "4")        // Number of tunnels
config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "4")
config.SetProperty(SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY, "2") // Backup tunnels
config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY, "2")
```

## Privacy Considerations 

This library implements core I2P networking primitives. When using it:

- Never mix I2P and clearnet traffic
- Use appropriate tunnel lengths for your threat model
- Handle all errors privately without leaking metadata
- Implement proper session isolation
- Consider timing attack mitigations
- Use TLS for I2CP connections when remote
- Rotate destinations if necessary
- Monitor tunnel health

## Roadmap

### Core I2CP Protocol Features
- [ ] **Message Priority Support** - Implement priority levels for I2CP messages (SendMessageExpires with priority flags)
- [ ] **Bandwidth Limiting** - Add support for bandwidth limiting properties (i2cp.inboundBytesPerSecond, i2cp.outboundBytesPerSecond)
- [ ] **LS2 Support** - Implement LeaseSet2 format for enhanced metadata and multiple signature types
- [ ] **ECIES-X25519 Encryption** - Add support for modern ECIES encryption alongside existing ElGamal
- [ ] **Ed25519 Signatures** - Implement Ed25519 signature support for improved performance and security
- [ ] **BlindedInfo Support** - Add support for blinded destinations and encrypted leaseset publishing
- [ ] **Meta LeaseSet Support** - Implement support for multi-destination meta leaseset format

### Extended I2CP Features  
- [ ] **Session Persistence** - Implement session state saving/loading for graceful restart
- [ ] **Advanced Tunnel Configuration** - Support for tunnel variance, randomization options
- [ ] **Client Authentication** - Implement I2CP client authentication mechanisms
- [ ] **Streaming Support** - Add higher-level streaming protocol implementation over I2CP
- [ ] **Datagram Support** - Implement repliable datagram messaging
- [ ] **Destination Lookup Caching** - Add intelligent caching for destination resolution

### Modern Crypto & Protocol
- [ ] **RedDSA Signatures** - Support for RedDSA signature algorithm
- [ ] **ChaCha20/Poly1305** - Modern AEAD cipher support for tunnel encryption
- [ ] **SipHash** - Implement SipHash for improved hash table security
- [ ] **Noise Protocol** - Add Noise-based handshakes for enhanced forward secrecy

### Quality & Performance
- [ ] **Connection Pooling** - Implement I2CP connection pooling for better resource usage
- [ ] **Async Message Handling** - Non-blocking message processing with goroutine pools
- [ ] **Metrics & Monitoring** - Add comprehensive metrics collection and health monitoring
- [ ] **Zero-Copy Operations** - Optimize buffer management to reduce memory allocations

## Testing

```bash
go test -v ./...
```

## Requirements

- Go 1.16+
- Running I2P router with I2CP enabled (default port 7654)
- SAM API v3.3 enabled in router

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add enhancement'`)
4. Push to branch (`git push origin feature/enhancement`) 
5. Open a Pull Request

## License

MIT License - See LICENSE file

