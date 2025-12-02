# go-i2cp Examples

This directory contains example programs demonstrating how to use the go-i2cp library.

## Available Examples

### 1. [Context Usage](context-usage/)

Demonstrates context-aware operations in go-i2cp, including:

- **Connection with Timeout**: Using `context.WithTimeout` to prevent hanging connections
- **Session Creation with Cancellation**: Manual cancellation using `context.WithCancel`
- **Graceful Shutdown**: Proper cleanup using the `Close()` method
- **Background Processing**: Running I/O loops with context support

**Features shown:**
- Context cancellation and timeout handling
- Proper error handling for context errors
- Graceful shutdown with cleanup
- Session lifecycle management

**Location:** `examples/context-usage/`

[📖 Full Documentation](context-usage/README.md)

### 2. [Modern Cryptography Demo](modern-crypto/)

Demonstrates the modern cryptographic algorithms supported by go-i2cp:

- **Ed25519 Digital Signatures**: Fast, secure signing and verification
- **X25519 Key Exchange**: ECDH for perfect forward secrecy
- **ChaCha20-Poly1305 Encryption**: Authenticated encryption with additional data
- **Stream Serialization**: I2CP protocol-compatible serialization
- **Legacy DSA Support**: Backward compatibility with older I2P versions

**Features shown:**
- Key pair generation for multiple algorithms
- Message signing and verification
- Diffie-Hellman key exchange
- Authenticated encryption/decryption
- Serialization and deserialization
- Integration with the Crypto struct

**Location:** `examples/modern-crypto/`

[📖 Full Documentation](modern-crypto/README.md)

## Running Examples

Each example is in its own subdirectory with a dedicated README.md:

```bash
# Context usage example
cd context-usage
go run context_usage.go

# Modern crypto example
cd modern-crypto
go run modern_crypto_demo.go
```

## Building Examples

Each example can be built independently:

```bash
# Build context usage
cd context-usage
go build

# Build modern crypto
cd modern-crypto
go build
```

## Common Usage Patterns

### Basic Client Connection

```go
import (
    "context"
    "time"
    i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
    client := i2cp.NewClient(nil)
    
    // Connect with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    err := client.Connect(ctx)
    if err != nil {
        // Handle error
    }
    defer client.Close()
    
    // Use client...
}
```

### Session Creation

```go
session := i2cp.NewSession(client, i2cp.SessionCallbacks{})

ctx := context.Background()
err := client.CreateSession(ctx, session)
if err != nil {
    // Handle error
}
```

### Graceful Shutdown

```go
// Close will:
// - Destroy all sessions
// - Wait for pending operations (max 5 seconds)
// - Close TCP connection
err := client.Close()
if err != nil && err != i2cp.ErrClientClosed {
    // Handle error
}
```

### Modern Cryptography

```go
crypto := i2cp.NewCrypto()

// Ed25519 signatures
kp, _ := crypto.Ed25519SignatureKeygen()
signature, _ := kp.Sign(message)
verified := kp.Verify(message, signature)

// X25519 key exchange
aliceKp, _ := crypto.X25519KeyExchangeKeygen()
bobKp, _ := crypto.X25519KeyExchangeKeygen()
sharedSecret, _ := aliceKp.GenerateSharedSecret(bobKp.PublicKey())

// ChaCha20-Poly1305 encryption
cipher, _ := crypto.ChaCha20Poly1305CipherKeygen()
ciphertext, _ := cipher.Encrypt(plaintext, additionalData)
decrypted, _ := cipher.Decrypt(ciphertext, additionalData)
```

## Requirements

- Go 1.18 or later
- Access to an I2P router (for actual connections)
  - Default: `127.0.0.1:7654`
  - Configure via `~/.i2cp.conf` or environment variables

## Notes

- Most examples will fail to fully connect without a running I2P router
- The examples demonstrate API usage even when not connected to a router
- Error handling is shown for demonstration purposes
- In production, add more robust error handling and logging

## Environment Configuration

Create `~/.i2cp.conf` to configure connection settings:

```ini
i2cp.tcp.host=127.0.0.1
i2cp.tcp.port=7654
i2cp.username=
i2cp.password=
i2cp.SSL=false
```

Or use environment variables:

```bash
export I2CP_HOME=/path/to/config
export GO_I2CP_CONF=/custom/config.conf
```

## Further Reading

- [I2CP Specification](https://geti2p.net/spec/i2cp)
- [go-i2cp Documentation](../README.md)
- [Development Roadmap](../ROADMAP.md)

## Contributing

Found an issue or want to add an example? Please submit a pull request or open an issue on GitHub.
