# Source Destination API - Usage Guide

## Overview

The go-i2cp library **already exposes source destinations** from incoming I2CP messages through the `OnMessage` callback. This guide demonstrates how to use this feature for implementing the I2P Streaming Protocol and other use cases that require knowing the sender's destination.

## API Summary

### 1. Receiving Source Destination (Already Implemented)

Every message received via I2CP includes the sender's destination:

```go
callbacks := SessionCallbacks{
    OnMessage: func(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
        // srcDest is ALWAYS available - parsed from I2CP MessagePayloadMessage
        fmt.Printf("Message from: %s\n", srcDest.Base32())
    },
}
```

**Location in Code**: `client.go:610-665` (onMsgPayload function)

The I2CP layer parses the source destination from the `MessagePayloadMessage` (type 31) and passes it to your callback. This happens automatically for all incoming messages.

### 2. Signature Verification (New in this PR)

Two new methods for offline signature verification:

```go
// Method 1: Direct verification via Destination
isValid := srcDest.VerifySignature(message, signature)

// Method 2: Get public key for advanced usage
pubKey := srcDest.SigningPublicKey()
isValid := pubKey.Verify(message, signature)
```

## Use Cases

### Use Case 1: I2P Streaming Protocol Server Mode

**Problem**: Java I2P clients send packets without `FlagFromIncluded` for efficiency. The streaming library needs to know who sent the packet.

**Solution**: The source destination is available from the I2CP layer:

```go
func (sm *StreamManager) handleIncomingMessage(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
    if protocol != 6 {
        return // Not streaming protocol
    }

    // Parse streaming packet
    packet := &StreamingPacket{}
    packet.Unmarshal(payload.Bytes())

    // srcDest is ALWAYS available from I2CP layer
    // No need for FlagFromIncluded optimization bandwidth waste
    conn := sm.getOrCreateConnection(srcDest, packet)
    conn.handlePacket(packet)
}
```

### Use Case 2: Offline Signature Verification

**Problem**: Need to cryptographically verify packet signatures without the sender's private key.

**Solution**: Extract the signing public key from the source destination:

```go
func verifyStreamingPacket(srcDest *Destination, packet *StreamingPacket) bool {
    // Extract signature from packet
    signature := packet.Signature

    // Compute signature input (packet without signature field)
    signatureInput := packet.MarshalForSignature()

    // Verify using source destination's public key
    return srcDest.VerifySignature(signatureInput, signature)
}
```

### Use Case 3: Connection Tracking

**Problem**: Need to maintain state for multiple concurrent connections from different peers.

**Solution**: Use source destination as connection identifier:

```go
type StreamManager struct {
    connections map[string]*Connection // key: srcDest.Base32()
    mu          sync.RWMutex
}

func (sm *StreamManager) getConnection(srcDest *Destination) *Connection {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    return sm.connections[srcDest.Base32()]
}
```

## Implementation Details

### I2CP Message Flow

1. **Remote peer sends message** → Router delivers via I2CP `MessagePayloadMessage` (type 31)
2. **go-i2cp parses message** → Extracts source destination from I2CP protocol
3. **OnMessage callback invoked** → Your code receives `srcDest` parameter
4. **Signature verification** → Use `srcDest.VerifySignature()` for packet authentication

### Wire Format

The I2CP `MessagePayloadMessage` (type 31) includes:

```
+----------------+
| Session ID     | 2 bytes
| Message ID     | 4 bytes
| Payload Size   | 4 bytes
| Source Dest    | 387+ bytes (THIS IS WHAT YOU REQUESTED!)
| Gzip flags     | 1 byte
| Source Port    | 2 bytes
| Dest Port      | 2 bytes
| Protocol byte  | 1 byte
| Protocol ID    | 1 byte
| Compressed     | variable
| Payload        |
+----------------+
```

The source destination is **already in the I2CP protocol** - go-i2cp just needed to expose it via the callback (which it already does).

## New API Methods

### Destination Methods

```go
// SigningPublicKey returns the Ed25519 public key for signature verification.
// This allows verification of signatures without needing the private key.
// Returns nil if no Ed25519 keypair is available.
func (dest *Destination) SigningPublicKey() *Ed25519KeyPair

// VerifySignature verifies a signature against the given message using this 
// destination's signing public key. This is useful for offline signature 
// verification without access to the private key.
//
// Returns true if the signature is valid, false otherwise.
func (dest *Destination) VerifySignature(message, signature []byte) bool
```

### Ed25519KeyPair Methods

The existing `Verify()` method works with just the public key:

```go
// Verify verifies a signature against the given message using Ed25519.
// Uses github.com/go-i2p/crypto/ed25519 Verifier interface.
// Works with public-key-only Ed25519KeyPair instances.
func (kp *Ed25519KeyPair) Verify(message, signature []byte) bool
```

## Comparison with Request

| Feature | Requested | Status |
|---------|-----------|--------|
| Access to source destination | Option 1: Add `From` field | ✅ **Already available** via `srcDest` callback parameter |
| Retrieve source destination | Option 2: `GetLastMessageSource()` | ✅ **Not needed** - available in callback |
| Signature verification | Option 3: Public key verify | ✅ **Implemented** - `VerifySignature()` and `SigningPublicKey()` |

## Examples

See the example programs:

- `examples/source-destination/main.go` - Complete demonstration of all use cases
- `examples/external-callbacks/main.go` - Shows OnMessage callback usage
- `examples/signing-keypair-usage/main.go` - Shows signing key pair operations

Run the example:

```bash
cd examples/source-destination
go run main.go
```

## Impact on go-streaming

With these APIs, go-streaming can now:

✅ **Handle packets without FlagFromIncluded** - Source from I2CP layer  
✅ **Verify signatures cryptographically** - `srcDest.VerifySignature()`  
✅ **Implement server mode** - `srcDest` identifies remote peer  
✅ **Optimize bandwidth** - No need to send 387+ byte destination in every packet  
✅ **Java I2P compatibility** - Matches Java I2P router behavior

## Testing

Unit tests demonstrate the verification functionality:

```bash
# Run all tests
go test ./...

# Test specific functionality
go test -v -run TestDestination
go test -v -run TestEd25519
```

## Migration Notes

If you were using workarounds (like always setting `FlagFromIncluded`):

**Before** (bandwidth inefficient):
```go
packet.Flags |= FlagFromIncluded
packet.From = myDestination // 387+ bytes overhead per packet
```

**After** (optimized):
```go
// Don't set FlagFromIncluded
// Source destination comes from I2CP layer automatically
func handleMessage(session *Session, srcDest *Destination, ...) {
    // srcDest is automatically available!
}
```

## References

- I2CP Specification: https://geti2p.net/spec/i2cp
- I2P Streaming Protocol: https://geti2p.net/spec/streaming
- go-i2cp Implementation: `client.go` (line 610) - `onMsgPayload()`
- Ed25519 Verification: `ed25519.go` - `Verify()` method
