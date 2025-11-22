# Modern Cryptography Demo

This example demonstrates the modern cryptographic algorithms supported by go-i2cp.

## Features Demonstrated

- **Ed25519 Digital Signatures**: Fast, secure signing and verification
- **X25519 Key Exchange**: ECDH for perfect forward secrecy
- **ChaCha20-Poly1305 Encryption**: Authenticated encryption with additional data (AEAD)
- **Stream Serialization**: I2CP protocol-compatible serialization
- **Legacy DSA Support**: Backward compatibility with older I2P versions

## What You'll Learn

- How to generate key pairs for multiple algorithms
- Message signing and signature verification
- Diffie-Hellman key exchange (ECDH)
- Authenticated encryption and decryption
- Serialization and deserialization of cryptographic keys
- Integration with the I2CP Crypto struct

## Running the Example

```bash
cd examples/modern-crypto
go run modern_crypto_demo.go
```

## Building the Example

```bash
cd examples/modern-crypto
go build
./modern-crypto
```

## Example Output

The demo will show:

```
=== I2CP Modern Cryptography Demo ===
✅ Crypto system initialized

🔑 Ed25519 Digital Signatures:
   ✅ Generated Ed25519 key pair
   ✅ Signed message (64 bytes signature)
   ✅ Signature verification successful

🔐 X25519 Key Exchange (ECDH):
   ✅ Generated Alice's X25519 key pair
   ✅ Generated Bob's X25519 key pair
   ✅ ECDH successful - shared secret established

🔒 ChaCha20-Poly1305 Authenticated Encryption:
   ✅ Created ChaCha20-Poly1305 cipher
   ✅ Encrypted message: 54 bytes → 70 bytes
   ✅ Decryption successful - message integrity verified

💾 Stream Serialization (I2CP compatibility):
   ✅ Ed25519 key pair serialized
   ✅ Ed25519 serialization/deserialization successful

🔄 Legacy DSA Support (preserved):
   ✅ Generated DSA key pair
   ✅ Legacy DSA functionality preserved

🎉 I2CP cryptography modernization complete!
```

## Code Highlights

### Ed25519 Signatures

```go
crypto := go_i2cp.NewCrypto()
kp, _ := crypto.Ed25519SignatureKeygen()
signature, _ := kp.Sign(message)
verified := kp.Verify(message, signature)
```

### X25519 Key Exchange

```go
aliceKp, _ := crypto.X25519KeyExchangeKeygen()
bobKp, _ := crypto.X25519KeyExchangeKeygen()
sharedSecret, _ := aliceKp.GenerateSharedSecret(bobKp.PublicKey())
```

### ChaCha20-Poly1305 Encryption

```go
cipher, _ := crypto.ChaCha20Poly1305CipherKeygen()
ciphertext, _ := cipher.Encrypt(plaintext, additionalData)
decrypted, _ := cipher.Decrypt(ciphertext, additionalData)
```

### Stream Serialization

```go
stream := go_i2cp.NewStream(make([]byte, 0, 1024))
kp.WriteToStream(stream)
kp2, _ := go_i2cp.Ed25519KeyPairFromStream(stream)
```

## Cryptographic Algorithms

### Ed25519
- **Type**: Digital signature algorithm
- **Security**: 128-bit security level
- **Key Size**: 32 bytes (public), 64 bytes (private)
- **Signature Size**: 64 bytes
- **Performance**: Very fast signing and verification
- **Use Case**: Message authentication, identity verification

### X25519
- **Type**: Elliptic curve Diffie-Hellman (ECDH)
- **Security**: 128-bit security level
- **Key Size**: 32 bytes (public and private)
- **Shared Secret**: 32 bytes
- **Performance**: Fast key exchange
- **Use Case**: Perfect forward secrecy, session key establishment

### ChaCha20-Poly1305
- **Type**: Authenticated encryption with additional data (AEAD)
- **Security**: 256-bit key, 128-bit authentication
- **Key Size**: 32 bytes
- **Nonce Size**: 12 bytes
- **Authentication Tag**: 16 bytes
- **Performance**: Very fast on modern CPUs
- **Use Case**: Secure message encryption, tunnel encryption

## Requirements

- Go 1.18 or later
- No I2P router required (this example works standalone)

## Related Examples

- [Context Usage](../context-usage/) - Demonstrates context-aware operations
- [Examples Overview](../) - All available examples

## Further Reading

- [Ed25519 Specification](https://ed25519.cr.yp.to/)
- [RFC 7748 - X25519](https://tools.ietf.org/html/rfc7748)
- [RFC 8439 - ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439)
- [I2CP Specification](https://geti2p.net/spec/i2cp)
- [go-i2cp Main Documentation](../../README.md)
