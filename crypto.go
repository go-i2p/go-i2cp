// Package go_i2cp provides I2CP protocol-specific cryptographic operations.
//
// IMPORTANT: This file exists solely to adapt cryptographic operations to I2CP
// message Stream format. All cryptographic primitives delegate to
// github.com/go-i2p/crypto for actual cryptographic implementations.
//
// Architecture:
//   - The Crypto type serves as an I2CP protocol adapter, NOT a cryptographic implementation
//   - Ed25519: Delegates to github.com/go-i2p/crypto/ed25519
//   - X25519: Delegates to github.com/go-i2p/crypto/curve25519
//   - ChaCha20-Poly1305: Delegates to github.com/go-i2p/crypto/chacha20poly1305
//
// Migration Status (Phase 3.0 - Legacy Crypto Removal Complete):
//   All modern crypto primitives migrated to github.com/go-i2p/crypto
//   Base32/Base64 encoding migrated to github.com/go-i2p/common
//   DSA and ElGamal legacy crypto removed
//
// Design Rationale:
// The I2CP protocol requires cryptographic operations to be serialized in
// specific binary formats for network transmission. Rather than implementing
// cryptography directly, this package provides thin adapters that:
//   1. Accept I2CP Stream objects for serialization
//   2. Delegate to specialized crypto packages for actual operations
//   3. Format results according to I2CP protocol specifications
//   4. Maintain backward compatibility with existing code
//
// See Also:
//   - github.com/go-i2p/crypto - Cryptographic implementations
//   - github.com/go-i2p/common - Shared data structures
//   - stream.go - I2CP binary message serialization

package go_i2cp

import (
	"crypto/rand"
	"fmt"
)

// NewCrypto creates a new Crypto instance
func NewCrypto() *Crypto {
	return &Crypto{
		rng: rand.Reader,
	}
}

// WriteEd25519SignatureToStream writes an Ed25519 signature keypair to stream
func (c *Crypto) WriteEd25519SignatureToStream(kp *Ed25519KeyPair, stream *Stream) error {
	if kp == nil {
		return fmt.Errorf("Ed25519 keypair cannot be nil")
	}
	return kp.WriteToStream(stream)
}

// Generate a signature keypair
func (c *Crypto) SignatureKeygen(algorithmTyp uint32) (sgk SignatureKeyPair, err error) {
	// Modern I2CP uses Ed25519 exclusively
	ed25519Kp, err := c.Ed25519SignatureKeygen()
	if err != nil {
		return sgk, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Store in SignatureKeyPair structure
	sgk.algorithmType = ED25519_SHA256
	sgk.ed25519KeyPair = ed25519Kp

	return sgk, nil
}

// Ed25519SignatureKeygen generates a new Ed25519 signature key pair
func (c *Crypto) Ed25519SignatureKeygen() (*Ed25519KeyPair, error) {
	return NewEd25519KeyPair()
}

// X25519KeyExchangeKeygen generates a new X25519 key exchange key pair
func (c *Crypto) X25519KeyExchangeKeygen() (*X25519KeyPair, error) {
	return NewX25519KeyPair()
}

// ChaCha20Poly1305CipherKeygen generates a new ChaCha20-Poly1305 cipher
func (c *Crypto) ChaCha20Poly1305CipherKeygen() (*ChaCha20Poly1305Cipher, error) {
	return NewChaCha20Poly1305Cipher()
}

// Random32 generates a cryptographically secure random uint32.
// Used for I2CP message nonces and request IDs per protocol specification
func (c *Crypto) Random32() uint32 {
	var bytes [4]byte
	_, err := c.rng.Read(bytes[:])
	if err != nil {
		// Fallback to a simpler method if crypto/rand fails
		// This should rarely happen in practice
		Fatal("Failed to generate random uint32: %v", err)
		return 0
	}
	// Convert big-endian bytes to uint32
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
