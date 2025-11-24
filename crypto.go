// Package go_i2cp provides I2CP protocol-specific cryptographic operations.
//
// IMPORTANT: This file exists solely to adapt cryptographic operations to I2CP
// message Stream format. All cryptographic primitives delegate to
// github.com/go-i2p/crypto for actual cryptographic implementations.
//
// Architecture:
//   - The Crypto type serves as an I2CP protocol adapter, NOT a cryptographic implementation
//   - Stream-based signing/verification for I2CP message format compatibility
//   - DSA signature serialization to I2CP Stream format (40-byte digest)
//   - Backwards compatibility for existing I2CP message handlers
//
// Cryptographic Operations:
//   - DSA (Legacy): Wraps crypto/dsa and github.com/go-i2p/crypto/dsa
//   - Ed25519: Delegates to github.com/go-i2p/crypto/ed25519
//   - X25519: Delegates to github.com/go-i2p/crypto/curve25519
//   - ChaCha20-Poly1305: Delegates to github.com/go-i2p/crypto/chacha20poly1305
//
// Migration Status (Phase 2.1 - Complete):
//   All modern crypto primitives migrated to github.com/go-i2p/crypto
//   Base32/Base64 encoding migrated to github.com/go-i2p/common
//   Wrapper pattern maintains API compatibility
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
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"math/big"
)

// NewCrypto creates a new Crypto instance
func NewCrypto() *Crypto {
	c := &Crypto{
		sh1: sha1.New(),
		rng: rand.Reader,
	}
	// Initialize DSA parameters on first use for performance
	dsa.GenerateParameters(&c.params, c.rng, dsa.L1024N160)
	return c
}

// Sign a stream using the specified algorithm
func (c *Crypto) SignStream(sgk *SignatureKeyPair, stream *Stream) (err error) {
	// Use new DSA wrapper if available
	if sgk.dsaKeyPair != nil {
		signature, err := sgk.dsaKeyPair.Sign(stream.Bytes())
		if err != nil {
			return fmt.Errorf("failed to sign stream with DSA: %w", err)
		}
		stream.Write(signature)
		return nil
	}

	// Fallback to legacy implementation for backward compatibility
	var r, s *big.Int
	out := NewStream(make([]byte, 40))
	c.sh1.Reset()
	sum := c.sh1.Sum(stream.Bytes())
	r, s, err = dsa.Sign(c.rng, &sgk.priv, sum)
	err = writeDsaSigToStream(r, s, out)
	stream.Write(out.Bytes())
	return
}

// Writes a 40-byte signature digest to the stream
func writeDsaSigToStream(r, s *big.Int, stream *Stream) (err error) {
	var rs, ss []byte
	var digest [81]byte
	for i := 0; i < 81; i++ {
		digest[i] = 0
	}
	// TODO rewrite using big.Int.Bytes()
	bites := stream.Bytes()
	rs = r.Bytes()
	if len(rs) > 21 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "DSA digest r > 21 bytes")
	} else if len(rs) > 20 {
		copy(bites[:20], rs[len(rs)-20:])
	} else if len(rs) == 20 {
		copy(bites[:20], rs)
	} else {
		copy(bites[20-len(rs):20], rs)
	}
	ss = s.Bytes()
	if len(ss) > 21 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "DSA digest r > 21 bytes")
	} else if len(ss) > 20 {
		copy(bites[20:], ss[len(ss)-20:])
	} else if len(ss) == 20 {
		copy(bites[20:], ss)
	} else {
		copy(bites[40-len(ss):], ss)
	}
	return
}

// Verify Stream
func (c *Crypto) VerifyStream(sgk *SignatureKeyPair, stream *Stream) (verified bool, err error) {
	if stream.Len() < 40 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Stream length < 40 bytes (signature length)")
		return false, fmt.Errorf("stream too short for signature verification")
	}

	message := stream.Bytes()[:stream.Len()-40]
	signature := stream.Bytes()[stream.Len()-40:]

	// Use new DSA wrapper if available
	if sgk.dsaKeyPair != nil {
		verified = sgk.dsaKeyPair.Verify(message, signature)
		return verified, nil
	}

	// Fallback to legacy implementation for backward compatibility
	var r, s big.Int
	// TODO not sure about this part...
	r.SetBytes(signature[:20])
	s.SetBytes(signature[20:])
	verified = dsa.Verify(&sgk.pub, message, &r, &s)
	return
}

// Write public signature key to stream
func (c *Crypto) WritePublicSignatureToStream(sgk *SignatureKeyPair, stream *Stream) (err error) {
	if sgk.algorithmType != DSA_SHA1 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Failed to write unsupported signature keypair to stream.")
	}
	var n int
	n, err = stream.Write(sgk.pub.Y.Bytes())
	if n != 128 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Failed to export signature because privatekey != 20 bytes")
	}
	return
}

// Write Signature keypair to stream
func (c *Crypto) WriteSignatureToStream(sgk *SignatureKeyPair, stream *Stream) (err error) {
	if sgk == nil {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Error signature cannot be nil")
		return fmt.Errorf("Error, signature cannot be nil")
	}
	if stream == nil {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Error, stream cannot be nil")
		return fmt.Errorf("Error, stream cannot be nil")
	}
	if sgk.algorithmType != DSA_SHA1 {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Failed to write unsupported signature keypair to stream.")
		return fmt.Errorf("Failed to write unsupported signature keypair to stream.")
	}
	err = stream.WriteUint32(sgk.algorithmType)
	if err != nil {
		return err
	}
	// Pad private key X to exactly 20 bytes (DSA_SHA1_PRIV_KEY_SIZE)
	// big.Int.Bytes() returns minimal representation without leading zeros
	privKeyBytes := sgk.priv.X.Bytes()
	paddedPrivKey := make([]byte, 20)
	copy(paddedPrivKey[20-len(privKeyBytes):], privKeyBytes)
	_, err = stream.Write(paddedPrivKey)
	if err != nil {
		return err
	}
	// Pad public key Y to exactly 128 bytes (DSA_SHA1_PUB_KEY_SIZE)
	// big.Int.Bytes() returns minimal representation without leading zeros
	pubKeyBytes := sgk.pub.Y.Bytes()
	paddedPubKey := make([]byte, 128)
	copy(paddedPubKey[128-len(pubKeyBytes):], pubKeyBytes)
	_, err = stream.Write(paddedPubKey)
	if err != nil {
		return err
	}
	return
}

// WriteEd25519SignatureToStream writes an Ed25519 signature keypair to stream
func (c *Crypto) WriteEd25519SignatureToStream(kp *Ed25519KeyPair, stream *Stream) error {
	if kp == nil {
		return fmt.Errorf("Ed25519 keypair cannot be nil")
	}
	return kp.WriteToStream(stream)
}

// Read and initialize signature keypair from stream
func (c *Crypto) SignatureKeyPairFromStream(stream *Stream) (sgk SignatureKeyPair, err error) {
	var typ uint32
	typ, err = stream.ReadUint32()
	if err != nil {
		return sgk, fmt.Errorf("failed to read signature type: %w", err)
	}
	if typ == DSA_SHA1 {
		keys := make([]byte, 20+128)
		_, err = stream.Read(keys)
		if err != nil {
			return sgk, fmt.Errorf("failed to read signature keys: %w", err)
		}
		sgk.algorithmType = typ
		// Initialize big.Int pointers before calling SetBytes
		sgk.priv.X = new(big.Int)
		sgk.priv.Y = new(big.Int)
		sgk.pub.Y = new(big.Int)
		sgk.priv.X.SetBytes(keys[:20])
		sgk.priv.Y.SetBytes(keys[20:])
		sgk.pub.Y.SetBytes(keys[20:])
	} else {
		Fatal(fmt.Sprintf("%08x", tAG|FATAL), "Failed to read unsupported signature keypair from stream.")
	}
	return
}

func (c *Crypto) PublicKeyFromStream(keyType uint32, stream *Stream) (key *big.Int, err error) {
	if keyType == DSA_SHA1 {
		key = &big.Int{}
		keyBytes := make([]byte, 128)
		_, err = stream.Read(keyBytes)
		key.SetBytes(keyBytes)
		return key, err
	} else {
		Fatal(fmt.Sprintf("%08x", CRYPTO), "Unknown signature algorithm")
		return nil, errors.New("Unknown signature algorithm")
	}
}

// Generate a signature keypair
func (c *Crypto) SignatureKeygen(algorithmTyp uint32) (sgk SignatureKeyPair, err error) {
	switch algorithmTyp {
	case DSA_SHA1:
		// Use new DSA wrapper from crypto package
		dsaKp, err := c.DSASignatureKeygen()
		if err != nil {
			return sgk, fmt.Errorf("failed to generate DSA key pair: %w", err)
		}

		// Convert new DSAKeyPair to legacy SignatureKeyPair for backward compatibility
		// This allows existing code to continue working while we migrate to the new types
		sgk.algorithmType = DSA_SHA1
		sgk.dsaKeyPair = dsaKp

		// Also populate legacy fields for backward compatibility
		// Extract raw bytes and reconstruct old big.Int format
		privKeyBytes := dsaKp.PrivateKey()
		pubKeyBytes := dsaKp.PublicKey()

		// Initialize DSA parameters from crypto struct
		sgk.priv.G = c.params.G
		sgk.priv.Q = c.params.Q
		sgk.priv.P = c.params.P
		sgk.pub.G = c.params.G
		sgk.pub.Q = c.params.Q
		sgk.pub.P = c.params.P

		// Set private key X from bytes
		sgk.priv.X = new(big.Int)
		sgk.priv.X.SetBytes(privKeyBytes)

		// Set public key Y from bytes
		sgk.pub.Y = new(big.Int)
		sgk.pub.Y.SetBytes(pubKeyBytes)
		sgk.priv.Y = sgk.pub.Y // Private key also stores public key Y
	default:
		err = fmt.Errorf("unsupported signature algorithm type: %d", algorithmTyp)
	}
	return
} // Ed25519SignatureKeygen generates a new Ed25519 signature key pair
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

// DSASignatureKeygen generates a new DSA signature key pair
func (c *Crypto) DSASignatureKeygen() (*DSAKeyPair, error) {
	return NewDSAKeyPair()
}

// Random32 generates a cryptographically secure random uint32.
// Used for I2CP message nonces and request IDs per protocol specification
func (c *Crypto) Random32() uint32 {
	var bytes [4]byte
	_, err := c.rng.Read(bytes[:])
	if err != nil {
		// Fallback to a simpler method if crypto/rand fails
		// This should rarely happen in practice
		Fatal(fmt.Sprintf("%08x", tAG|ERROR), "Failed to generate random uint32: %v", err)
		return 0
	}
	// Convert big-endian bytes to uint32
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
