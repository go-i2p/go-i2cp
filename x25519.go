// Migration Notes (November 24, 2025):
// Migrated to use github.com/go-i2p/crypto/curve25519 package which provides
// standardized X25519 key generation and ECDH operations via go.step.sm/crypto/x25519.
//
// Key Changes:
// - X25519KeyPair now wraps curve25519.Curve25519PrivateKey and Curve25519PublicKey (slice types)
// - NewX25519KeyPair() delegates to curve25519.GenerateX25519KeyPair()
// - GenerateSharedSecret() uses PrivateKey.SharedKey() for ECDH operations
// - Maintains [32]byte return types for backward compatibility
//
// The crypto package uses []byte (slice) types for keys, while I2CP uses
// [32]byte arrays. The wrapper maintains I2CP compatibility.

package go_i2cp

import (
	"fmt"

	cryptox25519 "github.com/go-i2p/crypto/curve25519"
	"go.step.sm/crypto/x25519"
)

// X25519KeyPair represents an X25519 key exchange key pair for modern I2P ECDH
// Wraps github.com/go-i2p/crypto/curve25519 types
type X25519KeyPair struct {
	algorithmType uint32
	privateKey    cryptox25519.Curve25519PrivateKey
	publicKey     cryptox25519.Curve25519PublicKey
}

// NewX25519KeyPair generates a new X25519 key pair for ECDH operations
// Delegates to github.com/go-i2p/crypto/curve25519.GenerateX25519KeyPair()
func NewX25519KeyPair() (*X25519KeyPair, error) {
	// Generate key pair using crypto package
	pubKey, privKey, err := cryptox25519.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 key pair: %w", err)
	}

	// Dereference pointers to get slice values
	return &X25519KeyPair{
		algorithmType: X25519,
		privateKey:    *privKey,
		publicKey:     *pubKey,
	}, nil
}

// X25519KeyPairFromStream reads an X25519 key pair from a stream
// Uses go.step.sm/crypto/x25519 for key reconstruction and validation
func X25519KeyPairFromStream(stream *Stream) (*X25519KeyPair, error) {
	var algorithmType uint32
	var err error

	algorithmType, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithm type: %w", err)
	}

	if algorithmType != X25519 {
		return nil, fmt.Errorf("unsupported algorithm type: %d", algorithmType)
	}

	// Read private key (32 bytes)
	privKeyBytes := make([]byte, 32)
	_, err = stream.Read(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read X25519 private key: %w", err)
	}

	// Read public key (32 bytes)
	pubKeyBytes := make([]byte, 32)
	_, err = stream.Read(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read X25519 public key: %w", err)
	}

	// Validate that the public key corresponds to the private key
	privKey := make(x25519.PrivateKey, 32)
	copy(privKey, privKeyBytes)

	expectedPubKeyInterface := privKey.Public()
	expectedPubKey, ok := expectedPubKeyInterface.(x25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert public key to x25519.PublicKey")
	}

	// Compare public keys
	if !bytesEqual(expectedPubKey, pubKeyBytes) {
		return nil, fmt.Errorf("public key does not match private key")
	}

	return &X25519KeyPair{
		algorithmType: algorithmType,
		privateKey:    cryptox25519.Curve25519PrivateKey(privKeyBytes),
		publicKey:     cryptox25519.Curve25519PublicKey(pubKeyBytes),
	}, nil
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// X25519PublicKeyFromStream reads only the public key from a stream
func X25519PublicKeyFromStream(stream *Stream) ([32]byte, error) {
	var publicKey [32]byte
	_, err := stream.Read(publicKey[:])
	if err != nil {
		return publicKey, fmt.Errorf("failed to read X25519 public key: %w", err)
	}
	return publicKey, nil
}

// GenerateSharedSecret performs ECDH to generate a shared secret with the peer's public key
// Uses go.step.sm/crypto/x25519 PrivateKey.SharedKey() for ECDH
func (kp *X25519KeyPair) GenerateSharedSecret(peerPublicKey [32]byte) ([32]byte, error) {
	var result [32]byte

	// Validate the peer's public key first
	if !ValidateX25519PublicKey(peerPublicKey) {
		return result, fmt.Errorf("invalid peer public key")
	}

	// Convert slice to x25519 types for SharedKey operation
	privKey := make(x25519.PrivateKey, 32)
	copy(privKey, kp.privateKey)

	pubKey := make(x25519.PublicKey, 32)
	copy(pubKey, peerPublicKey[:])

	// Perform X25519 key exchange (ECDH)
	sharedSecret, err := privKey.SharedKey(pubKey)
	if err != nil {
		return result, fmt.Errorf("X25519 key exchange failed: %w", err)
	}

	// Additional security check: reject all-zero shared secrets
	var zero [32]byte
	copy(result[:], sharedSecret)
	if result == zero {
		return result, fmt.Errorf("generated weak shared secret (all zeros)")
	}

	return result, nil
}

// WriteToStream writes the complete X25519 key pair to a stream
func (kp *X25519KeyPair) WriteToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	// Write algorithm type
	err := stream.WriteUint32(kp.algorithmType)
	if err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}

	// Write private key (convert slice to bytes)
	_, err = stream.Write(kp.privateKey)
	if err != nil {
		return fmt.Errorf("failed to write X25519 private key: %w", err)
	}

	// Write public key (convert slice to bytes)
	_, err = stream.Write(kp.publicKey)
	if err != nil {
		return fmt.Errorf("failed to write X25519 public key: %w", err)
	}

	return nil
}

// WritePublicKeyToStream writes only the public key to a stream
func (kp *X25519KeyPair) WritePublicKeyToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	_, err := stream.Write(kp.publicKey)
	if err != nil {
		return fmt.Errorf("failed to write X25519 public key: %w", err)
	}

	return nil
}

// PublicKey returns a copy of the public key as [32]byte for backward compatibility
func (kp *X25519KeyPair) PublicKey() [32]byte {
	var result [32]byte
	copy(result[:], kp.publicKey)
	return result
}

// PrivateKey returns a copy of the private key as [32]byte for backward compatibility
func (kp *X25519KeyPair) PrivateKey() [32]byte {
	var result [32]byte
	copy(result[:], kp.privateKey)
	return result
}

// AlgorithmType returns the algorithm type constant
func (kp *X25519KeyPair) AlgorithmType() uint32 {
	return kp.algorithmType
}

// ValidatePublicKey checks if a public key is valid for X25519
func ValidateX25519PublicKey(publicKey [32]byte) bool {
	// Check for forbidden values in X25519
	// Reject all-zero key
	var zero [32]byte
	if publicKey == zero {
		return false
	}

	// Reject all-one key (equivalent to -1 in field)
	var allOnes [32]byte
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	if publicKey == allOnes {
		return false
	}

	// Additional validation could be added here for other weak keys
	return true
}
