package go_i2cp

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// X25519KeyPair represents an X25519 key exchange key pair for modern I2P ECDH
type X25519KeyPair struct {
	algorithmType uint32
	privateKey    [32]byte
	publicKey     [32]byte
}

// NewX25519KeyPair generates a new X25519 key pair for ECDH operations
func NewX25519KeyPair() (*X25519KeyPair, error) {
	var privateKey, publicKey [32]byte

	// Generate random private key
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	// Derive public key from private key
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &X25519KeyPair{
		algorithmType: X25519,
		privateKey:    privateKey,
		publicKey:     publicKey,
	}, nil
}

// X25519KeyPairFromStream reads an X25519 key pair from a stream
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

	var kp X25519KeyPair
	kp.algorithmType = algorithmType

	// Read private key (32 bytes)
	_, err = stream.Read(kp.privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read X25519 private key: %w", err)
	}

	// Read public key (32 bytes)
	_, err = stream.Read(kp.publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read X25519 public key: %w", err)
	}

	return &kp, nil
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
func (kp *X25519KeyPair) GenerateSharedSecret(peerPublicKey [32]byte) ([32]byte, error) {
	var sharedSecret [32]byte

	// Perform scalar multiplication: shared_secret = our_private * peer_public
	curve25519.ScalarMult(&sharedSecret, &kp.privateKey, &peerPublicKey)

	// Check for weak shared secrets (all zeros)
	var zero [32]byte
	if sharedSecret == zero {
		return sharedSecret, fmt.Errorf("generated weak shared secret (all zeros)")
	}

	return sharedSecret, nil
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

	// Write private key
	_, err = stream.Write(kp.privateKey[:])
	if err != nil {
		return fmt.Errorf("failed to write X25519 private key: %w", err)
	}

	// Write public key
	_, err = stream.Write(kp.publicKey[:])
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

	_, err := stream.Write(kp.publicKey[:])
	if err != nil {
		return fmt.Errorf("failed to write X25519 public key: %w", err)
	}

	return nil
}

// PublicKey returns a copy of the public key
func (kp *X25519KeyPair) PublicKey() [32]byte {
	return kp.publicKey
}

// PrivateKey returns a copy of the private key
func (kp *X25519KeyPair) PrivateKey() [32]byte {
	return kp.privateKey
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
