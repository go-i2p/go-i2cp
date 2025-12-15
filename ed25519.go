package go_i2cp

import (
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"

	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
)

// Ed25519 Implementation Migration Notes:
//
// This file has been migrated to use github.com/go-i2p/crypto/ed25519 (v0.0.5)
// for all cryptographic operations, following Phase 2.1 of the migration plan.
//
// Migration completed: November 24, 2025
//
// Key changes:
//   - Ed25519KeyPair now wraps crypto package types (Ed25519PrivateKey, Ed25519PublicKey)
//   - Sign() delegates to crypto.Signer interface (NewSigner().SignHash())
//   - Verify() delegates to crypto.Verifier interface (NewVerifier().VerifyHash())
//   - NewEd25519KeyPair() uses crypto.GenerateEd25519KeyPair()
//   - Maintains I2CP-specific SHA-512 pre-hashing for EdDSA-SHA512-Ed25519 compatibility
//   - Backward compatible API - all existing tests pass without modification
//
// The crypto package provides:
//   - Interface-based signing/verification (types.Signer, types.Verifier)
//   - Secure key generation and management
//   - Memory zeroing for private keys (privKey.Zero())
//   - Consistent cryptographic operations across go-i2p ecosystem

// Ed25519KeyPair represents an Ed25519 signature key pair for modern I2P cryptography.
// This type wraps github.com/go-i2p/crypto/ed25519 keys to provide I2CP-specific
// functionality while delegating cryptographic operations to the specialized crypto package.
type Ed25519KeyPair struct {
	algorithmType uint32
	privateKey    cryptoed25519.Ed25519PrivateKey
	publicKey     cryptoed25519.Ed25519PublicKey
}

// NewEd25519KeyPair generates a new Ed25519 key pair using github.com/go-i2p/crypto.
// This function delegates to the crypto package for secure key generation.
func NewEd25519KeyPair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := cryptoed25519.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	// Dereference pointers - crypto package keys are slices
	return &Ed25519KeyPair{
		algorithmType: ED25519_SHA256,
		privateKey:    *privateKey,
		publicKey:     *publicKey,
	}, nil
}

// readEd25519AlgorithmType reads and validates the algorithm type from the stream.
// Returns the algorithm type if valid for Ed25519, error otherwise.
func readEd25519AlgorithmType(stream *Stream) (uint32, error) {
	algorithmType, err := stream.ReadUint32()
	if err != nil {
		return 0, fmt.Errorf("failed to read algorithm type: %w", err)
	}

	if algorithmType != ED25519_SHA256 {
		return 0, fmt.Errorf("unsupported algorithm type: %d", algorithmType)
	}

	return algorithmType, nil
}

// readEd25519KeyBytes reads private and public key bytes from the stream.
// Returns private key bytes, public key bytes, and any error encountered.
func readEd25519KeyBytes(stream *Stream) ([]byte, []byte, error) {
	// Read private key (64 bytes for Ed25519)
	privateKeyBytes := make([]byte, ed25519.PrivateKeySize)
	_, err := stream.Read(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Read public key (32 bytes for Ed25519)
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	_, err = stream.Read(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return privateKeyBytes, publicKeyBytes, nil
}

// createEd25519KeyPairFromBytes constructs crypto package keys from raw bytes.
// Returns Ed25519PrivateKey, Ed25519PublicKey, and any error encountered.
func createEd25519KeyPairFromBytes(privateKeyBytes, publicKeyBytes []byte) (cryptoed25519.Ed25519PrivateKey, cryptoed25519.Ed25519PublicKey, error) {
	privKey, err := cryptoed25519.CreateEd25519PrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private key: %w", err)
	}

	pubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create public key: %w", err)
	}

	return privKey, pubKey, nil
}

// Ed25519KeyPairFromStream reads an Ed25519 key pair from a stream.
// Uses github.com/go-i2p/crypto/ed25519 for key reconstruction.
func Ed25519KeyPairFromStream(stream *Stream) (*Ed25519KeyPair, error) {
	algorithmType, err := readEd25519AlgorithmType(stream)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, publicKeyBytes, err := readEd25519KeyBytes(stream)
	if err != nil {
		return nil, err
	}

	privKey, pubKey, err := createEd25519KeyPairFromBytes(privateKeyBytes, publicKeyBytes)
	if err != nil {
		return nil, err
	}

	return &Ed25519KeyPair{
		algorithmType: algorithmType,
		privateKey:    privKey,
		publicKey:     pubKey,
	}, nil
}

// Ed25519PublicKeyFromStream reads only the public key from a stream.
// Returns stdlib ed25519.PublicKey for backward compatibility.
func Ed25519PublicKeyFromStream(stream *Stream) (ed25519.PublicKey, error) {
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	_, err := stream.Read(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ed25519 public key: %w", err)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

// Sign creates a signature for the given message using Ed25519.
// Uses github.com/go-i2p/crypto/ed25519 Signer interface for cryptographic operations.
func (kp *Ed25519KeyPair) Sign(message []byte) ([]byte, error) {
	if kp.privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Create signer from private key
	signer, err := kp.privateKey.NewSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// For I2CP compatibility, hash the message first using SHA-512 (EdDSA-SHA512-Ed25519)
	hasher := sha512.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Sign the hash using the crypto package's interface-based signing
	signature, err := signer.SignHash(messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return signature, nil
}

// SignStream creates a signature for stream data and appends it to the stream
func (kp *Ed25519KeyPair) SignStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	signature, err := kp.Sign(stream.Bytes())
	if err != nil {
		return fmt.Errorf("failed to sign stream: %w", err)
	}

	_, err = stream.Write(signature)
	if err != nil {
		return fmt.Errorf("failed to write signature to stream: %w", err)
	}

	return nil
}

// Verify verifies a signature against the given message using Ed25519.
// Uses github.com/go-i2p/crypto/ed25519 Verifier interface for cryptographic operations.
func (kp *Ed25519KeyPair) Verify(message, signature []byte) bool {
	if kp.publicKey == nil {
		return false
	}

	// Create verifier from public key
	verifier, err := kp.publicKey.NewVerifier()
	if err != nil {
		return false
	}

	// Hash the message for I2CP compatibility (EdDSA-SHA512-Ed25519)
	hasher := sha512.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Verify using the crypto package's interface-based verification
	err = verifier.VerifyHash(messageHash, signature)
	return err == nil
}

// VerifyStream verifies a signature embedded in the stream data
func (kp *Ed25519KeyPair) VerifyStream(stream *Stream) (bool, error) {
	if stream == nil {
		return false, fmt.Errorf("stream cannot be nil")
	}

	if stream.Len() < ed25519.SignatureSize {
		return false, fmt.Errorf("stream too short for Ed25519 signature")
	}

	// Reset stream to beginning to ensure we read all data correctly
	stream.Seek(0, 0)

	// Extract all data from stream
	allData := make([]byte, stream.Len())
	n, err := stream.Read(allData)
	if err != nil || n != stream.Len() {
		return false, fmt.Errorf("failed to read stream data: %w", err)
	}

	// Extract message and signature from the complete data
	messageLen := len(allData) - ed25519.SignatureSize
	message := allData[:messageLen]
	signature := allData[messageLen:]

	return kp.Verify(message, signature), nil
}

// WriteToStream writes the complete Ed25519 key pair to a stream
func (kp *Ed25519KeyPair) WriteToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	// Write algorithm type
	err := stream.WriteUint32(kp.algorithmType)
	if err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}

	// Write private key
	_, err = stream.Write(kp.privateKey)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key
	_, err = stream.Write(kp.publicKey)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// WritePublicKeyToStream writes only the public key to a stream.
// Uses crypto package's Bytes() method for key serialization.
func (kp *Ed25519KeyPair) WritePublicKeyToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	_, err := stream.Write(kp.publicKey.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write Ed25519 public key: %w", err)
	}

	return nil
}

// PublicKey returns the public key as stdlib ed25519.PublicKey for backward compatibility.
func (kp *Ed25519KeyPair) PublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(kp.publicKey.Bytes())
}

// PrivateKey returns the private key as stdlib ed25519.PrivateKey for backward compatibility.
func (kp *Ed25519KeyPair) PrivateKey() ed25519.PrivateKey {
	return ed25519.PrivateKey(kp.privateKey.Bytes())
}

// AlgorithmType returns the algorithm type constant
func (kp *Ed25519KeyPair) AlgorithmType() uint32 {
	return kp.algorithmType
}
