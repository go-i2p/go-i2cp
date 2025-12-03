package go_i2cp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math/big"

	cryptodsa "github.com/go-i2p/crypto/dsa"
	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
)

// Signature Verification Methods
//
// This file implements cryptographic signature verification for I2CP protocol.
// Delegates to github.com/go-i2p/crypto for all cryptographic operations.
//
// Supported signature algorithms:
//   - DSA-SHA1 (legacy, type 0): 40-byte signatures
//   - Ed25519-SHA512 (modern, type 7): 64-byte signatures
//
// I2CP Specification: LeaseSet2 signature verification (section 3.4)
// References: https://geti2p.net/spec/common-structures#leaseset2

// verifyDSASignature verifies a DSA-SHA1 signature using github.com/go-i2p/crypto/dsa.
//
// Parameters:
//   - pubKeyBytes: DSA public key (128 bytes for I2CP DSA keys)
//   - message: The message that was signed
//   - signature: DSA signature (40 bytes: [r:20][s:20] in big-endian)
//
// Returns true if signature is valid, false otherwise.
func verifyDSASignature(pubKeyBytes, message, signature []byte) bool {
	// Validate signature length (40 bytes for DSA)
	if len(signature) != 40 {
		Error("Invalid DSA signature length: got %d, expected 40", len(signature))
		return false
	}

	// Validate public key length (128 bytes for I2CP DSA)
	if len(pubKeyBytes) != 128 {
		Error("Invalid DSA public key length: got %d, expected 128", len(pubKeyBytes))
		return false
	}

	// Reconstruct DSA public key from bytes
	var pubKey cryptodsa.DSAPublicKey
	copy(pubKey[:], pubKeyBytes)

	// Create verifier from public key
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		Error("Failed to create DSA verifier: %v", err)
		return false
	}

	// Verify the signature
	err = verifier.Verify(message, signature)
	if err != nil {
		Debug("DSA signature verification failed: %v", err)
		return false
	}

	return true
}

// verifyEd25519Signature verifies an Ed25519-SHA512 signature using github.com/go-i2p/crypto/ed25519.
//
// Parameters:
//   - pubKeyBytes: Ed25519 public key (32 bytes)
//   - message: The message that was signed
//   - signature: Ed25519 signature (64 bytes)
//
// Returns true if signature is valid, false otherwise.
func verifyEd25519Signature(pubKeyBytes, message, signature []byte) bool {
	// Validate signature length (64 bytes for Ed25519)
	if len(signature) != ed25519.SignatureSize {
		Error("Invalid Ed25519 signature length: got %d, expected %d", len(signature), ed25519.SignatureSize)
		return false
	}

	// Validate public key length (32 bytes for Ed25519)
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		Error("Invalid Ed25519 public key length: got %d, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
		return false
	}

	// Reconstruct Ed25519 public key from bytes
	pubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		Error("Failed to create Ed25519 public key: %v", err)
		return false
	}

	// Create verifier from public key
	verifier, err := pubKey.NewVerifier()
	if err != nil {
		Error("Failed to create Ed25519 verifier: %v", err)
		return false
	}

	// For I2CP compatibility, hash the message with SHA-256
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	// Verify the signature using hash
	err = verifier.VerifyHash(messageHash, signature)
	if err != nil {
		Debug("Ed25519 signature verification failed: %v", err)
		return false
	}

	return true
}

// verifyDSASignatureLegacy verifies a DSA signature using legacy big.Int r,s components.
// This is a fallback method for backward compatibility with older code.
//
// Deprecated: Use verifyDSASignature instead which uses the crypto package.
func verifyDSASignatureLegacy(pubKeyBytes, message []byte, r, s *big.Int) bool {
	if len(pubKeyBytes) != 128 {
		return false
	}

	// Convert to crypto package types
	var pubKey cryptodsa.DSAPublicKey
	copy(pubKey[:], pubKeyBytes)

	// Create signature from r,s components (40 bytes total)
	signature := make([]byte, 40)

	// Convert r to bytes (20 bytes)
	rBytes := r.Bytes()
	if len(rBytes) > 20 {
		copy(signature[:20], rBytes[len(rBytes)-20:])
	} else {
		copy(signature[20-len(rBytes):20], rBytes)
	}

	// Convert s to bytes (20 bytes)
	sBytes := s.Bytes()
	if len(sBytes) > 20 {
		copy(signature[20:40], sBytes[len(sBytes)-20:])
	} else {
		copy(signature[40-len(sBytes):40], sBytes)
	}

	return verifyDSASignature(pubKeyBytes, message, signature)
}

// SignatureVerifier is an interface for signature verification operations.
// Implementations can verify signatures using different cryptographic algorithms.
type SignatureVerifier interface {
	// Verify verifies a signature against a message
	Verify(message, signature []byte) error

	// AlgorithmType returns the signature algorithm type (DSA_SHA1, ED25519_SHA256, etc.)
	AlgorithmType() uint32
}

// DSAVerifier implements SignatureVerifier for DSA signatures
type DSAVerifier struct {
	pubKey cryptodsa.DSAPublicKey
}

// NewDSAVerifier creates a new DSA verifier from public key bytes
func NewDSAVerifier(pubKeyBytes []byte) (*DSAVerifier, error) {
	if len(pubKeyBytes) != 128 {
		return nil, fmt.Errorf("invalid DSA public key length: got %d, expected 128", len(pubKeyBytes))
	}

	var pubKey cryptodsa.DSAPublicKey
	copy(pubKey[:], pubKeyBytes)

	return &DSAVerifier{pubKey: pubKey}, nil
}

// Verify verifies a DSA signature
func (v *DSAVerifier) Verify(message, signature []byte) error {
	if !verifyDSASignature(v.pubKey[:], message, signature) {
		return fmt.Errorf("DSA signature verification failed")
	}
	return nil
}

// AlgorithmType returns DSA_SHA1
func (v *DSAVerifier) AlgorithmType() uint32 {
	return DSA_SHA1
}

// Ed25519Verifier implements SignatureVerifier for Ed25519 signatures
type Ed25519Verifier struct {
	pubKey cryptoed25519.Ed25519PublicKey
}

// NewEd25519Verifier creates a new Ed25519 verifier from public key bytes
func NewEd25519Verifier(pubKeyBytes []byte) (*Ed25519Verifier, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, expected %d",
			len(pubKeyBytes), ed25519.PublicKeySize)
	}

	pubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 public key: %w", err)
	}

	return &Ed25519Verifier{pubKey: pubKey}, nil
}

// Verify verifies an Ed25519 signature
func (v *Ed25519Verifier) Verify(message, signature []byte) error {
	if !verifyEd25519Signature(v.pubKey.Bytes(), message, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// AlgorithmType returns ED25519_SHA256
func (v *Ed25519Verifier) AlgorithmType() uint32 {
	return ED25519_SHA256
}
