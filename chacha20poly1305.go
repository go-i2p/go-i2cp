// Migration Notes (November 24, 2025):
// Migrated to use github.com/go-i2p/crypto/chacha20poly1305 package which provides
// standardized ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data).
//
// Key Changes:
// - ChaCha20Poly1305Cipher now wraps crypto/chacha20poly1305.AEAD
// - NewChaCha20Poly1305Cipher() delegates to chacha20poly1305.GenerateKey() and NewAEAD()
// - Encrypt/Decrypt maintain [nonce][ciphertext+tag] format for backward compatibility
// - Crypto package separates tag from ciphertext; wrapper combines them for I2CP compatibility
//
// The crypto package uses explicit tag separation (AEAD standard), while I2CP traditionally
// combines nonce+ciphertext+tag. The wrapper maintains I2CP format compatibility.

package go_i2cp

import (
	"fmt"

	cryptoaead "github.com/go-i2p/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Cipher provides authenticated encryption using ChaCha20-Poly1305
// Wraps github.com/go-i2p/crypto/chacha20poly1305.AEAD
type ChaCha20Poly1305Cipher struct {
	algorithmType uint32
	aead          *cryptoaead.AEAD
	key           [32]byte
}

// NewChaCha20Poly1305Cipher creates a new ChaCha20-Poly1305 cipher with a random key
// Delegates to github.com/go-i2p/crypto/chacha20poly1305.GenerateKey() and NewAEAD()
func NewChaCha20Poly1305Cipher() (*ChaCha20Poly1305Cipher, error) {
	// Generate random 256-bit key using crypto package
	key, err := cryptoaead.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ChaCha20-Poly1305 key: %w", err)
	}

	return NewChaCha20Poly1305CipherWithKey(key)
}

// NewChaCha20Poly1305CipherWithKey creates a new ChaCha20-Poly1305 cipher with the provided key
// Delegates to github.com/go-i2p/crypto/chacha20poly1305.NewAEAD()
func NewChaCha20Poly1305CipherWithKey(key [32]byte) (*ChaCha20Poly1305Cipher, error) {
	aead, err := cryptoaead.NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 AEAD: %w", err)
	}

	return &ChaCha20Poly1305Cipher{
		algorithmType: CHACHA20_POLY1305,
		aead:          aead,
		key:           key,
	}, nil
}

// ChaCha20Poly1305CipherFromStream reads a ChaCha20-Poly1305 cipher from a stream
func ChaCha20Poly1305CipherFromStream(stream *Stream) (*ChaCha20Poly1305Cipher, error) {
	var algorithmType uint32
	var err error

	algorithmType, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithm type: %w", err)
	}

	if algorithmType != CHACHA20_POLY1305 {
		return nil, fmt.Errorf("unsupported algorithm type: %d", algorithmType)
	}

	var key [32]byte
	_, err = stream.Read(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read ChaCha20-Poly1305 key: %w", err)
	}

	return NewChaCha20Poly1305CipherWithKey(key)
}

// Encrypt encrypts plaintext with optional associated data using ChaCha20-Poly1305
// Returns [nonce][ciphertext+tag] format for I2CP compatibility
// Uses github.com/go-i2p/crypto/chacha20poly1305.AEAD.Encrypt()
func (c *ChaCha20Poly1305Cipher) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if c.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	// Generate random nonce using crypto package
	nonce, err := cryptoaead.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext - crypto package returns separate ciphertext and tag
	ciphertext, tag, err := c.aead.Encrypt(plaintext, additionalData, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	// Combine nonce, ciphertext, and tag for I2CP compatibility
	// Format: [nonce][ciphertext][tag]
	result := make([]byte, len(nonce)+len(ciphertext)+len(tag))
	copy(result, nonce[:])
	copy(result[len(nonce):], ciphertext)
	copy(result[len(nonce)+len(ciphertext):], tag[:])

	return result, nil
}

// EncryptStream encrypts data from source stream and writes to destination stream
func (c *ChaCha20Poly1305Cipher) EncryptStream(src, dst *Stream, additionalData []byte) error {
	if src == nil || dst == nil {
		return fmt.Errorf("source and destination streams cannot be nil")
	}

	plaintext := src.Bytes()
	ciphertext, err := c.Encrypt(plaintext, additionalData)
	if err != nil {
		return fmt.Errorf("failed to encrypt stream: %w", err)
	}

	_, err = dst.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data to stream: %w", err)
	}

	return nil
}

// Decrypt decrypts ciphertext with optional associated data using ChaCha20-Poly1305
// Expects [nonce][ciphertext+tag] format for I2CP compatibility
// Uses github.com/go-i2p/crypto/chacha20poly1305.AEAD.Decrypt()
func (c *ChaCha20Poly1305Cipher) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	if c.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonceSize := cryptoaead.NonceSize
	tagSize := cryptoaead.TagSize
	minSize := nonceSize + tagSize

	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes (nonce + tag)", minSize)
	}

	// Extract nonce, ciphertext, and tag from combined format
	nonce := ciphertext[:nonceSize]
	actualCiphertextWithTag := ciphertext[nonceSize:]

	// Split ciphertext and tag
	actualCiphertext := actualCiphertextWithTag[:len(actualCiphertextWithTag)-tagSize]
	var tag [cryptoaead.TagSize]byte
	copy(tag[:], actualCiphertextWithTag[len(actualCiphertext):])

	// Decrypt using crypto package - pass tag separately
	plaintext, err := c.aead.Decrypt(actualCiphertext, tag[:], additionalData, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// DecryptStream decrypts data from source stream and writes to destination stream
func (c *ChaCha20Poly1305Cipher) DecryptStream(src, dst *Stream, additionalData []byte) error {
	if src == nil || dst == nil {
		return fmt.Errorf("source and destination streams cannot be nil")
	}

	ciphertext := src.Bytes()
	plaintext, err := c.Decrypt(ciphertext, additionalData)
	if err != nil {
		return fmt.Errorf("failed to decrypt stream: %w", err)
	}

	_, err = dst.Write(plaintext)
	if err != nil {
		return fmt.Errorf("failed to write decrypted data to stream: %w", err)
	}

	return nil
}

// WriteToStream writes the cipher key to a stream
func (c *ChaCha20Poly1305Cipher) WriteToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	// Write algorithm type
	err := stream.WriteUint32(c.algorithmType)
	if err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}

	// Write key
	_, err = stream.Write(c.key[:])
	if err != nil {
		return fmt.Errorf("failed to write ChaCha20-Poly1305 key: %w", err)
	}

	return nil
}

// Key returns a copy of the encryption key
func (c *ChaCha20Poly1305Cipher) Key() [32]byte {
	return c.key
}

// AlgorithmType returns the algorithm type constant
func (c *ChaCha20Poly1305Cipher) AlgorithmType() uint32 {
	return c.algorithmType
}

// NonceSize returns the nonce size used by the cipher
func (c *ChaCha20Poly1305Cipher) NonceSize() int {
	return cryptoaead.NonceSize
}

// Overhead returns the authentication tag overhead
func (c *ChaCha20Poly1305Cipher) Overhead() int {
	return cryptoaead.TagSize
}
