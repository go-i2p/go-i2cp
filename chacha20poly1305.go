package go_i2cp

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Cipher provides authenticated encryption using ChaCha20-Poly1305
type ChaCha20Poly1305Cipher struct {
	algorithmType uint32
	aead          cipher.AEAD
	key           [32]byte
}

// NewChaCha20Poly1305Cipher creates a new ChaCha20-Poly1305 cipher with a random key
func NewChaCha20Poly1305Cipher() (*ChaCha20Poly1305Cipher, error) {
	var key [32]byte

	// Generate random 256-bit key
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate ChaCha20-Poly1305 key: %w", err)
	}

	return NewChaCha20Poly1305CipherWithKey(key)
}

// NewChaCha20Poly1305CipherWithKey creates a new ChaCha20-Poly1305 cipher with the provided key
func NewChaCha20Poly1305CipherWithKey(key [32]byte) (*ChaCha20Poly1305Cipher, error) {
	aead, err := chacha20poly1305.New(key[:])
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
func (c *ChaCha20Poly1305Cipher) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if c.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	// Generate random nonce
	nonce := make([]byte, c.aead.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext := c.aead.Seal(nil, nonce, plaintext, additionalData)

	// Prepend nonce to ciphertext for transmission
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

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
func (c *ChaCha20Poly1305Cipher) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	if c.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes for nonce", nonceSize)
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// Decrypt ciphertext
	plaintext, err := c.aead.Open(nil, nonce, actualCiphertext, additionalData)
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
	if c.aead == nil {
		return chacha20poly1305.NonceSize // Return standard size even if not initialized
	}
	return c.aead.NonceSize()
}

// Overhead returns the authentication tag overhead
func (c *ChaCha20Poly1305Cipher) Overhead() int {
	if c.aead == nil {
		return chacha20poly1305.Overhead // Return standard overhead even if not initialized
	}
	return c.aead.Overhead()
}
