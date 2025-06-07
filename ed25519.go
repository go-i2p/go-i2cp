package go_i2cp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// Ed25519KeyPair represents an Ed25519 signature key pair for modern I2P cryptography
type Ed25519KeyPair struct {
	algorithmType uint32
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
}

// NewEd25519KeyPair generates a new Ed25519 key pair
func NewEd25519KeyPair() (*Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
	}

	return &Ed25519KeyPair{
		algorithmType: ED25519_SHA256,
		privateKey:    privateKey,
		publicKey:     publicKey,
	}, nil
}

// Ed25519KeyPairFromStream reads an Ed25519 key pair from a stream
func Ed25519KeyPairFromStream(stream *Stream) (*Ed25519KeyPair, error) {
	var algorithmType uint32
	var err error

	algorithmType, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithm type: %w", err)
	}

	if algorithmType != ED25519_SHA256 {
		return nil, fmt.Errorf("unsupported algorithm type: %d", algorithmType)
	}

	// Read private key (64 bytes for Ed25519)
	privateKeyBytes := make([]byte, ed25519.PrivateKeySize)
	_, err = stream.Read(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Read public key (32 bytes for Ed25519)
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	_, err = stream.Read(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return &Ed25519KeyPair{
		algorithmType: algorithmType,
		privateKey:    ed25519.PrivateKey(privateKeyBytes),
		publicKey:     ed25519.PublicKey(publicKeyBytes),
	}, nil
}

// Ed25519PublicKeyFromStream reads only the public key from a stream
func Ed25519PublicKeyFromStream(stream *Stream) (ed25519.PublicKey, error) {
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	_, err := stream.Read(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ed25519 public key: %w", err)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

// Sign creates a signature for the given message using Ed25519
func (kp *Ed25519KeyPair) Sign(message []byte) ([]byte, error) {
	if kp.privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Ed25519 signs the message directly, but for I2CP compatibility we hash it first
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	signature := ed25519.Sign(kp.privateKey, messageHash)
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

// Verify verifies a signature against the given message using Ed25519
func (kp *Ed25519KeyPair) Verify(message, signature []byte) bool {
	if kp.publicKey == nil {
		return false
	}

	// Hash the message for I2CP compatibility
	hasher := sha256.New()
	hasher.Write(message)
	messageHash := hasher.Sum(nil)

	return ed25519.Verify(kp.publicKey, messageHash, signature)
}

// VerifyStream verifies a signature embedded in the stream data
func (kp *Ed25519KeyPair) VerifyStream(stream *Stream) (bool, error) {
	if stream == nil {
		return false, fmt.Errorf("stream cannot be nil")
	}

	if stream.Len() < ed25519.SignatureSize {
		return false, fmt.Errorf("stream too short for Ed25519 signature")
	}

	// Extract message and signature
	data := stream.Bytes()
	messageLen := len(data) - ed25519.SignatureSize
	message := data[:messageLen]
	signature := data[messageLen:]

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

// WritePublicKeyToStream writes only the public key to a stream
func (kp *Ed25519KeyPair) WritePublicKeyToStream(stream *Stream) error {
	if stream == nil {
		return fmt.Errorf("stream cannot be nil")
	}

	_, err := stream.Write(kp.publicKey)
	if err != nil {
		return fmt.Errorf("failed to write Ed25519 public key: %w", err)
	}

	return nil
}

// PublicKey returns the public key
func (kp *Ed25519KeyPair) PublicKey() ed25519.PublicKey {
	return kp.publicKey
}

// PrivateKey returns the private key
func (kp *Ed25519KeyPair) PrivateKey() ed25519.PrivateKey {
	return kp.privateKey
}

// AlgorithmType returns the algorithm type constant
func (kp *Ed25519KeyPair) AlgorithmType() uint32 {
	return kp.algorithmType
}
