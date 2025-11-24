package go_i2cp

import (
	"fmt"

	cryptodsa "github.com/go-i2p/crypto/dsa"
)

// DSAKeyPair represents a DSA signature key pair using the crypto package
type DSAKeyPair struct {
	privKey cryptodsa.DSAPrivateKey
	pubKey  cryptodsa.DSAPublicKey
}

// NewDSAKeyPair generates a new DSA key pair using the crypto package
func NewDSAKeyPair() (*DSAKeyPair, error) {
	var privKey cryptodsa.DSAPrivateKey
	generatedKey, err := privKey.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DSA key pair: %w", err)
	}

	privKey = generatedKey.(cryptodsa.DSAPrivateKey)

	pubKeyInterface, err := privKey.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	pubKey := pubKeyInterface.(cryptodsa.DSAPublicKey)

	return &DSAKeyPair{
		privKey: privKey,
		pubKey:  pubKey,
	}, nil
}

// AlgorithmType returns DSA_SHA1 algorithm type
func (kp *DSAKeyPair) AlgorithmType() uint32 {
	return DSA_SHA1
}

// Sign creates a DSA signature for the given data
func (kp *DSAKeyPair) Sign(data []byte) ([]byte, error) {
	signer, err := kp.privKey.NewSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	signature, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signature, nil
}

// Verify verifies a DSA signature against the given data
func (kp *DSAKeyPair) Verify(data, signature []byte) bool {
	verifier, err := kp.pubKey.NewVerifier()
	if err != nil {
		return false
	}

	err = verifier.Verify(data, signature)
	if err != nil {
		return false
	}

	return true
}

// PrivateKey returns the private key bytes
func (kp *DSAKeyPair) PrivateKey() []byte {
	return kp.privKey.Bytes()
}

// PublicKey returns the public key bytes
func (kp *DSAKeyPair) PublicKey() []byte {
	return kp.pubKey.Bytes()
}

// WriteToStream writes the DSA key pair to a stream in I2CP format
func (kp *DSAKeyPair) WriteToStream(stream *Stream) error {
	// Write algorithm type
	err := stream.WriteUint32(DSA_SHA1)
	if err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}

	// Write private key (20 bytes)
	privKeyBytes := kp.privKey.Bytes()
	if len(privKeyBytes) != 20 {
		return fmt.Errorf("invalid DSA private key length: %d (expected 20)", len(privKeyBytes))
	}
	_, err = stream.Write(privKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key (128 bytes)
	pubKeyBytes := kp.pubKey.Bytes()
	if len(pubKeyBytes) != 128 {
		return fmt.Errorf("invalid DSA public key length: %d (expected 128)", len(pubKeyBytes))
	}
	_, err = stream.Write(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// DSAKeyPairFromStream reads a DSA key pair from a stream
func DSAKeyPairFromStream(stream *Stream) (*DSAKeyPair, error) {
	// Read private key (20 bytes)
	privKeyBytes := make([]byte, 20)
	_, err := stream.Read(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Read public key (128 bytes)
	pubKeyBytes := make([]byte, 128)
	_, err = stream.Read(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Convert to crypto package types
	var privKey cryptodsa.DSAPrivateKey
	copy(privKey[:], privKeyBytes)

	var pubKey cryptodsa.DSAPublicKey
	copy(pubKey[:], pubKeyBytes)

	return &DSAKeyPair{
		privKey: privKey,
		pubKey:  pubKey,
	}, nil
}
