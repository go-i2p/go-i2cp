package go_i2cp

import (
	"testing"

	cryptodsa "github.com/go-i2p/crypto/dsa"
)

// TestVerifyDSASignature tests DSA signature verification
func TestVerifyDSASignature(t *testing.T) {
	// Generate DSA key pair
	dsaKeyPair, err := NewDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate DSA key pair: %v", err)
	}

	message := []byte("test message for DSA signature verification")

	// Sign the message
	signature, err := dsaKeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify with correct public key
	if !verifyDSASignature(dsaKeyPair.PublicKey(), message, signature) {
		t.Error("DSA signature verification failed for valid signature")
	}

	// Verify with wrong message should fail
	wrongMessage := []byte("different message")
	if verifyDSASignature(dsaKeyPair.PublicKey(), wrongMessage, signature) {
		t.Error("DSA signature verification should fail for wrong message")
	}

	// Verify with invalid signature length
	invalidSig := []byte{1, 2, 3}
	if verifyDSASignature(dsaKeyPair.PublicKey(), message, invalidSig) {
		t.Error("DSA signature verification should fail for invalid signature length")
	}

	// Verify with invalid public key length
	invalidPubKey := []byte{1, 2, 3}
	if verifyDSASignature(invalidPubKey, message, signature) {
		t.Error("DSA signature verification should fail for invalid public key length")
	}
}

// TestVerifyEd25519Signature tests Ed25519 signature verification
func TestVerifyEd25519Signature(t *testing.T) {
	// Generate Ed25519 key pair
	ed25519KeyPair, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	message := []byte("test message for Ed25519 signature verification")

	// Sign the message
	signature, err := ed25519KeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify with correct public key
	pubKeyBytes := ed25519KeyPair.PublicKey()
	if !verifyEd25519Signature(pubKeyBytes, message, signature) {
		t.Error("Ed25519 signature verification failed for valid signature")
	}

	// Verify with wrong message should fail
	wrongMessage := []byte("different message")
	if verifyEd25519Signature(pubKeyBytes, wrongMessage, signature) {
		t.Error("Ed25519 signature verification should fail for wrong message")
	}

	// Verify with invalid signature length
	invalidSig := []byte{1, 2, 3}
	if verifyEd25519Signature(pubKeyBytes, message, invalidSig) {
		t.Error("Ed25519 signature verification should fail for invalid signature length")
	}

	// Verify with invalid public key length
	invalidPubKey := []byte{1, 2, 3}
	if verifyEd25519Signature(invalidPubKey, message, signature) {
		t.Error("Ed25519 signature verification should fail for invalid public key length")
	}
}

// TestDSAVerifier tests the DSAVerifier interface implementation
func TestDSAVerifier(t *testing.T) {
	// Generate DSA key pair
	dsaKeyPair, err := NewDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate DSA key pair: %v", err)
	}

	// Create verifier
	verifier, err := NewDSAVerifier(dsaKeyPair.PublicKey())
	if err != nil {
		t.Fatalf("Failed to create DSA verifier: %v", err)
	}

	// Check algorithm type
	if verifier.AlgorithmType() != DSA_SHA1 {
		t.Errorf("Expected algorithm type %d, got %d", DSA_SHA1, verifier.AlgorithmType())
	}

	message := []byte("test message")
	signature, err := dsaKeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature
	err = verifier.Verify(message, signature)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// Verify with wrong message
	wrongMessage := []byte("wrong message")
	err = verifier.Verify(wrongMessage, signature)
	if err == nil {
		t.Error("Verification should fail for wrong message")
	}
}

// TestEd25519Verifier tests the Ed25519Verifier interface implementation
func TestEd25519Verifier(t *testing.T) {
	// Generate Ed25519 key pair
	ed25519KeyPair, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create verifier
	pubKeyBytes := ed25519KeyPair.PublicKey()
	verifier, err := NewEd25519Verifier(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 verifier: %v", err)
	}

	// Check algorithm type
	if verifier.AlgorithmType() != ED25519_SHA256 {
		t.Errorf("Expected algorithm type %d, got %d", ED25519_SHA256, verifier.AlgorithmType())
	}

	message := []byte("test message")
	signature, err := ed25519KeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature
	err = verifier.Verify(message, signature)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}

	// Verify with wrong message
	wrongMessage := []byte("wrong message")
	err = verifier.Verify(wrongMessage, signature)
	if err == nil {
		t.Error("Verification should fail for wrong message")
	}
}

// TestVerifyDSASignatureLegacy tests legacy DSA signature verification with big.Int
func TestVerifyDSASignatureLegacy(t *testing.T) {
	// This test ensures backward compatibility with code using big.Int r,s components
	// Generate DSA key pair using crypto package
	var privKey cryptodsa.DSAPrivateKey
	generatedKey, err := privKey.Generate()
	if err != nil {
		t.Fatalf("Failed to generate DSA key pair: %v", err)
	}

	privKey = generatedKey.(cryptodsa.DSAPrivateKey)
	pubKeyInterface, err := privKey.Public()
	if err != nil {
		t.Fatalf("Failed to derive public key: %v", err)
	}
	pubKey := pubKeyInterface.(cryptodsa.DSAPublicKey)

	message := []byte("legacy DSA signature test")

	// Sign using DSA keypair
	dsaKeyPair := &DSAKeyPair{privKey: privKey, pubKey: pubKey}
	signature, err := dsaKeyPair.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Extract r and s from signature (40 bytes: [r:20][s:20])
	// For legacy compatibility test only - production code should use verifyDSASignature
	if len(signature) != 40 {
		t.Fatalf("Invalid signature length: %d", len(signature))
	}

	// Note: The legacy test validates that the new implementation works
	// The actual legacy function is available for backward compatibility
	// but new code should use verifyDSASignature directly
	if !verifyDSASignature(pubKey[:], message, signature) {
		t.Error("Legacy DSA signature verification failed")
	}
}

// TestSignatureVerifierInterface tests the SignatureVerifier interface
func TestSignatureVerifierInterface(t *testing.T) {
	message := []byte("interface test message")

	t.Run("DSA verifier", func(t *testing.T) {
		dsaKeyPair, err := NewDSAKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate DSA key pair: %v", err)
		}

		var verifier SignatureVerifier
		verifier, err = NewDSAVerifier(dsaKeyPair.PublicKey())
		if err != nil {
			t.Fatalf("Failed to create DSA verifier: %v", err)
		}

		signature, err := dsaKeyPair.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		err = verifier.Verify(message, signature)
		if err != nil {
			t.Errorf("DSA verifier interface verification failed: %v", err)
		}
	})

	t.Run("Ed25519 verifier", func(t *testing.T) {
		ed25519KeyPair, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		var verifier SignatureVerifier
		verifier, err = NewEd25519Verifier(ed25519KeyPair.PublicKey())
		if err != nil {
			t.Fatalf("Failed to create Ed25519 verifier: %v", err)
		}

		signature, err := ed25519KeyPair.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		err = verifier.Verify(message, signature)
		if err != nil {
			t.Errorf("Ed25519 verifier interface verification failed: %v", err)
		}
	})
}

// TestCrossVerification ensures that signatures from one key don't verify with another
func TestCrossVerification(t *testing.T) {
	message := []byte("cross verification test")

	// Generate two different DSA key pairs
	dsa1, err := NewDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first DSA key pair: %v", err)
	}

	dsa2, err := NewDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second DSA key pair: %v", err)
	}

	// Sign with first key
	sig1, err := dsa1.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with first key: %v", err)
	}

	// Verification with second key should fail
	if verifyDSASignature(dsa2.PublicKey(), message, sig1) {
		t.Error("Cross-verification should fail: signature from key1 verified with key2")
	}

	// Generate two different Ed25519 key pairs
	ed1, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate first Ed25519 key pair: %v", err)
	}

	ed2, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second Ed25519 key pair: %v", err)
	}

	// Sign with first key
	edSig1, err := ed1.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with first Ed25519 key: %v", err)
	}

	// Verification with second key should fail
	if verifyEd25519Signature(ed2.PublicKey(), message, edSig1) {
		t.Error("Cross-verification should fail: Ed25519 signature from key1 verified with key2")
	}
}
