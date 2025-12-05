package go_i2cp

import (
	"testing"
)

// TestEd25519KeyPair_PrivateKey tests the Ed25519 PrivateKey getter
func TestEd25519KeyPair_PrivateKey(t *testing.T) {
	kp, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 keypair: %v", err)
	}

	privKey := kp.PrivateKey()
	if privKey == nil {
		t.Fatal("PrivateKey() returned nil")
	}

	// Ed25519 private keys are 64 bytes (32-byte seed + 32-byte public key)
	if len(privKey) != 64 {
		t.Errorf("PrivateKey() length = %d, want 64", len(privKey))
	}

	// Verify it's not all zeros
	allZero := true
	for _, b := range privKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("PrivateKey() returned all zeros")
	}

	// Verify consistency - should return the same key on multiple calls
	privKey2 := kp.PrivateKey()
	if len(privKey) != len(privKey2) {
		t.Error("PrivateKey() returned different lengths on subsequent calls")
	}
	for i := range privKey {
		if privKey[i] != privKey2[i] {
			t.Error("PrivateKey() returned different values on subsequent calls")
			break
		}
	}
}

// TestX25519KeyPair_PrivateKey tests the X25519 PrivateKey getter
func TestX25519KeyPair_PrivateKey(t *testing.T) {
	kp, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create X25519 keypair: %v", err)
	}

	privKey := kp.PrivateKey()

	// X25519 private keys are 32 bytes (returned as [32]byte array)
	if len(privKey) != 32 {
		t.Errorf("PrivateKey() length = %d, want 32", len(privKey))
	}

	// Verify it's not all zeros
	allZero := true
	for _, b := range privKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("PrivateKey() returned all zeros")
	}

	// Verify consistency - should return the same key on multiple calls
	privKey2 := kp.PrivateKey()
	if privKey != privKey2 {
		t.Error("PrivateKey() returned different values on subsequent calls")
	}
}

// TestEd25519KeyPair_AlgorithmType tests the Ed25519 AlgorithmType getter
func TestEd25519KeyPair_AlgorithmType(t *testing.T) {
	kp, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create Ed25519 keypair: %v", err)
	}

	algType := kp.AlgorithmType()

	// Ed25519 algorithm type constant (should be defined in constants.go)
	// Based on I2P specification, Ed25519-SHA512 is type 7
	expectedType := uint32(7) // KEYCERT_SIGN_ED25519

	if algType != expectedType {
		t.Errorf("AlgorithmType() = %d, want %d", algType, expectedType)
	}

	// Verify consistency
	if kp.AlgorithmType() != algType {
		t.Error("AlgorithmType() returned different values on subsequent calls")
	}
}

// TestX25519KeyPair_AlgorithmType tests the X25519 AlgorithmType getter
func TestX25519KeyPair_AlgorithmType(t *testing.T) {
	kp, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create X25519 keypair: %v", err)
	}

	algType := kp.AlgorithmType()

	// X25519 algorithm type constant
	// Based on actual implementation, X25519 is type 3
	expectedType := uint32(3) // KEYCERT_CRYPTO_X25519

	if algType != expectedType {
		t.Errorf("AlgorithmType() = %d, want %d", algType, expectedType)
	}

	// Verify consistency
	if kp.AlgorithmType() != algType {
		t.Error("AlgorithmType() returned different values on subsequent calls")
	}
}

// TestKeyPairTypes_Consistency tests that all key pair types return correct algorithm types
func TestKeyPairTypes_Consistency(t *testing.T) {
	// DEPRECATED: DSA keypair tests removed - modern I2CP uses Ed25519 only
	/*
		t.Run("DSA keypair type consistency", func(t *testing.T) {
			crypto := NewCrypto()
			sgk, err := crypto.SignatureKeygen(ED25519_SHA256)
			if err != nil {
				t.Fatalf("Failed to generate DSA keypair: %v", err)
			}

			// Verify the signature keypair was created
			if sgk.ed25519KeyPair == nil {
				t.Error("DSA public key not initialized")
			}
		})
	*/

	t.Run("Ed25519 keypair type consistency", func(t *testing.T) {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create Ed25519 keypair: %v", err)
		}

		// Verify public key exists
		pubKey := kp.PublicKey()
		if len(pubKey) != 32 {
			t.Errorf("Ed25519 public key length = %d, want 32", len(pubKey))
		}

		// Verify private key exists
		privKey := kp.PrivateKey()
		if len(privKey) != 64 {
			t.Errorf("Ed25519 private key length = %d, want 64", len(privKey))
		}
	})

	t.Run("X25519 keypair type consistency", func(t *testing.T) {
		kp, err := NewX25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create X25519 keypair: %v", err)
		}

		// Verify public key exists
		pubKey := kp.PublicKey()
		if len(pubKey) != 32 {
			t.Errorf("X25519 public key length = %d, want 32", len(pubKey))
		}

		// Verify private key exists
		privKey := kp.PrivateKey()
		if len(privKey) != 32 {
			t.Errorf("X25519 private key length = %d, want 32", len(privKey))
		}
	})
}
