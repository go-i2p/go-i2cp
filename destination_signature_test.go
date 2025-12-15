package go_i2cp

import (
	"testing"
)

// TestDestination_SigningPublicKey tests extracting the signing public key from a destination
func TestDestination_SigningPublicKey(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Get the signing public key
	pubKey := dest.SigningPublicKey()
	if pubKey == nil {
		t.Fatal("SigningPublicKey returned nil")
	}

	// Verify it's a valid Ed25519 key
	if pubKey.AlgorithmType() != ED25519_SHA256 {
		t.Errorf("Expected algorithm type %d, got %d", ED25519_SHA256, pubKey.AlgorithmType())
	}

	// Verify public key is not nil
	if len(pubKey.PublicKey()) != 32 {
		t.Errorf("Expected 32-byte Ed25519 public key, got %d bytes", len(pubKey.PublicKey()))
	}

	// Verify it's a verification-only key (no private key)
	if len(pubKey.PrivateKey()) != 0 {
		t.Error("SigningPublicKey should not contain private key for security")
	}

	t.Log("✓ Successfully extracted signing public key")
	t.Logf("  Public key: %d bytes", len(pubKey.PublicKey()))
	t.Logf("  Algorithm: Ed25519-SHA512")
}

// TestDestination_VerifySignature tests offline signature verification using destination
func TestDestination_VerifySignature(t *testing.T) {
	crypto := NewCrypto()

	// Create a destination (simulating remote peer)
	remotePeer, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create remote peer destination: %v", err)
	}

	// Test message
	message := []byte("I2P Streaming Protocol packet data")

	t.Run("valid signature", func(t *testing.T) {
		// Sign the message using the destination's private key
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Verify the signature using only the public key (offline verification)
		isValid := remotePeer.VerifySignature(message, signature)
		if !isValid {
			t.Error("Valid signature was rejected")
		}

		t.Log("✓ Valid signature correctly verified")
	})

	t.Run("invalid signature", func(t *testing.T) {
		// Create an invalid signature
		invalidSignature := make([]byte, 64)
		for i := range invalidSignature {
			invalidSignature[i] = 0xFF
		}

		isValid := remotePeer.VerifySignature(message, invalidSignature)
		if isValid {
			t.Error("Invalid signature was accepted")
		}

		t.Log("✓ Invalid signature correctly rejected")
	})

	t.Run("corrupted signature", func(t *testing.T) {
		// Sign the message
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Corrupt the signature
		corruptedSignature := make([]byte, len(signature))
		copy(corruptedSignature, signature)
		corruptedSignature[0] ^= 0xFF

		isValid := remotePeer.VerifySignature(message, corruptedSignature)
		if isValid {
			t.Error("Corrupted signature was accepted")
		}

		t.Log("✓ Corrupted signature correctly rejected")
	})

	t.Run("wrong message", func(t *testing.T) {
		// Sign the original message
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Try to verify with different message
		differentMessage := []byte("Different message")
		isValid := remotePeer.VerifySignature(differentMessage, signature)
		if isValid {
			t.Error("Signature validated against wrong message")
		}

		t.Log("✓ Signature correctly rejected for wrong message")
	})
}

// TestDestination_VerifySignature_UseCases tests real-world use cases
func TestDestination_VerifySignature_UseCases(t *testing.T) {
	crypto := NewCrypto()

	// Simulate a server receiving a packet from a client
	t.Run("streaming protocol server mode", func(t *testing.T) {
		// Create client destination (simulating remote peer)
		clientDest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create client destination: %v", err)
		}

		// Simulate a streaming protocol SYN packet
		synPacket := []byte{
			0x01,                   // Protocol version
			0x06,                   // Flags: SYN | SignatureIncluded | FromIncluded
			0x00, 0x01, 0x23, 0x45, // Send stream ID
			0x00, 0x00, 0x00, 0x00, // Receive stream ID
			0x00, 0x00, 0x04, 0x00, // Sequence number
			0x00, 0x00, 0x04, 0x00, // Ack through
		}

		// Client signs the packet
		clientKey, err := clientDest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get client signing key: %v", err)
		}

		signature, err := clientKey.Sign(synPacket)
		if err != nil {
			t.Fatalf("Failed to sign SYN packet: %v", err)
		}

		// === SERVER SIDE ===
		// Server receives message via OnMessage callback with srcDest
		// Simulating: func handleIncomingMessage(session *Session, srcDest *Destination, ...)

		// Server verifies the signature using source destination
		isValid := clientDest.VerifySignature(synPacket, signature)
		if !isValid {
			t.Error("Server failed to verify client signature")
		}

		t.Log("✓ Server successfully verified client's SYN packet signature")
		t.Logf("  Client: %s", clientDest.Base32()[:52]+"...")
		t.Logf("  Packet: %d bytes", len(synPacket))
		t.Logf("  Signature: %d bytes", len(signature))
	})

	t.Run("connection tracking with signature verification", func(t *testing.T) {
		// Simulate multiple clients
		clients := make([]*Destination, 3)
		for i := range clients {
			dest, err := NewDestination(crypto)
			if err != nil {
				t.Fatalf("Failed to create client %d: %v", i, err)
			}
			clients[i] = dest
		}

		// Each client sends a signed message
		message := []byte("Hello from client")

		for i, client := range clients {
			// Sign message
			key, err := client.SigningKeyPair()
			if err != nil {
				t.Fatalf("Failed to get signing key for client %d: %v", i, err)
			}

			signature, err := key.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign message for client %d: %v", i, err)
			}

			// Verify signature
			if !client.VerifySignature(message, signature) {
				t.Errorf("Failed to verify signature for client %d", i)
			}

			// In real usage, would track connection: connections[client.Base32()] = conn
			t.Logf("✓ Client %d: %s", i, client.Base32()[:52]+"...")
		}

		t.Log("✓ Successfully verified signatures from multiple clients")
	})
}

// TestDestination_SigningPublicKey_NoPrivateKey ensures public key doesn't leak private key
func TestDestination_SigningPublicKey_NoPrivateKey(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Get the signing public key
	pubKey := dest.SigningPublicKey()
	if pubKey == nil {
		t.Fatal("SigningPublicKey returned nil")
	}

	// Verify it has no private key material
	if len(pubKey.PrivateKey()) > 0 {
		t.Error("SigningPublicKey leaked private key material")
		t.Errorf("Private key bytes: %d (expected: 0)", len(pubKey.PrivateKey()))
	}

	// Verify it can still verify signatures
	signingKey, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	message := []byte("test message")
	signature, err := signingKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Public key should still be able to verify
	isValid := pubKey.Verify(message, signature)
	if !isValid {
		t.Error("Public-only key failed to verify valid signature")
	}

	t.Log("✓ SigningPublicKey properly isolates public key")
	t.Log("✓ No private key material exposed")
	t.Log("✓ Verification still works correctly")
}

// TestDestination_VerifySignature_EdgeCases tests edge cases and error conditions
func TestDestination_VerifySignature_EdgeCases(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	t.Run("empty message", func(t *testing.T) {
		signingKey, err := dest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key: %v", err)
		}

		emptyMessage := []byte{}
		signature, err := signingKey.Sign(emptyMessage)
		if err != nil {
			t.Fatalf("Failed to sign empty message: %v", err)
		}

		isValid := dest.VerifySignature(emptyMessage, signature)
		if !isValid {
			t.Error("Failed to verify signature for empty message")
		}

		t.Log("✓ Empty message signature verified")
	})

	t.Run("nil signature", func(t *testing.T) {
		message := []byte("test")
		isValid := dest.VerifySignature(message, nil)
		if isValid {
			t.Error("Nil signature was accepted")
		}

		t.Log("✓ Nil signature correctly rejected")
	})

	t.Run("wrong length signature", func(t *testing.T) {
		message := []byte("test")
		shortSignature := make([]byte, 32) // Ed25519 signatures are 64 bytes

		isValid := dest.VerifySignature(message, shortSignature)
		if isValid {
			t.Error("Wrong-length signature was accepted")
		}

		t.Log("✓ Wrong-length signature correctly rejected")
	})

	t.Run("large message", func(t *testing.T) {
		// Test with 64KB message (I2CP max payload)
		largeMessage := make([]byte, 65536)
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}

		signingKey, err := dest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key: %v", err)
		}

		signature, err := signingKey.Sign(largeMessage)
		if err != nil {
			t.Fatalf("Failed to sign large message: %v", err)
		}

		isValid := dest.VerifySignature(largeMessage, signature)
		if !isValid {
			t.Error("Failed to verify signature for large message")
		}

		t.Logf("✓ Large message signature verified (%d bytes)", len(largeMessage))
	})
}
