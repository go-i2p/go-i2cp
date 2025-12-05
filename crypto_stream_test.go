package go_i2cp

import (
	"bytes"
	"testing"
)

// TestEd25519_StreamOperations tests stream-based Ed25519 operations
func TestEd25519_StreamOperations(t *testing.T) {
	t.Run("SignStream", func(t *testing.T) {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		message := []byte("test message for stream signing")
		stream := NewStream(message)

		// Test SignStream - this appends signature to the stream
		err = kp.SignStream(stream)
		if err != nil {
			t.Fatalf("SignStream failed: %v", err)
		}

		// Stream should now contain message + signature (64 bytes)
		streamBytes := stream.Bytes()
		if len(streamBytes) != len(message)+64 {
			t.Errorf("Stream length = %d, want %d (message + 64-byte signature)",
				len(streamBytes), len(message)+64)
		}

		// Verify the first part is still the original message
		if !bytes.Equal(streamBytes[:len(message)], message) {
			t.Error("Stream message portion was modified")
		}

		// Verify signature portion is non-zero (valid signature)
		signature := streamBytes[len(message):]
		allZeros := true
		for _, b := range signature {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("SignStream produced all-zero signature")
		}
	})

	t.Run("SignStream with nil stream", func(t *testing.T) {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		err = kp.SignStream(nil)
		if err == nil {
			t.Error("SignStream with nil stream should return error")
		}
	})

	t.Run("WritePublicKeyToStream", func(t *testing.T) {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		stream := NewStream(make([]byte, 0, 32))
		err = kp.WritePublicKeyToStream(stream)
		if err != nil {
			t.Fatalf("WritePublicKeyToStream failed: %v", err)
		}

		// Ed25519 public keys are 32 bytes
		if len(stream.Bytes()) != 32 {
			t.Errorf("Public key stream length = %d, want 32", len(stream.Bytes()))
		}

		// Verify it matches the public key from PublicKey()
		pubKey := kp.PublicKey()
		if !bytes.Equal(stream.Bytes(), pubKey) {
			t.Error("WritePublicKeyToStream produced different key than PublicKey()")
		}
	})

	t.Run("Ed25519PublicKeyFromStream", func(t *testing.T) {
		kp, err := NewEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		// Write public key to stream
		writeStream := NewStream(make([]byte, 0, 32))
		err = kp.WritePublicKeyToStream(writeStream)
		if err != nil {
			t.Fatalf("WritePublicKeyToStream failed: %v", err)
		}

		// Read it back
		readStream := NewStream(writeStream.Bytes())
		pubKey, err := Ed25519PublicKeyFromStream(readStream)
		if err != nil {
			t.Fatalf("Ed25519PublicKeyFromStream failed: %v", err)
		}

		// Verify it matches
		if !bytes.Equal(pubKey, kp.PublicKey()) {
			t.Error("Ed25519PublicKeyFromStream produced different key")
		}
	})
}

// TestX25519_StreamOperations tests stream-based X25519 operations
func TestX25519_StreamOperations(t *testing.T) {
	t.Run("WritePublicKeyToStream", func(t *testing.T) {
		kp, err := NewX25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		stream := NewStream(make([]byte, 0, 32))
		err = kp.WritePublicKeyToStream(stream)
		if err != nil {
			t.Fatalf("WritePublicKeyToStream failed: %v", err)
		}

		// X25519 public keys are 32 bytes
		if len(stream.Bytes()) != 32 {
			t.Errorf("Public key stream length = %d, want 32", len(stream.Bytes()))
		}

		// Verify it matches the public key from PublicKey()
		pubKey := kp.PublicKey()
		if !bytes.Equal(stream.Bytes(), pubKey[:]) {
			t.Error("WritePublicKeyToStream produced different key than PublicKey()")
		}
	})

	t.Run("X25519PublicKeyFromStream", func(t *testing.T) {
		kp1, err := NewX25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to create keypair: %v", err)
		}

		// Write public key
		stream := NewStream(make([]byte, 0, 32))
		err = kp1.WritePublicKeyToStream(stream)
		if err != nil {
			t.Fatalf("WritePublicKeyToStream failed: %v", err)
		}

		// Read it back
		readStream := NewStream(stream.Bytes())
		pubKey, err := X25519PublicKeyFromStream(readStream)
		if err != nil {
			t.Fatalf("X25519PublicKeyFromStream failed: %v", err)
		}

		// Verify the read public key is valid (32 bytes)
		if len(pubKey) != 32 {
			t.Errorf("Read public key length = %d, want 32", len(pubKey))
		}

		// Verify it matches the original
		originalPubKey := kp1.PublicKey()
		if pubKey != originalPubKey {
			t.Error("X25519PublicKeyFromStream produced different key")
		}
	})
}

// TestDSA_StreamOperations - DEPRECATED AND REMOVED
// DSA support has been removed from go-i2cp in favor of Ed25519.
// This test is retained only as a deprecation marker.
// Use TestEd25519_StreamOperations for modern cryptography testing.
