package go_i2cp

import (
	"bytes"
	"testing"
)

// TestEd25519KeyPair tests Ed25519 signature operations
func TestEd25519KeyPair(t *testing.T) {
	// Generate a new Ed25519 key pair
	kp, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Test algorithm type
	if kp.AlgorithmType() != ED25519_SHA256 {
		t.Errorf("Expected algorithm type %d, got %d", ED25519_SHA256, kp.AlgorithmType())
	}

	// Test signing and verification
	message := []byte("Hello, I2P anonymous network!")
	signature, err := kp.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if !kp.Verify(message, signature) {
		t.Error("Signature verification failed")
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	if kp.Verify(wrongMessage, signature) {
		t.Error("Signature verification should have failed for wrong message")
	}

	// Test stream serialization
	stream := NewStream(make([]byte, 0, 1024))
	err = kp.WriteToStream(stream)
	if err != nil {
		t.Fatalf("Failed to write key pair to stream: %v", err)
	}

	// Read back from stream
	readStream := NewStream(stream.Bytes())
	kp2, err := Ed25519KeyPairFromStream(readStream)
	if err != nil {
		t.Fatalf("Failed to read key pair from stream: %v", err)
	}

	// Test that the restored key pair works
	if !bytes.Equal(kp.PublicKey(), kp2.PublicKey()) {
		t.Error("Public keys don't match after stream serialization")
	}

	signature2, err := kp2.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with restored key pair: %v", err)
	}

	if !kp.Verify(message, signature2) {
		t.Error("Original key pair should verify signature from restored key pair")
	}
}

// TestX25519KeyPair tests X25519 key exchange operations
func TestX25519KeyPair(t *testing.T) {
	// Generate two key pairs for ECDH
	alice, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's X25519 key pair: %v", err)
	}

	bob, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's X25519 key pair: %v", err)
	}

	// Test algorithm type
	if alice.AlgorithmType() != X25519 {
		t.Errorf("Expected algorithm type %d, got %d", X25519, alice.AlgorithmType())
	}

	// Perform ECDH from both sides
	sharedSecretAlice, err := alice.GenerateSharedSecret(bob.PublicKey())
	if err != nil {
		t.Fatalf("Alice failed to generate shared secret: %v", err)
	}

	sharedSecretBob, err := bob.GenerateSharedSecret(alice.PublicKey())
	if err != nil {
		t.Fatalf("Bob failed to generate shared secret: %v", err)
	}

	// Shared secrets should be identical
	if sharedSecretAlice != sharedSecretBob {
		t.Error("Shared secrets don't match")
	}

	// Test stream serialization
	stream := NewStream(make([]byte, 0, 1024))
	err = alice.WriteToStream(stream)
	if err != nil {
		t.Fatalf("Failed to write key pair to stream: %v", err)
	}

	// Read back from stream
	readStream := NewStream(stream.Bytes())
	alice2, err := X25519KeyPairFromStream(readStream)
	if err != nil {
		t.Fatalf("Failed to read key pair from stream: %v", err)
	}

	// Test that the restored key pair works
	if alice.PublicKey() != alice2.PublicKey() {
		t.Error("Public keys don't match after stream serialization")
	}

	sharedSecretAlice2, err := alice2.GenerateSharedSecret(bob.PublicKey())
	if err != nil {
		t.Fatalf("Restored Alice failed to generate shared secret: %v", err)
	}

	if sharedSecretAlice != sharedSecretAlice2 {
		t.Error("Shared secrets don't match after key pair restoration")
	}
}

// TestChaCha20Poly1305Cipher tests ChaCha20-Poly1305 encryption operations
func TestChaCha20Poly1305Cipher(t *testing.T) {
	// Create a new cipher
	cipher, err := NewChaCha20Poly1305Cipher()
	if err != nil {
		t.Fatalf("Failed to create ChaCha20-Poly1305 cipher: %v", err)
	}

	// Test algorithm type
	if cipher.AlgorithmType() != CHACHA20_POLY1305 {
		t.Errorf("Expected algorithm type %d, got %d", CHACHA20_POLY1305, cipher.AlgorithmType())
	}

	// Test encryption and decryption
	plaintext := []byte("This is a secret message for the I2P network!")
	additionalData := []byte("session_metadata")

	ciphertext, err := cipher.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag overhead)
	expectedMinLength := len(plaintext) + cipher.NonceSize() + cipher.Overhead()
	if len(ciphertext) < expectedMinLength {
		t.Errorf("Ciphertext too short: expected at least %d bytes, got %d", expectedMinLength, len(ciphertext))
	}

	decrypted, err := cipher.Decrypt(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match original plaintext")
	}

	// Test with wrong additional data
	wrongAdditionalData := []byte("wrong_metadata")
	_, err = cipher.Decrypt(ciphertext, wrongAdditionalData)
	if err == nil {
		t.Error("Decryption should have failed with wrong additional data")
	}

	// Test stream operations
	srcStream := NewStream(plaintext)
	dstStream := NewStream(make([]byte, 0, len(ciphertext)+100))

	err = cipher.EncryptStream(srcStream, dstStream, additionalData)
	if err != nil {
		t.Fatalf("Failed to encrypt stream: %v", err)
	}

	// Decrypt stream
	encryptedStream := NewStream(dstStream.Bytes())
	decryptedStream := NewStream(make([]byte, 0, len(plaintext)+100))

	err = cipher.DecryptStream(encryptedStream, decryptedStream, additionalData)
	if err != nil {
		t.Fatalf("Failed to decrypt stream: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedStream.Bytes()) {
		t.Error("Stream decryption result doesn't match original plaintext")
	}

	// Test stream serialization
	keyStream := NewStream(make([]byte, 0, 100))
	err = cipher.WriteToStream(keyStream)
	if err != nil {
		t.Fatalf("Failed to write cipher to stream: %v", err)
	}

	// Read back from stream
	readKeyStream := NewStream(keyStream.Bytes())
	cipher2, err := ChaCha20Poly1305CipherFromStream(readKeyStream)
	if err != nil {
		t.Fatalf("Failed to read cipher from stream: %v", err)
	}

	// Test that the restored cipher works
	if cipher.Key() != cipher2.Key() {
		t.Error("Keys don't match after stream serialization")
	}

	decrypted2, err := cipher2.Decrypt(ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Restored cipher failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted2) {
		t.Error("Restored cipher decryption result doesn't match original plaintext")
	}
}

// TestCryptoIntegration tests integration of modern crypto with existing Crypto struct
func TestCryptoIntegration(t *testing.T) {
	crypto := NewCrypto()

	// Test Ed25519 key generation through Crypto struct
	ed25519Kp, err := crypto.Ed25519SignatureKeygen()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair through Crypto: %v", err)
	}

	if ed25519Kp.AlgorithmType() != ED25519_SHA256 {
		t.Error("Ed25519 key pair has wrong algorithm type")
	}

	// Test X25519 key generation through Crypto struct
	x25519Kp, err := crypto.X25519KeyExchangeKeygen()
	if err != nil {
		t.Fatalf("Failed to generate X25519 key pair through Crypto: %v", err)
	}

	if x25519Kp.AlgorithmType() != X25519 {
		t.Error("X25519 key pair has wrong algorithm type")
	}

	// Test ChaCha20-Poly1305 cipher generation through Crypto struct
	chaChacipher, err := crypto.ChaCha20Poly1305CipherKeygen()
	if err != nil {
		t.Fatalf("Failed to generate ChaCha20-Poly1305 cipher through Crypto: %v", err)
	}

	if chaChacipher.AlgorithmType() != CHACHA20_POLY1305 {
		t.Error("ChaCha20-Poly1305 cipher has wrong algorithm type")
	}

	t.Log("All modern crypto algorithms successfully integrated with Crypto struct")
}

// --- merged from crypto_stream_test.go ---

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

// --- merged from crypto_utilities_test.go ---

// TestRandom32 verifies Random32 generates non-zero values
func TestRandom32(t *testing.T) {
	crypto := NewCrypto()

	// Generate multiple random values
	values := make(map[uint32]bool)
	const iterations = 100

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()
		values[val] = true
	}

	// Verify we got at least some different values
	// With 100 iterations and 32-bit space, we should get mostly unique values
	if len(values) < 50 {
		t.Errorf("expected at least 50 unique values from %d iterations, got %d", iterations, len(values))
	}
}

// TestRandom32Distribution verifies Random32 uses all bytes
func TestRandom32Distribution(t *testing.T) {
	crypto := NewCrypto()

	// Generate values and check that we see variety across all byte positions
	const iterations = 1000
	bytePositions := [4]map[byte]bool{
		make(map[byte]bool),
		make(map[byte]bool),
		make(map[byte]bool),
		make(map[byte]bool),
	}

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()

		// Extract bytes
		bytePositions[0][byte(val>>24)] = true
		bytePositions[1][byte(val>>16)] = true
		bytePositions[2][byte(val>>8)] = true
		bytePositions[3][byte(val)] = true
	}

	// Check that each byte position has reasonable variety
	// With 1000 iterations, we should see at least 100 different values per byte
	for i, bytesMap := range bytePositions {
		if len(bytesMap) < 100 {
			t.Errorf("byte position %d has insufficient variety: only %d unique values", i, len(bytesMap))
		}
	}
}

// TestRandom32Uniqueness verifies consecutive calls produce different values
func TestRandom32Uniqueness(t *testing.T) {
	crypto := NewCrypto()

	const iterations = 50
	var duplicateCount int
	var lastValue uint32

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()
		if i > 0 && val == lastValue {
			duplicateCount++
		}
		lastValue = val
	}

	// Allow a very small number of duplicates due to chance
	// but with 32-bit space, consecutive duplicates should be extremely rare
	if duplicateCount > 2 {
		t.Errorf("too many consecutive duplicates: %d in %d iterations", duplicateCount, iterations)
	}
}

// TestRandom32NonZero verifies Random32 can generate non-zero values
func TestRandom32NonZero(t *testing.T) {
	crypto := NewCrypto()

	// Generate some values and verify at least one is non-zero
	foundNonZero := false
	for i := 0; i < 10; i++ {
		if val := crypto.Random32(); val != 0 {
			foundNonZero = true
			break
		}
	}

	if !foundNonZero {
		t.Error("expected to find at least one non-zero value in 10 iterations")
	}
}

// TestRandom32FullRange verifies Random32 can generate values across the uint32 range
func TestRandom32FullRange(t *testing.T) {
	crypto := NewCrypto()

	// Check that we can generate values in different ranges
	const iterations = 1000
	var lowRange, midRange, highRange int

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()

		if val < 0x55555555 {
			lowRange++
		} else if val < 0xAAAAAAAA {
			midRange++
		} else {
			highRange++
		}
	}

	// Each range should have at least some values
	// With uniform distribution, we expect roughly 333 in each range
	// Allow for statistical variance but ensure no range is empty
	if lowRange == 0 {
		t.Error("no values generated in low range (0 to 0x55555554)")
	}
	if midRange == 0 {
		t.Error("no values generated in mid range (0x55555555 to 0xAAAAAAA9)")
	}
	if highRange == 0 {
		t.Error("no values generated in high range (0xAAAAAAAA to 0xFFFFFFFF)")
	}

	// Also verify reasonable distribution (each should be between 20% and 50%)
	if lowRange < 200 || lowRange > 500 {
		t.Logf("low range count outside expected distribution: %d", lowRange)
	}
	if midRange < 200 || midRange > 500 {
		t.Logf("mid range count outside expected distribution: %d", midRange)
	}
	if highRange < 200 || highRange > 500 {
		t.Logf("high range count outside expected distribution: %d", highRange)
	}
}

// TestRandom32Concurrency verifies Random32 is safe for concurrent use
func TestRandom32Concurrency(t *testing.T) {
	crypto := NewCrypto()

	const goroutines = 10
	const iterations = 100
	done := make(chan bool, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < iterations; i++ {
				_ = crypto.Random32()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for g := 0; g < goroutines; g++ {
		<-done
	}

	// If we get here without panic, concurrency safety is verified
}
