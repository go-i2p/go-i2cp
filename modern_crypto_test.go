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

	// Test that existing DSA functionality compiles and generates key pairs
	dsaKp, err := crypto.SignatureKeygen(DSA_SHA1)
	if err != nil {
		t.Fatalf("Failed to generate DSA key pair: %v", err)
	}

	// Verify DSA key pair was created with correct algorithm type
	if dsaKp.algorithmType != DSA_SHA1 {
		t.Error("DSA key pair has wrong algorithm type")
	}

	t.Log("All modern crypto algorithms successfully integrated with Crypto struct")
}
