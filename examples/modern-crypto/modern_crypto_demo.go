// Example: Modern I2P Cryptography Usage
// This file demonstrates how to use the modernized cryptographic algorithms
// alongside the existing DSA/SHA1/SHA256 functionality.

package main

import (
	"fmt"
	"log"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	fmt.Println("=== I2CP Modern Cryptography Demo ===")

	// Initialize the crypto system
	crypto := go_i2cp.NewCrypto()
	fmt.Println("✅ Crypto system initialized")

	// === Ed25519 Digital Signatures ===
	fmt.Println("\n🔑 Ed25519 Digital Signatures:")

	ed25519Kp, err := crypto.Ed25519SignatureKeygen()
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	fmt.Printf("   ✅ Generated Ed25519 key pair (algorithm type: %d)\n", ed25519Kp.AlgorithmType())

	// Sign a message
	message := []byte("Hello, anonymous I2P network!")
	signature, err := ed25519Kp.Sign(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	fmt.Printf("   ✅ Signed message (%d bytes signature)\n", len(signature))

	// Verify signature
	verified := ed25519Kp.Verify(message, signature)
	if verified {
		fmt.Println("   ✅ Signature verification successful")
	} else {
		fmt.Println("   ❌ Signature verification failed")
	}

	// === X25519 Key Exchange ===
	fmt.Println("\n🔐 X25519 Key Exchange (ECDH):")

	// Generate two key pairs (Alice and Bob)
	aliceKp, err := crypto.X25519KeyExchangeKeygen()
	if err != nil {
		log.Fatalf("Failed to generate Alice's key pair: %v", err)
	}
	fmt.Printf("   ✅ Generated Alice's X25519 key pair (algorithm type: %d)\n", aliceKp.AlgorithmType())

	bobKp, err := crypto.X25519KeyExchangeKeygen()
	if err != nil {
		log.Fatalf("Failed to generate Bob's key pair: %v", err)
	}
	fmt.Println("   ✅ Generated Bob's X25519 key pair")

	// Perform ECDH from both sides
	sharedSecretAlice, err := aliceKp.GenerateSharedSecret(bobKp.PublicKey())
	if err != nil {
		log.Fatalf("Alice failed to generate shared secret: %v", err)
	}

	sharedSecretBob, err := bobKp.GenerateSharedSecret(aliceKp.PublicKey())
	if err != nil {
		log.Fatalf("Bob failed to generate shared secret: %v", err)
	}

	if sharedSecretAlice == sharedSecretBob {
		fmt.Printf("   ✅ ECDH successful - shared secret established (%d bytes)\n", len(sharedSecretAlice))
	} else {
		fmt.Println("   ❌ ECDH failed - shared secrets don't match")
	}

	// === ChaCha20-Poly1305 Encryption ===
	fmt.Println("\n🔒 ChaCha20-Poly1305 Authenticated Encryption:")

	cipher, err := crypto.ChaCha20Poly1305CipherKeygen()
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}
	fmt.Printf("   ✅ Created ChaCha20-Poly1305 cipher (algorithm type: %d)\n", cipher.AlgorithmType())

	// Encrypt a message
	plaintext := []byte("This is a secret message traveling through I2P tunnels!")
	additionalData := []byte("session_metadata_v1")

	ciphertext, err := cipher.Encrypt(plaintext, additionalData)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	fmt.Printf("   ✅ Encrypted message: %d bytes → %d bytes (overhead: %d bytes)\n",
		len(plaintext), len(ciphertext), len(ciphertext)-len(plaintext))

	// Decrypt the message
	decrypted, err := cipher.Decrypt(ciphertext, additionalData)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) == string(plaintext) {
		fmt.Println("   ✅ Decryption successful - message integrity verified")
	} else {
		fmt.Println("   ❌ Decryption failed - message corrupted")
	}

	// === Stream Serialization ===
	fmt.Println("\n💾 Stream Serialization (I2CP compatibility):")

	// Test Ed25519 serialization
	stream := go_i2cp.NewStream(make([]byte, 0, 1024))
	err = ed25519Kp.WriteToStream(stream)
	if err != nil {
		log.Fatalf("Failed to serialize Ed25519 key pair: %v", err)
	}
	fmt.Printf("   ✅ Ed25519 key pair serialized (%d bytes)\n", stream.Len())

	// Deserialize and verify
	readStream := go_i2cp.NewStream(stream.Bytes())
	ed25519Kp2, err := go_i2cp.Ed25519KeyPairFromStream(readStream)
	if err != nil {
		log.Fatalf("Failed to deserialize Ed25519 key pair: %v", err)
	}

	// Test that deserialized key pair works
	signature2, err := ed25519Kp2.Sign(message)
	if err != nil {
		log.Fatalf("Failed to sign with deserialized key: %v", err)
	}

	if ed25519Kp.Verify(message, signature2) {
		fmt.Println("   ✅ Ed25519 serialization/deserialization successful")
	} else {
		fmt.Println("   ❌ Ed25519 serialization/deserialization failed")
	}

	// === Integration Summary ===
	fmt.Println("\n📋 Integration Summary:")
	fmt.Println("   ✅ Ed25519 signatures (modern, fast, secure)")
	fmt.Println("   ✅ X25519 key exchange (ECDH for perfect forward secrecy)")
	fmt.Println("   ✅ ChaCha20-Poly1305 encryption (authenticated encryption)")
	fmt.Println("   ✅ Stream-based serialization (I2CP protocol compatible)")
	fmt.Println("   ✅ Integrated with existing Crypto struct")

	fmt.Println("\n🎉 I2CP cryptography modernization complete!")
	fmt.Println("   Ready for production use in anonymous I2P applications.")
}
