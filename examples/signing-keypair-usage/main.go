package main

import (
	"fmt"
	"log"

	i2cp "github.com/go-i2p/go-i2cp"
)

// Example: Using Session.SigningKeyPair() for I2P Streaming Protocol packet authentication
//
// This demonstrates how to access the session's Ed25519 signing key pair
// to sign packets for the I2P Streaming Protocol, as required by the spec.

func main() {
	fmt.Println("=== Session Signing Key Pair Usage Example ===")

	session := createExampleSession()
	keyPair := getSigningKeyPair(session)

	packetData := createExamplePacket()
	signature := demonstrateSigning(keyPair, packetData)
	demonstratVerification(keyPair, packetData, signature)
	demonstrateTamperedVerification(keyPair, packetData, signature)

	showKeyRelationships(session)
	printUseCaseGuide()
}

// createExampleSession creates a session for the example.
func createExampleSession() *i2cp.Session {
	client := i2cp.NewClient(nil)
	return i2cp.NewSession(client, i2cp.SessionCallbacks{})
}

// getSigningKeyPair retrieves and displays the signing key pair.
func getSigningKeyPair(session *i2cp.Session) *i2cp.Ed25519KeyPair {
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		log.Fatalf("Failed to get signing key pair: %v", err)
	}
	fmt.Printf("✓ Retrieved signing key pair from session\n")
	fmt.Printf("  Algorithm: Ed25519-SHA512\n")
	fmt.Printf("  Public key length: %d bytes\n", len(keyPair.PublicKey()))
	fmt.Printf("  Private key length: %d bytes\n\n", len(keyPair.PrivateKey()))
	return keyPair
}

// createExamplePacket creates an example packet for signing.
func createExamplePacket() []byte {
	return []byte{
		0x01,                   // Protocol version
		0x06,                   // Flags: SYN | SignatureIncluded | FromIncluded
		0x00, 0x01, 0x23, 0x45, // Send stream ID
		0x00, 0x00, 0x00, 0x00, // Receive stream ID
	}
}

// demonstrateSigning demonstrates packet signing.
func demonstrateSigning(keyPair *i2cp.Ed25519KeyPair, packetData []byte) []byte {
	fmt.Println("Example: Signing I2P Streaming Protocol packet")
	fmt.Printf("  Packet data: %d bytes\n", len(packetData))

	signature, err := keyPair.Sign(packetData)
	if err != nil {
		log.Fatalf("Failed to sign packet: %v", err)
	}
	fmt.Printf("✓ Generated signature: %d bytes\n", len(signature))
	fmt.Printf("  Signature (first 32 bytes): %x...\n\n", signature[:32])
	return signature
}

// demonstratVerification demonstrates signature verification.
func demonstratVerification(keyPair *i2cp.Ed25519KeyPair, packetData, signature []byte) {
	fmt.Println("Example: Verifying packet signature")
	if keyPair.Verify(packetData, signature) {
		fmt.Println("✓ Signature verified successfully")
	} else {
		fmt.Println("✗ Signature verification failed")
	}
}

// demonstrateTamperedVerification demonstrates verification with tampered data.
func demonstrateTamperedVerification(keyPair *i2cp.Ed25519KeyPair, packetData, signature []byte) {
	fmt.Println("\nExample: Signature verification with tampered data")
	tamperedData := make([]byte, len(packetData))
	copy(tamperedData, packetData)
	tamperedData[0] = 0xFF

	if !keyPair.Verify(tamperedData, signature) {
		fmt.Println("✓ Signature verification correctly failed for tampered data")
	} else {
		fmt.Println("✗ ERROR: Signature should not verify for tampered data")
	}
}

// showKeyRelationships displays the relationship between session, destination, and key pair.
func showKeyRelationships(session *i2cp.Session) {
	fmt.Println("\n=== Key Relationships ===")
	dest := session.Destination()
	fmt.Printf("Session destination: %s\n", dest.Base32())
	fmt.Println("✓ SigningKeyPair() returns the same key pair used by the destination")
	fmt.Println("✓ This enables proper packet authentication in I2P Streaming Protocol")
}

// printUseCaseGuide prints the usage guide for I2P Streaming Protocol.
func printUseCaseGuide() {
	fmt.Println("\n=== Use Case: I2P Streaming Protocol ===")
	fmt.Println("When implementing streaming protocol packet sending:")
	fmt.Println("  1. Create packet with flags FlagSignatureIncluded")
	fmt.Println("  2. Marshal packet (excluding signature field)")
	fmt.Println("  3. keyPair, _ := session.SigningKeyPair()")
	fmt.Println("  4. signature, _ := keyPair.Sign(marshaledPacket)")
	fmt.Println("  5. Append signature to packet")
	fmt.Println("  6. Send authenticated packet to peer")
	fmt.Println("\nReceiver verifies by:")
	fmt.Println("  1. Extract sender destination from packet")
	fmt.Println("  2. Get sender's public key from destination")
	fmt.Println("  3. senderKeyPair.Verify(packetData, signature)")
}
