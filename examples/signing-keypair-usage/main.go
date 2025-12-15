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
	// Create a new session (in real usage, you'd connect to an I2P router)
	client := i2cp.NewClient(nil)
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{})

	fmt.Println("=== Session Signing Key Pair Usage Example ===")

	// Get the session's signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		log.Fatalf("Failed to get signing key pair: %v", err)
	}

	fmt.Printf("✓ Retrieved signing key pair from session\n")
	fmt.Printf("  Algorithm: Ed25519-SHA512\n")
	fmt.Printf("  Public key length: %d bytes\n", len(keyPair.PublicKey()))
	fmt.Printf("  Private key length: %d bytes\n\n", len(keyPair.PrivateKey()))

	// Example: Signing an I2P Streaming Protocol packet
	// In real usage, this would be a marshaled packet structure
	packetData := []byte{
		// Simulated packet header
		0x01,                   // Protocol version
		0x06,                   // Flags: SYN | SignatureIncluded | FromIncluded
		0x00, 0x01, 0x23, 0x45, // Send stream ID
		0x00, 0x00, 0x00, 0x00, // Receive stream ID
		// ... more packet fields ...
	}

	fmt.Println("Example: Signing I2P Streaming Protocol packet")
	fmt.Printf("  Packet data: %d bytes\n", len(packetData))

	// Sign the packet data
	signature, err := keyPair.Sign(packetData)
	if err != nil {
		log.Fatalf("Failed to sign packet: %v", err)
	}

	fmt.Printf("✓ Generated signature: %d bytes\n", len(signature))
	fmt.Printf("  Signature (first 32 bytes): %x...\n\n", signature[:32])

	// Verify the signature (receiver would do this)
	fmt.Println("Example: Verifying packet signature")
	valid := keyPair.Verify(packetData, signature)
	if valid {
		fmt.Println("✓ Signature verified successfully")
	} else {
		fmt.Println("✗ Signature verification failed")
	}

	// Demonstrate signature verification failure with tampered data
	fmt.Println("\nExample: Signature verification with tampered data")
	tamperedData := make([]byte, len(packetData))
	copy(tamperedData, packetData)
	tamperedData[0] = 0xFF // Tamper with first byte

	valid = keyPair.Verify(tamperedData, signature)
	if !valid {
		fmt.Println("✓ Signature verification correctly failed for tampered data")
	} else {
		fmt.Println("✗ ERROR: Signature should not verify for tampered data")
	}

	// Show relationship between session, destination, and key pair
	fmt.Println("\n=== Key Relationships ===")
	dest := session.Destination()
	fmt.Printf("Session destination: %s\n", dest.Base32())
	fmt.Println("✓ SigningKeyPair() returns the same key pair used by the destination")
	fmt.Println("✓ This enables proper packet authentication in I2P Streaming Protocol")

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
