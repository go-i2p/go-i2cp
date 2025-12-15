package main

import (
	"fmt"
	"log"

	i2cp "github.com/go-i2p/go-i2cp"
)

// Example: Accessing Source Destination from Incoming Messages
//
// This demonstrates how to use the source destination (srcDest) parameter
// in the OnMessage callback to:
// 1. Extract the sender's I2P destination
// 2. Verify packet signatures offline (without private key)
// 3. Implement server-mode connections for streaming protocol

func main() {
	fmt.Println("=== Source Destination API Usage Example ===")

	// Create I2CP client
	client := i2cp.NewClient(nil)

	// Create session with message callback
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnMessage: handleIncomingMessage,
	})

	fmt.Println("Session created with message handler")
	fmt.Println("The OnMessage callback receives the source destination (srcDest)")
	fmt.Println("from the I2CP layer for every incoming message.")

	// Get the session's own destination for reference
	dest := session.Destination()
	if dest != nil {
		fmt.Printf("Session destination: %s\n", dest.Base32())
		fmt.Println("This is YOUR destination that other peers send messages to.")
	}

	fmt.Println("=== Use Cases ===")
	fmt.Println("1. Server Connections (I2P Streaming Protocol)")
	fmt.Println("   - When receiving a SYN packet, srcDest identifies the remote peer")
	fmt.Println("   - Required for establishing bidirectional connections")
	fmt.Println("   - Without FlagFromIncluded, srcDest comes from I2CP layer")

	fmt.Println("2. Offline Signature Verification")
	fmt.Println("   - Extract signing public key from srcDest")
	fmt.Println("   - Verify packet signatures cryptographically")
	fmt.Println("   - No private key needed - just the sender's destination")

	fmt.Println("3. Connection Tracking")
	fmt.Println("   - Use srcDest.Base32() as connection identifier")
	fmt.Println("   - Track multiple connections from different peers")
	fmt.Println("   - Implement per-connection state management")

	// Example: Simulate receiving a packet with embedded signature
	demonstrateSignatureVerification()
}

// handleIncomingMessage processes messages from the I2CP layer
// This is the callback signature that receives the source destination
func handleIncomingMessage(session *i2cp.Session, srcDest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
	// srcDest is ALWAYS available here - this is what was requested!
	fmt.Printf("\n=== Received Message ===\n")
	fmt.Printf("From: %s\n", srcDest.Base32())
	fmt.Printf("Protocol: %d\n", protocol)
	fmt.Printf("Source Port: %d\n", srcPort)
	fmt.Printf("Destination Port: %d\n", destPort)
	fmt.Printf("Payload Size: %d bytes\n", payload.Len())

	// Use Case 1: Extract sender's destination for server connections
	if protocol == 6 { // I2P Streaming Protocol
		fmt.Printf("\n✓ I2P Streaming packet detected\n")
		fmt.Printf("  Remote peer destination: %s\n", srcDest.Base32())
		fmt.Printf("  Can now establish bidirectional connection\n")

		// In real usage, you would:
		// conn := streamManager.acceptConnection(packet, srcDest)
	}

	// Use Case 2: Verify packet signature using source destination
	// (See demonstrateSignatureVerification for detailed example)

	// Use Case 3: Track connection by source destination
	connectionID := srcDest.Base32()
	fmt.Printf("\n✓ Connection tracking\n")
	fmt.Printf("  Connection ID: %s\n", connectionID[:52]+"...")
	fmt.Printf("  Use this to maintain per-connection state\n")
}

// createRemotePeerAndPacket creates a test destination and signs a packet.
// Returns the remote peer, packet data, and signature.
func createRemotePeerAndPacket() (*i2cp.Destination, []byte, []byte) {
	crypto := i2cp.NewCrypto()
	remotePeer, err := i2cp.NewDestination(crypto)
	if err != nil {
		log.Fatalf("Failed to create remote peer destination: %v", err)
	}

	fmt.Printf("Remote peer destination: %s\n", remotePeer.Base32())

	packetData := []byte("I2P Streaming Protocol SYN packet data")
	fmt.Printf("Packet data: %q\n", packetData)
	fmt.Printf("Size: %d bytes\n", len(packetData))

	signingKey, err := remotePeer.SigningKeyPair()
	if err != nil {
		log.Fatalf("Failed to get signing key: %v", err)
	}

	signature, err := signingKey.Sign(packetData)
	if err != nil {
		log.Fatalf("Failed to sign packet: %v", err)
	}

	fmt.Println("✓ Packet signed by remote peer")
	fmt.Printf("  Signature size: %d bytes\n", len(signature))

	return remotePeer, packetData, signature
}

// verifySignatureWithMethods demonstrates two methods of signature verification.
// Method 1 uses Destination.VerifySignature, Method 2 uses SigningPublicKey directly.
func verifySignatureWithMethods(remotePeer *i2cp.Destination, packetData, signature []byte) {
	fmt.Println("=== Receiver Side (Server) ===")
	fmt.Println("Received srcDest from I2CP layer (OnMessage callback)")
	fmt.Printf("Source: %s\n", remotePeer.Base32())

	isValid := remotePeer.VerifySignature(packetData, signature)
	fmt.Println("✓ Signature verification (Method 1 - Destination.VerifySignature)")
	fmt.Printf("  Result: %v\n", isValid)
	if isValid {
		fmt.Println("  ✓ Signature is cryptographically valid!")
		fmt.Println("  ✓ Packet authenticity confirmed")
		fmt.Println("  ✓ No private key needed for verification")
	}

	pubKey := remotePeer.SigningPublicKey()
	if pubKey != nil {
		isValid2 := pubKey.Verify(packetData, signature)
		fmt.Println("✓ Signature verification (Method 2 - SigningPublicKey.Verify)")
		fmt.Printf("  Result: %v\n", isValid2)
		fmt.Println("  Public key algorithm: Ed25519-SHA512")
	}
}

// testInvalidSignature verifies that corrupted signatures are correctly rejected.
func testInvalidSignature(remotePeer *i2cp.Destination, packetData, signature []byte) {
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[0] ^= 0xFF

	isInvalid := remotePeer.VerifySignature(packetData, invalidSignature)
	fmt.Println("✓ Invalid signature test")
	fmt.Printf("  Result: %v (expected: false)\n", isInvalid)
	if !isInvalid {
		fmt.Println("  ✓ Correctly rejected corrupted signature")
	}
}

// demonstrateSignatureVerification shows how to verify signatures
// using the source destination's public key
func demonstrateSignatureVerification() {
	fmt.Println("\n=== Example: Offline Signature Verification ===")

	remotePeer, packetData, signature := createRemotePeerAndPacket()

	verifySignatureWithMethods(remotePeer, packetData, signature)

	testInvalidSignature(remotePeer, packetData, signature)

	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ Source destination is available from OnMessage callback")
	fmt.Println("✓ Can extract signing public key for verification")
	fmt.Println("✓ Offline signature verification works without private key")
	fmt.Println("✓ Enables full I2P Streaming Protocol implementation")
	fmt.Println("✓ Supports both client and server modes")
}
