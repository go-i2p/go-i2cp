package go_i2cp

import (
	"testing"
)

// TestSessionConfigSignatureGeneration verifies that CreateSession signature
// is generated correctly per I2CP specification
func TestSessionConfigSignatureGeneration(t *testing.T) {
	crypto := NewCrypto()

	// Create a destination with DSA keypair
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Create session config
	config := &SessionConfig{
		destination: dest,
	}

	// Set some properties
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")

	// Generate the CreateSession message
	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	// Verify message was generated
	if stream.Len() == 0 {
		t.Fatal("CreateSession message is empty")
	}

	t.Logf("CreateSession message length: %d bytes", stream.Len())

	// Parse the message to extract signature
	parseStream := NewStream(stream.Bytes())

	// Read destination (skip - we'll use the original dest for verification)
	_, err = NewDestinationFromMessage(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to read destination from message: %v", err)
	}

	// Read properties mapping
	_, err = parseStream.ReadMapping()
	if err != nil {
		t.Fatalf("Failed to read properties mapping: %v", err)
	}

	// Read creation date
	creationDate, err := parseStream.ReadUint64()
	if err != nil {
		t.Fatalf("Failed to read creation date: %v", err)
	}
	t.Logf("Creation date: %d (ms since epoch)", creationDate)

	// Signature follows directly (no type prefix)
	// Java I2P determines signature type from Destination's signing key type in certificate
	// Signature length depends on type: Ed25519 = 64 bytes, DSA = 40 bytes
	// Our destination uses Ed25519, so expect 64-byte signature
	signature := make([]byte, 64)
	n, err := parseStream.Read(signature)
	if err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}
	if n != 64 {
		t.Fatalf("Signature length incorrect: got %d bytes, expected 64", n)
	}

	t.Logf("Signature: %x", signature)

	// Verify signature by reconstructing the data that was signed
	// Use the original dest, not readDest, to ensure exact match
	dataToVerify := NewStream(make([]byte, 0, 512))
	dest.WriteToMessage(dataToVerify)

	// Rebuild properties mapping
	m := make(map[string]string)
	for i := 0; i < int(NR_OF_SESSION_CONFIG_PROPERTIES); i++ {
		if config.properties[i] == "" {
			continue
		}
		option := config.configOptLookup(SessionConfigProperty(i))
		if option == "" {
			continue
		}
		m[option] = config.properties[i]
	}
	dataToVerify.WriteMapping(m)
	dataToVerify.WriteUint64(creationDate)

	t.Logf("Data to verify length: %d bytes", dataToVerify.Len())
	t.Logf("Data to verify (first 64 bytes): %x", dataToVerify.Bytes()[:min64(64, dataToVerify.Len())])

	// Verify Ed25519 signature using the destination's public key
	if dest.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available")
	}

	verified := dest.sgk.ed25519KeyPair.Verify(dataToVerify.Bytes(), signature)
	if !verified {
		t.Fatal("Signature verification failed")
	}

	t.Log("Signature verification succeeded")
}

func min64(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSessionConfigSignatureFormat verifies the signature has correct format
func TestSessionConfigSignatureFormat(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	// The message should end with: 64-byte Ed25519 signature (no type prefix)
	// Java I2P determines signature type from the Destination's signing key certificate
	messageBytes := stream.Bytes()
	if len(messageBytes) < 64 {
		t.Fatalf("Message too short to contain signature: %d bytes", len(messageBytes))
	}

	// Last 64 bytes: signature only (no type prefix)
	signature := messageBytes[len(messageBytes)-64:]

	// Signature should not be all zeros
	allZeros := true
	for _, b := range signature {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Fatal("Signature is all zeros - signing failed")
	}

	t.Logf("Signature (64 bytes): %x", signature)
}

// TestSessionConfigSignatureWithoutProperties verifies signing works with empty properties
func TestSessionConfigSignatureWithoutProperties(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Config with no properties set
	config := &SessionConfig{
		destination: dest,
	}

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	if stream.Len() == 0 {
		t.Fatal("Message generation failed")
	}

	t.Logf("Message with no properties: %d bytes", stream.Len())

	// Should still have valid Ed25519 signature (2 bytes type + 64 bytes signature)
	messageBytes := stream.Bytes()
	if len(messageBytes) < 66 {
		t.Fatalf("Message too short for signature: %d bytes", len(messageBytes))
	}

	signature := messageBytes[len(messageBytes)-64:]

	// Verify signature is not all zeros
	allZeros := true
	for _, b := range signature {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Fatal("Signature is all zeros")
	}
}

// TestCreateSessionMessageSize verifies the message size is reasonable
func TestCreateSessionMessageSize(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}

	// Add typical properties
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "3")
	config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "3")

	stream := NewStream(make([]byte, 0, 1024))
	config.writeToMessage(stream, crypto, nil)

	messageSize := stream.Len()

	// Expected size breakdown:
	// - Destination: 387 bytes (256 pubkey + 128 signing pubkey + 3 cert)
	// - Properties mapping: variable (typically 50-200 bytes)
	// - Creation date: 8 bytes
	// - Signature type: 2 bytes
	// - Ed25519 signature: 64 bytes
	// Total: ~511-661 bytes

	if messageSize < 450 {
		t.Fatalf("Message too small: %d bytes (expected 450+)", messageSize)
	}

	if messageSize > 1000 {
		t.Fatalf("Message too large: %d bytes (expected <1000)", messageSize)
	}

	t.Logf("Message size: %d bytes (within expected range)", messageSize)
}
