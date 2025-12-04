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

	// Read destination (skip)
	readDest, err := NewDestinationFromMessage(parseStream, crypto)
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

	// Read signature
	signature := make([]byte, 40) // DSA signature is 40 bytes
	n, err := parseStream.Read(signature)
	if err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}
	if n != 40 {
		t.Fatalf("Signature length incorrect: got %d bytes, expected 40", n)
	}

	t.Logf("Signature: %x", signature)

	// Verify signature by reconstructing the data that was signed
	dataToVerify := NewStream(make([]byte, 0, 512))
	readDest.WriteToMessage(dataToVerify)

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

	// Verify signature using the destination's public key
	verified := dest.sgk.dsaKeyPair.Verify(dataToVerify.Bytes(), signature)
	if !verified {
		t.Fatal("Signature verification failed")
	}

	t.Log("Signature verification succeeded")
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

	// The message should end with a 40-byte DSA signature
	messageBytes := stream.Bytes()
	if len(messageBytes) < 40 {
		t.Fatalf("Message too short to contain signature: %d bytes", len(messageBytes))
	}

	// Last 40 bytes should be the signature
	signature := messageBytes[len(messageBytes)-40:]

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

	t.Logf("Signature (40 bytes): %x", signature)
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

	// Should still have valid signature
	messageBytes := stream.Bytes()
	signature := messageBytes[len(messageBytes)-40:]

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
	// - Signature: 40 bytes
	// Total: ~485-635 bytes

	if messageSize < 400 {
		t.Fatalf("Message too small: %d bytes (expected 400+)", messageSize)
	}

	if messageSize > 1000 {
		t.Fatalf("Message too large: %d bytes (expected <1000)", messageSize)
	}

	t.Logf("Message size: %d bytes (within expected range)", messageSize)
}
