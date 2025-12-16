package go_i2cp

import (
	"testing"
)

// TestSessionConfigWireFormatVerification tests that a signature created over truncated format
// can be verified against wire format after Java-style extraction
func TestSessionConfigWireFormatVerification(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")

	// Step 1: Build signature data (truncated format) and sign it
	signatureData := NewStream(make([]byte, 0, 512))
	if err := config.destination.WriteForSignature(signatureData); err != nil {
		t.Fatalf("Failed to write destination for signature: %v", err)
	}
	if err := config.writeMappingToMessage(signatureData); err != nil {
		t.Fatalf("Failed to write mapping for signature: %v", err)
	}
	timestamp := uint64(1234567890000)
	signatureData.WriteUint64(timestamp)

	signature, err := config.signSessionConfig(signatureData.Bytes(), crypto)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Logf("Signed %d bytes", signatureData.Len())
	t.Logf("Signature: %x", signature)

	// Step 2: Build wire message (padded format)
	wireMessage := NewStream(make([]byte, 0, 512))
	if err := config.destination.WriteToMessage(wireMessage); err != nil {
		t.Fatalf("Failed to write destination to wire: %v", err)
	}
	if err := config.writeMappingToMessage(wireMessage); err != nil {
		t.Fatalf("Failed to write mapping to wire: %v", err)
	}
	wireMessage.WriteUint64(timestamp)
	wireMessage.Write(signature)

	t.Logf("Wire message: %d bytes", wireMessage.Len())

	// Step 3: Simulate Java's process: read wire message, extract keys, re-serialize for verification
	readStream := NewStream(wireMessage.Bytes())

	// Read wire format destination
	destRead, err := NewDestinationFromMessage(readStream, crypto)
	if err != nil {
		t.Fatalf("Failed to read destination from wire: %v", err)
	}

	// Read properties
	propsRead, err := readStream.ReadMapping()
	if err != nil {
		t.Fatalf("Failed to read properties: %v", err)
	}

	// Read timestamp
	timestampRead, err := readStream.ReadUint64()
	if err != nil {
		t.Fatalf("Failed to read timestamp: %v", err)
	}

	// Read signature
	signatureRead := make([]byte, 64)
	if _, err := readStream.Read(signatureRead); err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}

	t.Logf("Read destination, %d properties, timestamp %d", len(propsRead), timestampRead)

	// CRITICAL CHECK: Verify the public key we read matches the original
	originalPubKey := dest.sgk.ed25519KeyPair.PublicKey()
	readPubKey := destRead.sgk.ed25519KeyPair.PublicKey()

	t.Logf("Original public key: %x", originalPubKey[:])
	t.Logf("Read public key:     %x", readPubKey[:])

	if string(originalPubKey[:]) != string(readPubKey[:]) {
		t.Fatalf("Public key mismatch! Original != Read")
	}
	t.Log("Public keys match ✓")

	// Step 4: Re-serialize for verification (truncated format, like Java does)
	verifyData := NewStream(make([]byte, 0, 512))
	if err := destRead.WriteForSignature(verifyData); err != nil {
		t.Fatalf("Failed to write destination for verification: %v", err)
	}

	// Write properties using WriteMapping
	if err := verifyData.WriteMapping(propsRead); err != nil {
		t.Fatalf("Failed to write properties for verification: %v", err)
	}

	verifyData.WriteUint64(timestampRead)

	t.Logf("Verify data: %d bytes", verifyData.Len())
	t.Logf("Original signature data: %d bytes", signatureData.Len())

	if verifyData.Len() != signatureData.Len() {
		t.Fatalf("Data length mismatch: signed %d bytes, verifying %d bytes", signatureData.Len(), verifyData.Len())
	}

	// Compare byte-by-byte
	for i := 0; i < signatureData.Len(); i++ {
		if signatureData.Bytes()[i] != verifyData.Bytes()[i] {
			t.Errorf("Byte mismatch at position %d: signed=0x%02x, verify=0x%02x", i, signatureData.Bytes()[i], verifyData.Bytes()[i])
			if i > 0 {
				t.Logf("Context at %d: signed[%d--%d]=%x", i, max(0, i-4), min(signatureData.Len(), i+4), signatureData.Bytes()[max(0, i-4):min(signatureData.Len(), i+4)])
				t.Logf("Context at %d: verify[%d:%d]=%x", i, max(0, i-4), min(verifyData.Len(), i+4), verifyData.Bytes()[max(0, i-4):min(verifyData.Len(), i+4)])
			}
			break
		}
	}

	// Step 5: Verify signature
	if destRead.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available after reading")
	}

	verified := destRead.sgk.ed25519KeyPair.Verify(verifyData.Bytes(), signatureRead)
	if !verified {
		t.Fatal("Signature verification failed!")
	}

	t.Log("Signature verification succeeded!")
}
