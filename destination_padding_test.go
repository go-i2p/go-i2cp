package go_i2cp

import (
	"testing"
)

// TestDestinationWriteToMessagePadding verifies that Destination.WriteToMessage
// correctly pads the signing public key to 128 bytes for I2CP protocol compatibility.
//
// This test ensures the fix for the CreateSessionMessage EOF bug where Java I2P Router
// failed to parse destinations because Ed25519 signing keys (32 bytes) were not padded
// to the required 128-byte field size.
func TestDestinationWriteToMessagePadding(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, DEST_SIZE))
	err = dest.WriteToMessage(stream)
	if err != nil {
		t.Fatalf("Failed to write destination to message: %v", err)
	}

	// I2CP Destination format (per Java I2P Destination.java):
	// - 256 bytes: public encryption key
	// - 128 bytes: signing public key (ALWAYS 128 bytes, even for Ed25519)
	// - Variable: certificate (3 bytes minimum for NULL cert)
	//
	// For Ed25519 with KEY certificate:
	// - 256 bytes: X25519 public key
	// - 128 bytes: Ed25519 public key (32 bytes actual, 96 bytes padding)
	// - 3 bytes: NULL certificate
	// Total: 387 bytes

	expectedSize := 387 // 256 + 128 + 3
	actualSize := stream.Len()

	if actualSize != expectedSize {
		t.Errorf("Incorrect destination size: got %d bytes, want %d bytes", actualSize, expectedSize)
		t.Errorf("Expected format: 256 (pubKey) + 128 (signKey padded) + 3 (cert) = 387")
	}

	// Verify the structure by reading it back
	data := stream.Bytes()

	// First 256 bytes: public encryption key
	if len(data) < 256 {
		t.Fatalf("Insufficient data for public key: got %d bytes", len(data))
	}

	// Next 128 bytes: signing public key (padded)
	if len(data) < 384 {
		t.Fatalf("Insufficient data for signing public key: got %d bytes", len(data))
	}

	// Ed25519 keys are 32 bytes, so first 96 bytes should be zero padding
	signKeyField := data[256:384]
	for i := 0; i < 96; i++ {
		if signKeyField[i] != 0 {
			t.Errorf("Expected zero padding at byte %d of signing key field, got %d", i, signKeyField[i])
			break
		}
	}

	// Last 32 bytes of signing key field should contain the actual Ed25519 public key
	actualSignKey := signKeyField[96:128]
	hasNonZero := false
	for _, b := range actualSignKey {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Signing public key appears to be all zeros (should contain actual Ed25519 key)")
	}

	// Remaining bytes: certificate
	if len(data) < 387 {
		t.Fatalf("Insufficient data for certificate: got %d bytes", len(data))
	}

	t.Logf("✓ Destination correctly serialized as %d bytes", actualSize)
	t.Logf("✓ Signing public key correctly padded to 128 bytes")
}
