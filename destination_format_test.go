package go_i2cp

import (
	"bytes"
	"testing"
)

// TestDestinationWriteFormats verifies that WriteForSignature produces the correct
// truncated format compared to WriteToMessage padded format
func TestDestinationWriteFormats(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Write with padded format (wire format)
	paddedStream := NewStream(make([]byte, 0, 512))
	if err := dest.WriteToMessage(paddedStream); err != nil {
		t.Fatalf("WriteToMessage failed: %v", err)
	}

	// Write with truncated format (signature format)
	truncatedStream := NewStream(make([]byte, 0, 512))
	if err := dest.WriteForSignature(truncatedStream); err != nil {
		t.Fatalf("WriteForSignature failed: %v", err)
	}

	paddedBytes := paddedStream.Bytes()
	truncatedBytes := truncatedStream.Bytes()

	t.Logf("Padded format:    %d bytes", len(paddedBytes))
	t.Logf("Truncated format: %d bytes", len(truncatedBytes))
	t.Logf("Difference:       %d bytes", len(paddedBytes)-len(truncatedBytes))

	expectedDiff := 128 - 32 // Should be 96 bytes difference
	if len(paddedBytes)-len(truncatedBytes) != expectedDiff {
		t.Fatalf("Expected %d byte difference, got %d", expectedDiff, len(paddedBytes)-len(truncatedBytes))
	}

	// Verify pubKey is identical (first 256 bytes)
	if !bytes.Equal(paddedBytes[:256], truncatedBytes[:256]) {
		t.Fatal("Public key (first 256 bytes) differs between formats!")
	}
	t.Log("✓ Public key identical in both formats")

	// Extract signing keys
	paddedSigningKey := paddedBytes[256:384]       // 128 bytes
	truncatedSigningKey := truncatedBytes[256:288] // 32 bytes

	t.Logf("Padded signing key (128 bytes):    %x", paddedSigningKey)
	t.Logf("Truncated signing key (32 bytes): %x", truncatedSigningKey)

	// The truncated key should match the RIGHT-ALIGNED portion of the padded key
	paddedKeyExtracted := paddedSigningKey[96:128] // Last 32 bytes
	t.Logf("Extracted from padded (bytes 96-127): %x", paddedKeyExtracted)

	if !bytes.Equal(paddedKeyExtracted, truncatedSigningKey) {
		t.Fatal("Truncated signing key doesn't match extracted key from padded format!")
	}
	t.Log("✓ Truncated signing key matches right-aligned portion of padded key")

	// Verify certificate is identical
	paddedCert := paddedBytes[384:391]       // 7 bytes (type=1, length=2, payload=4)
	truncatedCert := truncatedBytes[288:295] // 7 bytes

	t.Logf("Padded cert:    %x", paddedCert)
	t.Logf("Truncated cert: %x", truncatedCert)

	if !bytes.Equal(paddedCert, truncatedCert) {
		t.Fatal("Certificate differs between formats!")
	}
	t.Log("✓ Certificate identical in both formats")

	t.Log("✓ All format validations passed")
}
