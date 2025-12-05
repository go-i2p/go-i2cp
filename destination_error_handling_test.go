package go_i2cp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDestinationWriteToFileErrorHandling tests error handling in WriteToFile
func TestDestinationWriteToFileErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("success case", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		tmpDir := t.TempDir()
		filename := filepath.Join(tmpDir, "test_dest.dat")

		err = dest.WriteToFile(filename)
		if err != nil {
			t.Errorf("WriteToFile failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Error("Destination file was not created")
		}
	})

	t.Run("invalid directory", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// Try to write to non-existent directory
		filename := "/nonexistent/directory/test_dest.dat"

		err = dest.WriteToFile(filename)
		if err == nil {
			t.Error("Expected error when writing to non-existent directory")
		}
		t.Logf("Got expected error: %v", err)
	})
}

// TestDestinationWriteToMessageErrorHandling tests WriteToMessage error handling
func TestDestinationWriteToMessageErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("success case", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		stream := NewStream(make([]byte, 0, DEST_SIZE))
		err = dest.WriteToMessage(stream)
		if err != nil {
			t.Errorf("WriteToMessage failed: %v", err)
		}

		// Verify some data was written
		if stream.Len() == 0 {
			t.Error("No data written to stream")
		}
	})

	t.Run("round-trip preserves data", func(t *testing.T) {
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// Write to stream
		stream := NewStream(make([]byte, 0, DEST_SIZE))
		err = original.WriteToMessage(stream)
		if err != nil {
			t.Fatalf("WriteToMessage failed: %v", err)
		}

		// Read back
		stream.Seek(0, 0)
		reconstructed, err := NewDestinationFromMessage(stream, crypto)
		if err != nil {
			t.Fatalf("Failed to reconstruct destination: %v", err)
		}

		// Compare b32 addresses
		if original.b32 != reconstructed.b32 {
			t.Errorf("B32 addresses don't match: %s != %s", original.b32, reconstructed.b32)
		}
	})
}

// TestDestinationWriteToStreamErrorHandling tests WriteToStream error handling
func TestDestinationWriteToStreamErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("success case", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		stream := NewStream(make([]byte, 0, DEST_SIZE))
		err = dest.WriteToStream(stream)
		if err != nil {
			t.Errorf("WriteToStream failed: %v", err)
		}

		// Verify data was written
		if stream.Len() == 0 {
			t.Error("No data written to stream")
		}
	})

	t.Run("round-trip via stream", func(t *testing.T) {
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// Write to stream
		stream := NewStream(make([]byte, 0, DEST_SIZE))
		err = original.WriteToStream(stream)
		if err != nil {
			t.Fatalf("WriteToStream failed: %v", err)
		}

		// Read back
		stream.Seek(0, 0)
		reconstructed, err := NewDestinationFromStream(stream, crypto)
		if err != nil {
			t.Fatalf("Failed to reconstruct destination: %v", err)
		}

		// Compare b32 addresses
		if original.b32 != reconstructed.b32 {
			t.Errorf("B32 addresses don't match: %s != %s", original.b32, reconstructed.b32)
		}
	})
}

// TestDestinationGenerateB32ErrorHandling tests generateB32 error handling
func TestDestinationGenerateB32ErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("normal generation", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// B32 should be automatically generated
		if dest.b32 == "" {
			t.Error("B32 address was not generated")
		}

		if len(dest.b32) < 10 {
			t.Errorf("B32 address too short: %s", dest.b32)
		}

		// Should end with .b32.i2p
		expectedSuffix := ".b32.i2p"
		if len(dest.b32) < len(expectedSuffix) || dest.b32[len(dest.b32)-len(expectedSuffix):] != expectedSuffix {
			t.Errorf("B32 address doesn't end with %s: %s", expectedSuffix, dest.b32)
		}
	})

	t.Run("regenerate b32", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		first := dest.b32

		// Regenerate
		dest.generateB32()
		second := dest.b32

		// Should be identical (same data)
		if first != second {
			t.Errorf("Regenerated B32 differs: %s != %s", first, second)
		}
	})
}

// TestDestinationGenerateB64ErrorHandling tests generateB64 error handling
func TestDestinationGenerateB64ErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("normal generation", func(t *testing.T) {
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// B64 should be automatically generated
		if dest.b64 == "" {
			t.Error("B64 address was not generated")
		}

		if len(dest.b64) < 10 {
			t.Errorf("B64 address too short: %s", dest.b64)
		}
	})

	t.Run("round-trip via b64", func(t *testing.T) {
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		b64 := original.b64

		// Reconstruct from b64
		reconstructed, err := NewDestinationFromBase64(b64, crypto)
		if err != nil {
			t.Fatalf("Failed to reconstruct from b64: %v", err)
		}

		// Compare b32 addresses (more reliable than b64 comparison)
		if original.b32 != reconstructed.b32 {
			t.Errorf("B32 addresses don't match: %s != %s", original.b32, reconstructed.b32)
		}
	})
}

// TestDestinationVerifyErrorHandling tests Verify error handling
// DEPRECATED: Verify() method removed - DSA verification no longer supported
// Modern I2CP implementations use Ed25519 signatures exclusively
/*
func TestDestinationVerifyErrorHandling(t *testing.T) {
	crypto := NewCrypto()

	t.Run("verify destination", func(t *testing.T) {
	})
}
*/
