package go_i2cp

import (
	"bytes"
	"testing"
)

// TestDestination_Copy tests the Copy method
func TestDestination_Copy(t *testing.T) {
	t.Run("Copy creates independent destination", func(t *testing.T) {
		crypto := NewCrypto()
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create original destination: %v", err)
		}

		// Make a copy
		copied := original.Copy()

		// Verify all fields are copied
		if copied.cert != original.cert {
			t.Error("Certificate not copied correctly")
		}
		if copied.signPubKey.Cmp(original.signPubKey) != 0 {
			t.Error("Signing public key not copied correctly")
		}
		if copied.pubKey != original.pubKey {
			t.Error("Public key not copied correctly")
		}
		if copied.b32 != original.b32 {
			t.Errorf("Base32 address not copied correctly: got %s, want %s", copied.b32, original.b32)
		}
		if copied.b64 != original.b64 {
			t.Errorf("Base64 address not copied correctly: got %s, want %s", copied.b64, original.b64)
		}
		if copied.digest != original.digest {
			t.Error("Digest not copied correctly")
		}
	})

	t.Run("Copy preserves all destination data", func(t *testing.T) {
		crypto := NewCrypto()
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create original destination: %v", err)
		}

		copied := original.Copy()

		// Serialize both destinations
		origStream := NewStream(make([]byte, 0, DEST_SIZE))
		if err := original.WriteToMessage(origStream); err != nil {
			t.Fatalf("Failed to write original destination: %v", err)
		}

		copiedStream := NewStream(make([]byte, 0, DEST_SIZE))
		if err := copied.WriteToMessage(copiedStream); err != nil {
			t.Fatalf("Failed to write copied destination: %v", err)
		}

		// Verify serialized forms are identical
		origBytes := origStream.Bytes()
		copiedBytes := copiedStream.Bytes()

		if !bytes.Equal(origBytes, copiedBytes) {
			t.Errorf("Serialized destinations differ: original %d bytes, copied %d bytes",
				len(origBytes), len(copiedBytes))
		}
	})

	t.Run("Multiple copies are independent", func(t *testing.T) {
		crypto := NewCrypto()
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create original destination: %v", err)
		}

		copy1 := original.Copy()
		copy2 := original.Copy()

		// Verify all three have the same base32 address
		if copy1.b32 != original.b32 {
			t.Errorf("Copy1 base32 mismatch: got %s, want %s", copy1.b32, original.b32)
		}
		if copy2.b32 != original.b32 {
			t.Errorf("Copy2 base32 mismatch: got %s, want %s", copy2.b32, original.b32)
		}
		if copy1.b32 != copy2.b32 {
			t.Errorf("Copies have different base32: %s vs %s", copy1.b32, copy2.b32)
		}
	})
}
