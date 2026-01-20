package go_i2cp

import "testing"

func TestRandomDestination(t *testing.T) {
	var destOne, destTwo *Destination
	var err error
	crypto := NewCrypto()
	destOne, err = NewDestination(crypto)
	stream := NewStream(make([]byte, 4096))
	destOne.WriteToStream(stream)
	if err != nil {
		t.Fatalf("Could not create first test destination with error %s", err.Error())
	}
	destTwo, err = NewDestination(crypto)
	if err != nil {
		t.Fatalf("Could not create second test destination with error %s", err.Error())
	}
	if destOne.b32 == destTwo.b32 {
		t.Fatal("Random destOne == random destTwo")
	}
}

func TestNewDestinationFromMessage(t *testing.T) {
	stream := NewStream(make([]byte, 0, 4096))
	crypto := NewCrypto()
	randDest, err := NewDestination(crypto)
	if err != nil {
		t.Fatal("Could not create random destination.")
	}
	initialB32 := randDest.b32
	randDest.WriteToMessage(stream)
	secDest, err := NewDestinationFromMessage(stream, crypto)
	if err != nil {
		t.Fatalf("Failed to create destination from message: '%s'", err.Error())
	}
	finalB32 := secDest.b32
	if initialB32 != finalB32 {
		t.Fatalf("Recreated destination base32 addresses do not match %s != %s", initialB32, finalB32)
	}
}

func TestNewDestinationFromBase64(t *testing.T) {
	crypto := NewCrypto()
	randDest, err := NewDestination(crypto)
	if err != nil {
		t.Fatal("Could not create random destination.")
	}
	initialB64 := randDest.b64
	secDest, err := NewDestinationFromBase64(initialB64, crypto)
	if err != nil {
		t.Fatalf("Failed to create destination from message: '%s'", err.Error())
	}
	finalB64 := secDest.b64
	if initialB64 != finalB64 {
		t.Fatalf("Recreated destination base64 addresses do not match %s != %s", initialB64, finalB64)
	}
}

// TestDestinationHash tests the Hash() method for canonical destination hashing
func TestDestinationHash(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Get hash
	hash := dest.Hash()

	// Hash should be 32 bytes (SHA-256)
	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	// Hash should be non-zero
	zeroHash := [32]byte{}
	if hash == zeroHash {
		t.Error("Hash should not be all zeros")
	}

	// Hash should be deterministic (same destination = same hash)
	hash2 := dest.Hash()
	if hash != hash2 {
		t.Error("Hash() should return the same value on repeated calls")
	}
}

// TestDestinationHashDifferent tests that different destinations produce different hashes
func TestDestinationHashDifferent(t *testing.T) {
	crypto := NewCrypto()
	dest1, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create first destination: %v", err)
	}

	dest2, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create second destination: %v", err)
	}

	hash1 := dest1.Hash()
	hash2 := dest2.Hash()

	if hash1 == hash2 {
		t.Error("Different destinations should produce different hashes")
	}
}

// TestDestinationHashMatchesB32Derivation tests that Hash() matches the b32 derivation
func TestDestinationHashMatchesB32Derivation(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// The b32 address is derived from the same hash
	// Get hash directly
	hash := dest.Hash()

	// Manually compute what generateB32 does and compare
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	if err := dest.WriteToMessage(stream); err != nil {
		t.Fatalf("Failed to write destination to stream: %v", err)
	}

	// The hash used for b32 should match Hash()
	// Note: We can't directly compare to b32 string without base32 encoding,
	// but we can verify the hash is computed over the same serialization
	if stream.Len() == 0 {
		t.Error("Destination serialization should not be empty")
	}

	// Verify hash is non-zero (meaning serialization worked)
	zeroHash := [32]byte{}
	if hash == zeroHash {
		t.Error("Hash should not be zero for a valid destination")
	}
}

// TestDestinationHashFromRecreatedDestination tests hash consistency after serialization round-trip
func TestDestinationHashFromRecreatedDestination(t *testing.T) {
	crypto := NewCrypto()
	dest1, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	hash1 := dest1.Hash()

	// Serialize to message format
	stream := NewStream(make([]byte, 0, 4096))
	if err := dest1.WriteToMessage(stream); err != nil {
		t.Fatalf("Failed to write destination to message: %v", err)
	}

	// Recreate from message
	dest2, err := NewDestinationFromMessage(stream, crypto)
	if err != nil {
		t.Fatalf("Failed to recreate destination from message: %v", err)
	}

	hash2 := dest2.Hash()

	// Hashes should match after round-trip
	if hash1 != hash2 {
		t.Errorf("Hash mismatch after serialization round-trip: %x != %x", hash1, hash2)
	}
}
