package go_i2cp

import (
	"testing"
)

// TestWriteMappingDeterministic verifies that calling writeMappingToMessage multiple times
// produces identical byte output
func TestWriteMappingDeterministic(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, "4")
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	// Write properties multiple times
	stream1 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream1); err != nil {
		t.Fatalf("Failed to write mapping (attempt 1): %v", err)
	}

	stream2 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream2); err != nil {
		t.Fatalf("Failed to write mapping (attempt 2): %v", err)
	}

	stream3 := NewStream(make([]byte, 0, 256))
	if err := config.writeMappingToMessage(stream3); err != nil {
		t.Fatalf("Failed to write mapping (attempt 3): %v", err)
	}

	// Compare bytes
	bytes1 := stream1.Bytes()
	bytes2 := stream2.Bytes()
	bytes3 := stream3.Bytes()

	t.Logf("Attempt 1: %d bytes: %x", len(bytes1), bytes1)
	t.Logf("Attempt 2: %d bytes: %x", len(bytes2), bytes2)
	t.Logf("Attempt 3: %d bytes: %x", len(bytes3), bytes3)

	if string(bytes1) != string(bytes2) {
		t.Fatal("Properties bytes differ between attempt 1 and 2!")
	}

	if string(bytes1) != string(bytes3) {
		t.Fatal("Properties bytes differ between attempt 1 and 3!")
	}

	t.Log("All attempts produced identical bytes ✓")
}
