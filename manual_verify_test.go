package go_i2cp

import (
	"testing"
)

// TestManualSignatureVerification verifies that the signature we generate can be verified
// using the same format. This test generates fresh data each time rather than using
// hardcoded hex values that may become outdated.
func TestManualSignatureVerification(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	config := &SessionConfig{
		destination: dest,
	}
	config.properties[SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE] = "true"
	config.properties[SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY] = "none"
	config.properties[SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE] = "4"

	// Generate the signature data using WriteToMessage (padded format)
	// This is the format that Java I2P expects when it reconstructs for verification
	dataStream := NewStream(make([]byte, 0, 512))
	dest.WriteToMessage(dataStream)

	// Write properties mapping
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
	dataStream.WriteMapping(m)

	// Write timestamp
	timestamp := uint64(1765853211000) // Example timestamp
	dataStream.WriteUint64(timestamp)

	data := dataStream.Bytes()
	t.Logf("Data length: %d bytes", len(data))

	// Sign the data
	if dest.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available")
	}

	signature, err := dest.sgk.ed25519KeyPair.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	t.Logf("Signature length: %d bytes", len(signature))

	// Verify the signature
	verified := dest.sgk.ed25519KeyPair.Verify(data, signature)

	if verified {
		t.Log("✓ Signature verification PASSED - signature is mathematically valid!")
	} else {
		t.Error("✗ Signature verification FAILED - this means there's a bug in our signing")
	}
}
