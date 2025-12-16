package go_i2cp

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestManualSignatureVerification(t *testing.T) {
	// Data from the actual test run
	dataHex := "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e6990a705b4994790e3f90feed34f78623de8d854baede9e69942f5db241194805000400070000005010693263702e66617374526563656976653d04747275653b14693263702e6c65617365536574456e63547970653d01343b17693263702e6d65737361676552656c696162696c6974793d046e6f6e653b0000019b24342d38"
	signatureHex := "56dfce8f8975122b9bab5f8ec1604d3fffc2ee777cb9a681fd8cbaa4f53489a6dd7576f5964d94cc725430204537d054dce41fc57add3c480a003456a60aa502"
	publicKeyHex := "e6990a705b4994790e3f90feed34f78623de8d854baede9e69942f5db2411948"

	data, err := hex.DecodeString(dataHex)
	if err != nil {
		t.Fatalf("Failed to decode data: %v", err)
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	t.Logf("Data length: %d bytes", len(data))
	t.Logf("Signature length: %d bytes", len(signature))
	t.Logf("Public key length: %d bytes", len(publicKey))

	// Verify the signature
	verified := ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)

	if verified {
		t.Log("✓ Signature verification PASSED - signature is mathematically valid!")
	} else {
		t.Error("✗ Signature verification FAILED - this means there's a bug in our signing")
	}
}
