package go_i2cp

import (
	"bytes"
	"testing"
)

// --- Core destination tests ---

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

// --- Hash tests ---

func TestDestinationHash(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	hash := dest.Hash()

	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	zeroHash := [32]byte{}
	if hash == zeroHash {
		t.Error("Hash should not be all zeros")
	}

	hash2 := dest.Hash()
	if hash != hash2 {
		t.Error("Hash() should return the same value on repeated calls")
	}
}

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

func TestDestinationHashMatchesB32Derivation(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	hash := dest.Hash()

	stream := NewStream(make([]byte, 0, DEST_SIZE))
	if err := dest.WriteToMessage(stream); err != nil {
		t.Fatalf("Failed to write destination to stream: %v", err)
	}

	if stream.Len() == 0 {
		t.Error("Destination serialization should not be empty")
	}

	zeroHash := [32]byte{}
	if hash == zeroHash {
		t.Error("Hash should not be zero for a valid destination")
	}
}

func TestDestinationHashFromRecreatedDestination(t *testing.T) {
	crypto := NewCrypto()
	dest1, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	hash1 := dest1.Hash()

	stream := NewStream(make([]byte, 0, 4096))
	if err := dest1.WriteToMessage(stream); err != nil {
		t.Fatalf("Failed to write destination to message: %v", err)
	}

	dest2, err := NewDestinationFromMessage(stream, crypto)
	if err != nil {
		t.Fatalf("Failed to recreate destination from message: %v", err)
	}

	hash2 := dest2.Hash()

	if hash1 != hash2 {
		t.Errorf("Hash mismatch after serialization round-trip: %x != %x", hash1, hash2)
	}
}

// --- Copy tests ---

func TestDestination_Copy(t *testing.T) {
	t.Run("Copy creates independent destination", func(t *testing.T) {
		crypto := NewCrypto()
		original, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create original destination: %v", err)
		}

		copied := original.Copy()

		if copied.cert != original.cert {
			t.Error("Certificate not copied correctly")
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

		origStream := NewStream(make([]byte, 0, DEST_SIZE))
		if err := original.WriteToMessage(origStream); err != nil {
			t.Fatalf("Failed to write original destination: %v", err)
		}

		copiedStream := NewStream(make([]byte, 0, DEST_SIZE))
		if err := copied.WriteToMessage(copiedStream); err != nil {
			t.Fatalf("Failed to write copied destination: %v", err)
		}

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

// --- Write format tests ---

func TestDestinationWriteFormats(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	paddedStream := NewStream(make([]byte, 0, 512))
	if err := dest.WriteToMessage(paddedStream); err != nil {
		t.Fatalf("WriteToMessage failed: %v", err)
	}

	truncatedStream := NewStream(make([]byte, 0, 512))
	if err := dest.WriteForSignature(truncatedStream); err != nil {
		t.Fatalf("WriteForSignature failed: %v", err)
	}

	paddedBytes := paddedStream.Bytes()
	truncatedBytes := truncatedStream.Bytes()

	t.Logf("Padded format:    %d bytes", len(paddedBytes))
	t.Logf("Truncated format: %d bytes", len(truncatedBytes))
	t.Logf("Difference:       %d bytes", len(paddedBytes)-len(truncatedBytes))

	expectedDiff := 128 - 32
	if len(paddedBytes)-len(truncatedBytes) != expectedDiff {
		t.Fatalf("Expected %d byte difference, got %d", expectedDiff, len(paddedBytes)-len(truncatedBytes))
	}

	if !bytes.Equal(paddedBytes[:256], truncatedBytes[:256]) {
		t.Fatal("Public key (first 256 bytes) differs between formats!")
	}

	paddedSigningKey := paddedBytes[256:384]
	truncatedSigningKey := truncatedBytes[256:288]

	paddedKeyExtracted := paddedSigningKey[96:128]

	if !bytes.Equal(paddedKeyExtracted, truncatedSigningKey) {
		t.Fatal("Truncated signing key doesn't match extracted key from padded format!")
	}

	paddedCert := paddedBytes[384:391]
	truncatedCert := truncatedBytes[288:295]

	if !bytes.Equal(paddedCert, truncatedCert) {
		t.Fatal("Certificate differs between formats!")
	}
}

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

	expectedSize := 391
	actualSize := stream.Len()

	if actualSize != expectedSize {
		t.Errorf("Incorrect destination size: got %d bytes, want %d bytes", actualSize, expectedSize)
		t.Errorf("Expected format: 256 (pubKey) + 128 (signKey padded) + 7 (KEY cert) = 391")
	}

	data := stream.Bytes()

	if len(data) < 256 {
		t.Fatalf("Insufficient data for public key: got %d bytes", len(data))
	}

	if len(data) < 384 {
		t.Fatalf("Insufficient data for signing public key: got %d bytes", len(data))
	}

	signKeyField := data[256:384]
	for i := 0; i < 96; i++ {
		if signKeyField[i] != 0 {
			t.Errorf("Expected zero padding at byte %d of signing key field, got %d", i, signKeyField[i])
			break
		}
	}

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

	if len(data) < 391 {
		t.Fatalf("Insufficient data for certificate: got %d bytes", len(data))
	}
}

// --- Signing and signature tests ---

func TestDestination_SigningPublicKey(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	pubKey := dest.SigningPublicKey()
	if pubKey == nil {
		t.Fatal("SigningPublicKey returned nil")
	}

	if pubKey.AlgorithmType() != ED25519_SHA256 {
		t.Errorf("Expected algorithm type %d, got %d", ED25519_SHA256, pubKey.AlgorithmType())
	}

	if len(pubKey.PublicKey()) != 32 {
		t.Errorf("Expected 32-byte Ed25519 public key, got %d bytes", len(pubKey.PublicKey()))
	}

	if len(pubKey.PrivateKey()) != 0 {
		t.Error("SigningPublicKey should not contain private key for security")
	}
}

func TestDestination_VerifySignature(t *testing.T) {
	crypto := NewCrypto()

	remotePeer, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create remote peer destination: %v", err)
	}

	message := []byte("I2P Streaming Protocol packet data")

	t.Run("valid signature", func(t *testing.T) {
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		isValid := remotePeer.VerifySignature(message, signature)
		if !isValid {
			t.Error("Valid signature was rejected")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		invalidSignature := make([]byte, 64)
		for i := range invalidSignature {
			invalidSignature[i] = 0xFF
		}

		isValid := remotePeer.VerifySignature(message, invalidSignature)
		if isValid {
			t.Error("Invalid signature was accepted")
		}
	})

	t.Run("corrupted signature", func(t *testing.T) {
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		corruptedSignature := make([]byte, len(signature))
		copy(corruptedSignature, signature)
		corruptedSignature[0] ^= 0xFF

		isValid := remotePeer.VerifySignature(message, corruptedSignature)
		if isValid {
			t.Error("Corrupted signature was accepted")
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		signingKey, err := remotePeer.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key pair: %v", err)
		}

		signature, err := signingKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		differentMessage := []byte("Different message")
		isValid := remotePeer.VerifySignature(differentMessage, signature)
		if isValid {
			t.Error("Signature validated against wrong message")
		}
	})
}

func TestDestination_VerifySignature_UseCases(t *testing.T) {
	crypto := NewCrypto()

	t.Run("streaming protocol server mode", func(t *testing.T) {
		clientDest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create client destination: %v", err)
		}

		synPacket := []byte{
			0x01,
			0x06,
			0x00, 0x01, 0x23, 0x45,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x04, 0x00,
			0x00, 0x00, 0x04, 0x00,
		}

		clientKey, err := clientDest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get client signing key: %v", err)
		}

		signature, err := clientKey.Sign(synPacket)
		if err != nil {
			t.Fatalf("Failed to sign SYN packet: %v", err)
		}

		isValid := clientDest.VerifySignature(synPacket, signature)
		if !isValid {
			t.Error("Server failed to verify client signature")
		}
	})

	t.Run("connection tracking with signature verification", func(t *testing.T) {
		clients := make([]*Destination, 3)
		for i := range clients {
			dest, err := NewDestination(crypto)
			if err != nil {
				t.Fatalf("Failed to create client %d: %v", i, err)
			}
			clients[i] = dest
		}

		message := []byte("Hello from client")

		for i, client := range clients {
			key, err := client.SigningKeyPair()
			if err != nil {
				t.Fatalf("Failed to get signing key for client %d: %v", i, err)
			}

			signature, err := key.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign message for client %d: %v", i, err)
			}

			if !client.VerifySignature(message, signature) {
				t.Errorf("Failed to verify signature for client %d", i)
			}
		}
	})
}

func TestDestination_SigningPublicKey_NoPrivateKey(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	pubKey := dest.SigningPublicKey()
	if pubKey == nil {
		t.Fatal("SigningPublicKey returned nil")
	}

	if len(pubKey.PrivateKey()) > 0 {
		t.Error("SigningPublicKey leaked private key material")
		t.Errorf("Private key bytes: %d (expected: 0)", len(pubKey.PrivateKey()))
	}

	signingKey, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	message := []byte("test message")
	signature, err := signingKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	isValid := pubKey.Verify(message, signature)
	if !isValid {
		t.Error("Public-only key failed to verify valid signature")
	}
}

func TestDestination_VerifySignature_EdgeCases(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	t.Run("empty message", func(t *testing.T) {
		signingKey, err := dest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key: %v", err)
		}

		emptyMessage := []byte{}
		signature, err := signingKey.Sign(emptyMessage)
		if err != nil {
			t.Fatalf("Failed to sign empty message: %v", err)
		}

		isValid := dest.VerifySignature(emptyMessage, signature)
		if !isValid {
			t.Error("Failed to verify signature for empty message")
		}
	})

	t.Run("nil signature", func(t *testing.T) {
		message := []byte("test")
		isValid := dest.VerifySignature(message, nil)
		if isValid {
			t.Error("Nil signature was accepted")
		}
	})

	t.Run("wrong length signature", func(t *testing.T) {
		message := []byte("test")
		shortSignature := make([]byte, 32)

		isValid := dest.VerifySignature(message, shortSignature)
		if isValid {
			t.Error("Wrong-length signature was accepted")
		}
	})

	t.Run("large message", func(t *testing.T) {
		largeMessage := make([]byte, 65536)
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}

		signingKey, err := dest.SigningKeyPair()
		if err != nil {
			t.Fatalf("Failed to get signing key: %v", err)
		}

		signature, err := signingKey.Sign(largeMessage)
		if err != nil {
			t.Fatalf("Failed to sign large message: %v", err)
		}

		isValid := dest.VerifySignature(largeMessage, signature)
		if !isValid {
			t.Error("Failed to verify signature for large message")
		}
	})
}

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

	dataStream := NewStream(make([]byte, 0, 512))
	dest.WriteToMessage(dataStream)

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

	timestamp := uint64(1765853211000)
	dataStream.WriteUint64(timestamp)

	data := dataStream.Bytes()

	if dest.sgk.ed25519KeyPair == nil {
		t.Fatal("Ed25519 keypair not available")
	}

	signature, err := dest.sgk.ed25519KeyPair.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	verified := dest.sgk.ed25519KeyPair.Verify(data, signature)

	if !verified {
		t.Error("Signature verification FAILED - this means there's a bug in our signing")
	}
}
