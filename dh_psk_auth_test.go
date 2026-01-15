package go_i2cp

import (
	"bytes"
	"testing"
)

// TestDHAuthenticator_Basic tests basic DH authentication.
func TestDHAuthenticator_Basic(t *testing.T) {
	// Generate client key pair
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	// Generate server key pair
	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	// Create DH authenticator
	auth := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())

	// Perform authentication
	result, err := auth.Authenticate()
	if err != nil {
		t.Fatalf("DH authentication failed: %v", err)
	}

	// Verify result
	if result.Scheme != BLINDING_AUTH_SCHEME_DH {
		t.Errorf("Expected scheme %d, got %d", BLINDING_AUTH_SCHEME_DH, result.Scheme)
	}

	var zero [32]byte
	if result.DecryptionKey == zero {
		t.Error("DecryptionKey should not be zero")
	}
	if result.SharedSecret == zero {
		t.Error("SharedSecret should not be zero")
	}
}

// TestDHAuthenticator_Deterministic tests that DH produces consistent results.
func TestDHAuthenticator_Deterministic(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	auth1 := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	result1, err := auth1.Authenticate()
	if err != nil {
		t.Fatalf("First authentication failed: %v", err)
	}

	auth2 := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	result2, err := auth2.Authenticate()
	if err != nil {
		t.Fatalf("Second authentication failed: %v", err)
	}

	if result1.DecryptionKey != result2.DecryptionKey {
		t.Error("DH authentication should be deterministic")
	}
	if result1.SharedSecret != result2.SharedSecret {
		t.Error("DH shared secret should be deterministic")
	}
}

// TestDHAuthenticator_InvalidServerKey tests that invalid server keys are rejected.
func TestDHAuthenticator_InvalidServerKey(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	// All-zero server key
	var zeroKey [32]byte
	auth := NewDHAuthenticator(clientKeyPair.PrivateKey(), zeroKey)

	_, err = auth.Authenticate()
	if err == nil {
		t.Error("Expected error for zero server public key")
	}
}

// TestDHAuthenticator_WithSaltAndInfo tests custom salt and info.
func TestDHAuthenticator_WithSaltAndInfo(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	salt := []byte("custom-salt")
	info := []byte("custom-info")

	auth := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey()).
		WithSalt(salt).
		WithInfo(info)

	result, err := auth.Authenticate()
	if err != nil {
		t.Fatalf("DH authentication failed: %v", err)
	}

	// Different salt/info should produce different key
	auth2 := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	result2, err := auth2.Authenticate()
	if err != nil {
		t.Fatalf("Default authentication failed: %v", err)
	}

	if result.DecryptionKey == result2.DecryptionKey {
		t.Error("Different salt/info should produce different decryption key")
	}
	// But shared secret should be the same (DH is independent of HKDF params)
	if result.SharedSecret != result2.SharedSecret {
		t.Error("DH shared secret should be independent of HKDF params")
	}
}

// TestPSKAuthenticator_Basic tests basic PSK authentication.
func TestPSKAuthenticator_Basic(t *testing.T) {
	// Create a test PSK
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	auth := NewPSKAuthenticator(psk)
	result, err := auth.Authenticate()
	if err != nil {
		t.Fatalf("PSK authentication failed: %v", err)
	}

	if result.Scheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("Expected scheme %d, got %d", BLINDING_AUTH_SCHEME_PSK, result.Scheme)
	}

	var zero [32]byte
	if result.DecryptionKey == zero {
		t.Error("DecryptionKey should not be zero")
	}
	// SharedSecret should be zero for PSK
	if result.SharedSecret != zero {
		t.Error("SharedSecret should be zero for PSK")
	}
}

// TestPSKAuthenticator_Deterministic tests that PSK produces consistent results.
func TestPSKAuthenticator_Deterministic(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	auth1 := NewPSKAuthenticator(psk)
	result1, err := auth1.Authenticate()
	if err != nil {
		t.Fatalf("First authentication failed: %v", err)
	}

	auth2 := NewPSKAuthenticator(psk)
	result2, err := auth2.Authenticate()
	if err != nil {
		t.Fatalf("Second authentication failed: %v", err)
	}

	if result1.DecryptionKey != result2.DecryptionKey {
		t.Error("PSK authentication should be deterministic")
	}
}

// TestPSKAuthenticator_ZeroKeyRejected tests that zero PSK is rejected.
func TestPSKAuthenticator_ZeroKeyRejected(t *testing.T) {
	var zeroPSK [32]byte
	auth := NewPSKAuthenticator(zeroPSK)

	_, err := auth.Authenticate()
	if err == nil {
		t.Error("Expected error for zero PSK")
	}
}

// TestPSKAuthenticator_WithSaltAndInfo tests custom salt and info.
func TestPSKAuthenticator_WithSaltAndInfo(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	salt := []byte("custom-salt")
	info := []byte("custom-info")

	auth := NewPSKAuthenticator(psk).WithSalt(salt).WithInfo(info)
	result, err := auth.Authenticate()
	if err != nil {
		t.Fatalf("PSK authentication failed: %v", err)
	}

	// Different salt/info should produce different key
	auth2 := NewPSKAuthenticator(psk)
	result2, err := auth2.Authenticate()
	if err != nil {
		t.Fatalf("Default authentication failed: %v", err)
	}

	if result.DecryptionKey == result2.DecryptionKey {
		t.Error("Different salt/info should produce different decryption key")
	}
}

// TestDerivePerClientAuthKey_DH tests the convenience function for DH.
func TestDerivePerClientAuthKey_DH(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	key, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_DH, clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	if err != nil {
		t.Fatalf("DerivePerClientAuthKey failed: %v", err)
	}

	var zero [32]byte
	if key == zero {
		t.Error("Derived key should not be zero")
	}
}

// TestDerivePerClientAuthKey_PSK tests the convenience function for PSK.
func TestDerivePerClientAuthKey_PSK(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	key, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_PSK, psk, [32]byte{})
	if err != nil {
		t.Fatalf("DerivePerClientAuthKey failed: %v", err)
	}

	var zero [32]byte
	if key == zero {
		t.Error("Derived key should not be zero")
	}
}

// TestDerivePerClientAuthKey_InvalidScheme tests error handling for invalid scheme.
func TestDerivePerClientAuthKey_InvalidScheme(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	_, err := DerivePerClientAuthKey(99, key, [32]byte{})
	if err == nil {
		t.Error("Expected error for invalid scheme")
	}
}

// TestX25519KeyPairFromPrivateKey tests creating key pair from private key.
func TestX25519KeyPairFromPrivateKey(t *testing.T) {
	// Generate a reference key pair
	refKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate reference key pair: %v", err)
	}

	// Create key pair from just the private key
	derivedKeyPair, err := X25519KeyPairFromPrivateKey(refKeyPair.PrivateKey())
	if err != nil {
		t.Fatalf("X25519KeyPairFromPrivateKey failed: %v", err)
	}

	// Public keys should match
	if refKeyPair.PublicKey() != derivedKeyPair.PublicKey() {
		t.Error("Derived public key should match original")
	}
}

// TestCreateDHBlindingInfo tests creating BlindingInfo with DH auth.
func TestCreateDHBlindingInfo(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	destHash := make([]byte, 32)
	for i := range destHash {
		destHash[i] = byte(i)
	}

	info, err := CreateDHBlindingInfo(destHash, clientKeyPair.PrivateKey(), serverKeyPair.PublicKey(), 7, 1000)
	if err != nil {
		t.Fatalf("CreateDHBlindingInfo failed: %v", err)
	}

	if !info.PerClientAuth {
		t.Error("PerClientAuth should be true")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_DH {
		t.Errorf("Expected DH scheme, got %d", info.AuthScheme)
	}
	if len(info.DecryptionKey) != 32 {
		t.Errorf("DecryptionKey should be 32 bytes, got %d", len(info.DecryptionKey))
	}
	if info.BlindedSigType != 7 {
		t.Errorf("Expected sig type 7, got %d", info.BlindedSigType)
	}
	if info.Expiration != 1000 {
		t.Errorf("Expected expiration 1000, got %d", info.Expiration)
	}
}

// TestCreatePSKBlindingInfo tests creating BlindingInfo with PSK auth.
func TestCreatePSKBlindingInfo(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	destHash := make([]byte, 32)
	for i := range destHash {
		destHash[i] = byte(i)
	}

	info, err := CreatePSKBlindingInfo(destHash, psk, 7, 1000)
	if err != nil {
		t.Fatalf("CreatePSKBlindingInfo failed: %v", err)
	}

	if !info.PerClientAuth {
		t.Error("PerClientAuth should be true")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("Expected PSK scheme, got %d", info.AuthScheme)
	}
	if len(info.DecryptionKey) != 32 {
		t.Errorf("DecryptionKey should be 32 bytes, got %d", len(info.DecryptionKey))
	}
}

// TestCreateDHBlindingInfoForHostname tests hostname-based DH blinding info.
func TestCreateDHBlindingInfoForHostname(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	info, err := CreateDHBlindingInfoForHostname("test.b32.i2p", clientKeyPair.PrivateKey(), serverKeyPair.PublicKey(), 7, 1000)
	if err != nil {
		t.Fatalf("CreateDHBlindingInfoForHostname failed: %v", err)
	}

	if info.EndpointType != BLINDING_ENDPOINT_HOSTNAME {
		t.Errorf("Expected hostname endpoint type, got %d", info.EndpointType)
	}
	if string(info.Endpoint) != "test.b32.i2p" {
		t.Errorf("Expected hostname 'test.b32.i2p', got '%s'", string(info.Endpoint))
	}
	if !info.PerClientAuth {
		t.Error("PerClientAuth should be true")
	}
}

// TestCreatePSKBlindingInfoForHostname tests hostname-based PSK blinding info.
func TestCreatePSKBlindingInfoForHostname(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	info, err := CreatePSKBlindingInfoForHostname("test.b32.i2p", psk, 7, 1000)
	if err != nil {
		t.Fatalf("CreatePSKBlindingInfoForHostname failed: %v", err)
	}

	if info.EndpointType != BLINDING_ENDPOINT_HOSTNAME {
		t.Errorf("Expected hostname endpoint type, got %d", info.EndpointType)
	}
	if !info.PerClientAuth {
		t.Error("PerClientAuth should be true")
	}
	if info.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("Expected PSK scheme, got %d", info.AuthScheme)
	}
}

// TestVerifyDHSharedSecret tests DH shared secret verification.
func TestVerifyDHSharedSecret(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	valid, err := VerifyDHSharedSecret(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	if err != nil {
		t.Fatalf("VerifyDHSharedSecret failed: %v", err)
	}
	if !valid {
		t.Error("DH shared secret verification should succeed")
	}
}

// TestVerifyPSKDerivation tests PSK derivation verification.
func TestVerifyPSKDerivation(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	valid, err := VerifyPSKDerivation(psk)
	if err != nil {
		t.Fatalf("VerifyPSKDerivation failed: %v", err)
	}
	if !valid {
		t.Error("PSK derivation verification should succeed")
	}
}

// TestAuthenticateForBlindedDestination_DH tests the session helper for DH.
func TestAuthenticateForBlindedDestination_DH(t *testing.T) {
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	config, err := AuthenticateForBlindedDestination(BLINDING_AUTH_SCHEME_DH, clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	if err != nil {
		t.Fatalf("AuthenticateForBlindedDestination failed: %v", err)
	}

	if config.AuthScheme != BLINDING_AUTH_SCHEME_DH {
		t.Errorf("Expected DH scheme, got %d", config.AuthScheme)
	}

	var zero [32]byte
	if config.PrivateKey == zero {
		t.Error("PrivateKey should contain the derived decryption key")
	}
}

// TestAuthenticateForBlindedDestination_PSK tests the session helper for PSK.
func TestAuthenticateForBlindedDestination_PSK(t *testing.T) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	config, err := AuthenticateForBlindedDestination(BLINDING_AUTH_SCHEME_PSK, psk, [32]byte{})
	if err != nil {
		t.Fatalf("AuthenticateForBlindedDestination failed: %v", err)
	}

	if config.AuthScheme != BLINDING_AUTH_SCHEME_PSK {
		t.Errorf("Expected PSK scheme, got %d", config.AuthScheme)
	}

	var zero [32]byte
	if config.PrivateKey == zero {
		t.Error("PrivateKey should contain the derived decryption key")
	}
}

// TestDH_BidirectionalKeyAgreement tests that both parties derive the same shared secret.
func TestDH_BidirectionalKeyAgreement(t *testing.T) {
	// Generate Alice's key pair
	aliceKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's key pair: %v", err)
	}

	// Generate Bob's key pair
	bobKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	// Alice authenticates to Bob
	aliceAuth := NewDHAuthenticator(aliceKeyPair.PrivateKey(), bobKeyPair.PublicKey())
	aliceResult, err := aliceAuth.Authenticate()
	if err != nil {
		t.Fatalf("Alice's authentication failed: %v", err)
	}

	// Bob authenticates to Alice
	bobAuth := NewDHAuthenticator(bobKeyPair.PrivateKey(), aliceKeyPair.PublicKey())
	bobResult, err := bobAuth.Authenticate()
	if err != nil {
		t.Fatalf("Bob's authentication failed: %v", err)
	}

	// Both should derive the same shared secret
	if aliceResult.SharedSecret != bobResult.SharedSecret {
		t.Error("DH shared secrets should match for bidirectional key agreement")
	}

	// And the same decryption key (since they use the same HKDF params)
	if aliceResult.DecryptionKey != bobResult.DecryptionKey {
		t.Error("DH decryption keys should match for bidirectional key agreement")
	}
}

// TestDeriveAuthKey tests the internal HKDF derivation function.
func TestDeriveAuthKey(t *testing.T) {
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
	}

	salt := []byte("test-salt")
	info := []byte("test-info")

	key1, err := deriveAuthKey(ikm, salt, info)
	if err != nil {
		t.Fatalf("deriveAuthKey failed: %v", err)
	}

	var zero [32]byte
	if key1 == zero {
		t.Error("Derived key should not be zero")
	}

	// Same inputs should produce same output
	key2, err := deriveAuthKey(ikm, salt, info)
	if err != nil {
		t.Fatalf("deriveAuthKey failed: %v", err)
	}
	if key1 != key2 {
		t.Error("HKDF should be deterministic")
	}

	// Different salt should produce different key
	key3, err := deriveAuthKey(ikm, []byte("different-salt"), info)
	if err != nil {
		t.Fatalf("deriveAuthKey failed: %v", err)
	}
	if key1 == key3 {
		t.Error("Different salt should produce different key")
	}
}

// TestELS2AuthInfo tests the default HKDF info string.
func TestELS2AuthInfo(t *testing.T) {
	if ELS2AuthInfo != "ELS2_L1K" {
		t.Errorf("Expected ELS2AuthInfo 'ELS2_L1K', got '%s'", ELS2AuthInfo)
	}
}

// BenchmarkDHAuthentication benchmarks DH authentication.
func BenchmarkDHAuthentication(b *testing.B) {
	clientKeyPair, _ := NewX25519KeyPair()
	serverKeyPair, _ := NewX25519KeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth := NewDHAuthenticator(clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
		_, _ = auth.Authenticate()
	}
}

// BenchmarkPSKAuthentication benchmarks PSK authentication.
func BenchmarkPSKAuthentication(b *testing.B) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth := NewPSKAuthenticator(psk)
		_, _ = auth.Authenticate()
	}
}

// BenchmarkDerivePerClientAuthKey_DH benchmarks the convenience function for DH.
func BenchmarkDerivePerClientAuthKey_DH(b *testing.B) {
	clientKeyPair, _ := NewX25519KeyPair()
	serverKeyPair, _ := NewX25519KeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_DH, clientKeyPair.PrivateKey(), serverKeyPair.PublicKey())
	}
}

// BenchmarkDerivePerClientAuthKey_PSK benchmarks the convenience function for PSK.
func BenchmarkDerivePerClientAuthKey_PSK(b *testing.B) {
	var psk [32]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_PSK, psk, [32]byte{})
	}
}

// TestDHPSKAuth_Integration tests a complete workflow using DH/PSK auth.
func TestDHPSKAuth_Integration(t *testing.T) {
	// Simulate server publishing an encrypted LeaseSet
	// Server generates key pair for per-client auth
	serverKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	// Client generates key pair
	clientKeyPair, err := NewX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	// Server would publish their public key in the b32 address or out-of-band
	serverPubKey := serverKeyPair.PublicKey()

	// Client derives the decryption key for DH auth
	decryptionKey, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_DH, clientKeyPair.PrivateKey(), serverPubKey)
	if err != nil {
		t.Fatalf("Client failed to derive decryption key: %v", err)
	}

	// Create BlindingInfo with the derived key
	destHash := make([]byte, 32)
	for i := range destHash {
		destHash[i] = byte(i)
	}

	blindingInfo, err := NewBlindingInfoWithHash(destHash, 7, 1000)
	if err != nil {
		t.Fatalf("Failed to create BlindingInfo: %v", err)
	}

	blindingInfo.PerClientAuth = true
	blindingInfo.AuthScheme = BLINDING_AUTH_SCHEME_DH
	blindingInfo.DecryptionKey = decryptionKey[:]

	// Verify the BlindingInfo is correctly configured
	if !blindingInfo.IsPerClientAuthEnabled() {
		t.Error("BlindingInfo should have per-client auth enabled")
	}
	if blindingInfo.GetAuthSchemeName() != "DH (Diffie-Hellman)" {
		t.Errorf("Expected 'DH (Diffie-Hellman)', got '%s'", blindingInfo.GetAuthSchemeName())
	}

	// Verify the decryption key would allow server to authenticate client
	// Server derives the same shared secret
	serverAuth := NewDHAuthenticator(serverKeyPair.PrivateKey(), clientKeyPair.PublicKey())
	serverResult, err := serverAuth.Authenticate()
	if err != nil {
		t.Fatalf("Server authentication failed: %v", err)
	}

	// The decryption keys should match
	if !bytes.Equal(decryptionKey[:], serverResult.DecryptionKey[:]) {
		t.Error("Client and server decryption keys should match")
	}
}
