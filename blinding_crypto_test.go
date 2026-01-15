package go_i2cp

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/kdf"
)

// getTestKeys extracts public and private keys from an Ed25519KeyPair for testing.
func getTestKeys(keyPair *Ed25519KeyPair) (publicKey [32]byte, privateKey [64]byte, secret []byte) {
	pubKey := keyPair.PublicKey()
	privKey := keyPair.PrivateKey()
	copy(publicKey[:], pubKey[:])
	copy(privateKey[:], privKey[:])
	secret = privKey[:32]
	return
}

// TestDeriveBlindingFactor tests the basic blinding factor derivation.
func TestDeriveBlindingFactor(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	date := "2025-11-24"

	alpha, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}

	// Verify alpha is non-zero
	var zero [32]byte
	if alpha == zero {
		t.Error("Derived blinding factor is all zeros")
	}

	// Verify deterministic: same inputs produce same output
	alpha2, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Second DeriveBlindingFactor failed: %v", err)
	}
	if alpha != alpha2 {
		t.Error("Blinding factor derivation is not deterministic")
	}

	// Verify different dates produce different factors
	alpha3, err := DeriveBlindingFactor(secret, "2025-11-25")
	if err != nil {
		t.Fatalf("DeriveBlindingFactor with different date failed: %v", err)
	}
	if alpha == alpha3 {
		t.Error("Different dates should produce different blinding factors")
	}
}

// TestDeriveBlindingFactor_InvalidInputs tests error handling for invalid inputs.
func TestDeriveBlindingFactor_InvalidInputs(t *testing.T) {
	validSecret := make([]byte, 32)

	// Test short secret
	shortSecret := make([]byte, 16)
	_, err := DeriveBlindingFactor(shortSecret, "2025-11-24")
	if err == nil {
		t.Error("Expected error for short secret")
	}

	// Test invalid date format
	_, err = DeriveBlindingFactor(validSecret, "invalid-date")
	if err == nil {
		t.Error("Expected error for invalid date format")
	}

	// Test invalid date values
	_, err = DeriveBlindingFactor(validSecret, "2025-02-30")
	if err == nil {
		t.Error("Expected error for invalid date values (Feb 30)")
	}
}

// TestDeriveBlindingFactorForToday tests derivation for current date.
func TestDeriveBlindingFactorForToday(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	alpha, err := DeriveBlindingFactorForToday(secret)
	if err != nil {
		t.Fatalf("DeriveBlindingFactorForToday failed: %v", err)
	}

	// Verify non-zero
	var zero [32]byte
	if alpha == zero {
		t.Error("Derived blinding factor is all zeros")
	}

	// Verify matches manual derivation with today's date
	today := GetCurrentBlindingDate()
	alpha2, err := DeriveBlindingFactor(secret, today)
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}
	if alpha != alpha2 {
		t.Error("DeriveBlindingFactorForToday doesn't match manual derivation with today's date")
	}
}

// TestDeriveBlindingFactorWithTimestamp tests timestamp-based derivation.
func TestDeriveBlindingFactorWithTimestamp(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	// Use a known timestamp (2024-11-24 12:00:00 UTC)
	timestamp := int64(1732449600)

	alpha, err := DeriveBlindingFactorWithTimestamp(secret, timestamp)
	if err != nil {
		t.Fatalf("DeriveBlindingFactorWithTimestamp failed: %v", err)
	}

	// Verify matches date-based derivation (timestamp is 2024-11-24)
	alpha2, err := DeriveBlindingFactor(secret, "2024-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}
	if alpha != alpha2 {
		t.Error("Timestamp-based derivation doesn't match date-based derivation")
	}
}

// TestBlindPublicKey tests public key blinding.
func TestBlindPublicKey(t *testing.T) {
	// Generate a test Ed25519 key pair
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, _, secret := getTestKeys(keyPair)

	// Derive blinding factor
	alpha, err := DeriveBlindingFactor(secret, "2025-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}

	// Blind the public key
	blindedPubKey, err := BlindPublicKey(publicKey, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	// Verify blinded key is different from original
	if blindedPubKey == publicKey {
		t.Error("Blinded public key should be different from original")
	}

	// Verify deterministic
	blindedPubKey2, err := BlindPublicKey(publicKey, alpha)
	if err != nil {
		t.Fatalf("Second BlindPublicKey failed: %v", err)
	}
	if blindedPubKey != blindedPubKey2 {
		t.Error("Public key blinding is not deterministic")
	}
}

// TestBlindUnblindRoundTrip tests that unblinding reverses blinding.
func TestBlindUnblindRoundTrip(t *testing.T) {
	// Generate a test Ed25519 key pair
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, _, secret := getTestKeys(keyPair)

	// Derive blinding factor
	alpha, err := DeriveBlindingFactor(secret, "2025-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}

	// Blind then unblind
	blindedPubKey, err := BlindPublicKey(publicKey, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	recoveredPubKey, err := UnblindPublicKey(blindedPubKey, alpha)
	if err != nil {
		t.Fatalf("UnblindPublicKey failed: %v", err)
	}

	if recoveredPubKey != publicKey {
		t.Error("Unblinded public key doesn't match original")
	}
}

// TestDeriveBlindingKeys tests the convenience function for deriving blinding keys.
func TestDeriveBlindingKeys(t *testing.T) {
	// Generate a test Ed25519 key pair
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, _, secret := getTestKeys(keyPair)

	// Test with explicit date
	result, err := DeriveBlindingKeys(secret, publicKey, "2025-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingKeys failed: %v", err)
	}

	if result.Date != "2025-11-24" {
		t.Errorf("Expected date 2025-11-24, got %s", result.Date)
	}
	if result.HasPrivateKey {
		t.Error("Expected HasPrivateKey to be false")
	}

	var zero [32]byte
	if result.Alpha == zero {
		t.Error("Alpha should not be zero")
	}
	if result.BlindedPublicKey == zero {
		t.Error("BlindedPublicKey should not be zero")
	}

	// Test with empty date (uses today)
	result2, err := DeriveBlindingKeys(secret, publicKey, "")
	if err != nil {
		t.Fatalf("DeriveBlindingKeys with empty date failed: %v", err)
	}

	if result2.Date != GetCurrentBlindingDate() {
		t.Errorf("Expected today's date %s, got %s", GetCurrentBlindingDate(), result2.Date)
	}
}

// TestDeriveBlindingKeysWithPrivate tests derivation including private key blinding.
func TestDeriveBlindingKeysWithPrivate(t *testing.T) {
	// Generate a test Ed25519 key pair
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, privateKey, secret := getTestKeys(keyPair)

	result, err := DeriveBlindingKeysWithPrivate(secret, publicKey, privateKey, "2025-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingKeysWithPrivate failed: %v", err)
	}

	if !result.HasPrivateKey {
		t.Error("Expected HasPrivateKey to be true")
	}

	var zero64 [64]byte
	if result.BlindedPrivateKey == zero64 {
		t.Error("BlindedPrivateKey should not be zero")
	}
}

// TestVerifyBlindedDestination tests blinded destination verification.
func TestVerifyBlindedDestination(t *testing.T) {
	// Generate a test Ed25519 key pair
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, _, secret := getTestKeys(keyPair)

	alpha, err := DeriveBlindingFactor(secret, "2025-11-24")
	if err != nil {
		t.Fatalf("DeriveBlindingFactor failed: %v", err)
	}

	blindedPubKey, err := BlindPublicKey(publicKey, alpha)
	if err != nil {
		t.Fatalf("BlindPublicKey failed: %v", err)
	}

	// Verify correct blinded key
	if !VerifyBlindedDestination(blindedPubKey, publicKey, alpha) {
		t.Error("VerifyBlindedDestination returned false for valid blinded key")
	}

	// Verify wrong public key fails
	var wrongPubKey [32]byte
	wrongPubKey[0] = 0xFF
	if VerifyBlindedDestination(blindedPubKey, wrongPubKey, alpha) {
		t.Error("VerifyBlindedDestination returned true for wrong public key")
	}

	// Verify wrong alpha fails
	var wrongAlpha [32]byte
	wrongAlpha[0] = 0xFF
	if VerifyBlindedDestination(blindedPubKey, publicKey, wrongAlpha) {
		t.Error("VerifyBlindedDestination returned true for wrong alpha")
	}
}

// TestGetCurrentBlindingDate tests date formatting.
func TestGetCurrentBlindingDate(t *testing.T) {
	date := GetCurrentBlindingDate()

	// Verify format is YYYY-MM-DD (10 characters)
	if len(date) != 10 {
		t.Errorf("Expected date length 10, got %d", len(date))
	}

	// Verify it can be parsed
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		t.Errorf("GetCurrentBlindingDate returned unparseable date: %v", err)
	}
}

// TestFormatDateForBlinding tests date formatting function.
func TestFormatDateForBlinding(t *testing.T) {
	// Test a known timestamp
	testTime := time.Date(2025, 11, 24, 12, 0, 0, 0, time.UTC)
	date := FormatDateForBlinding(testTime)

	if date != "2025-11-24" {
		t.Errorf("Expected 2025-11-24, got %s", date)
	}

	// Test timezone handling (should convert to UTC)
	loc, _ := time.LoadLocation("America/New_York")
	testTimeEST := time.Date(2025, 11, 24, 23, 0, 0, 0, loc)
	dateEST := FormatDateForBlinding(testTimeEST)

	// 23:00 EST is 04:00 UTC next day
	if dateEST != "2025-11-25" {
		t.Errorf("Expected 2025-11-25 (UTC conversion), got %s", dateEST)
	}
}

// TestSessionStoreBlindingInfo tests storing blinding info in a session.
func TestSessionStoreBlindingInfo(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	// Store blinding info
	params := []byte{0x01, 0x02, 0x03, 0x04}
	session.StoreBlindingInfo(1, 0x0002, params)

	// Verify stored values
	if session.BlindingScheme() != 1 {
		t.Errorf("Expected scheme 1, got %d", session.BlindingScheme())
	}
	if session.BlindingFlags() != 0x0002 {
		t.Errorf("Expected flags 0x0002, got 0x%04x", session.BlindingFlags())
	}
	storedParams := session.BlindingParams()
	if !bytes.Equal(storedParams, params) {
		t.Errorf("Expected params %v, got %v", params, storedParams)
	}

	// Verify params are copied
	params[0] = 0xFF
	if session.BlindingParams()[0] == 0xFF {
		t.Error("StoreBlindingInfo should copy params, not store reference")
	}
}

// TestSessionStoreBlindingInfo_NilParams tests storing nil params.
func TestSessionStoreBlindingInfo_NilParams(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	// Store with non-nil params first
	session.StoreBlindingInfo(1, 0x0001, []byte{0x01, 0x02})

	// Then store with nil params
	session.StoreBlindingInfo(2, 0x0002, nil)

	if session.BlindingParams() != nil {
		t.Error("Expected nil params after storing nil")
	}
	if session.BlindingScheme() != 2 {
		t.Errorf("Expected scheme 2, got %d", session.BlindingScheme())
	}
}

// TestBlindingCrypto_Integration tests the full blinding workflow.
func TestBlindingCrypto_Integration(t *testing.T) {
	// Simulate a service creating a blinded destination

	// 1. Service generates a destination
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		t.Fatalf("Failed to get signing key pair: %v", err)
	}

	publicKey, privateKey, secret := getTestKeys(keyPair)
	date := "2025-11-24"

	// 2. Service derives blinding keys for the day
	serviceKeys, err := DeriveBlindingKeysWithPrivate(secret, publicKey, privateKey, date)
	if err != nil {
		t.Fatalf("Service DeriveBlindingKeysWithPrivate failed: %v", err)
	}

	// 3. Client also derives the blinding factor from shared secret
	// (In practice, client would derive from destination's known public info)
	clientAlpha, err := DeriveBlindingFactor(secret, date)
	if err != nil {
		t.Fatalf("Client DeriveBlindingFactor failed: %v", err)
	}

	// 4. Client blinds the known public key
	clientBlindedPubKey, err := BlindPublicKey(publicKey, clientAlpha)
	if err != nil {
		t.Fatalf("Client BlindPublicKey failed: %v", err)
	}

	// 5. Verify both sides derived the same blinded public key
	if serviceKeys.BlindedPublicKey != clientBlindedPubKey {
		t.Error("Service and client derived different blinded public keys")
	}

	// 6. Verify the blinded destination can be verified
	if !VerifyBlindedDestination(serviceKeys.BlindedPublicKey, publicKey, serviceKeys.Alpha) {
		t.Error("Failed to verify blinded destination")
	}
}

// BenchmarkDeriveBlindingFactor benchmarks blinding factor derivation.
func BenchmarkDeriveBlindingFactor(b *testing.B) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	date := kdf.GetCurrentBlindingDate()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveBlindingFactor(secret, date)
	}
}

// BenchmarkBlindPublicKey benchmarks public key blinding.
func BenchmarkBlindPublicKey(b *testing.B) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, _ := dest.SigningKeyPair()
	publicKey, _, secret := getTestKeys(keyPair)
	alpha, _ := DeriveBlindingFactor(secret, "2025-11-24")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = BlindPublicKey(publicKey, alpha)
	}
}

// BenchmarkDeriveBlindingKeys benchmarks the full key derivation.
func BenchmarkDeriveBlindingKeys(b *testing.B) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		b.Fatalf("Failed to create destination: %v", err)
	}

	keyPair, _ := dest.SigningKeyPair()
	publicKey, _, secret := getTestKeys(keyPair)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeriveBlindingKeys(secret, publicKey, "2025-11-24")
	}
}
