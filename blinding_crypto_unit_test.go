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

// --- merged from blinding_test.go ---

// TestSession_BlindingGettersSetters tests the blinding field getter/setter methods
// per I2CP specification 0.9.43+
func TestSession_BlindingGettersSetters(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	// Test initial state (blinding disabled)
	if session.BlindingScheme() != 0 {
		t.Errorf("Expected initial blinding scheme 0, got %d", session.BlindingScheme())
	}
	if session.BlindingFlags() != 0 {
		t.Errorf("Expected initial blinding flags 0, got %d", session.BlindingFlags())
	}
	if session.BlindingParams() != nil {
		t.Errorf("Expected initial blinding params nil, got %v", session.BlindingParams())
	}
	if session.IsBlindingEnabled() {
		t.Error("Expected blinding to be disabled initially")
	}

	// Test SetBlindingScheme
	session.SetBlindingScheme(1)
	if scheme := session.BlindingScheme(); scheme != 1 {
		t.Errorf("Expected blinding scheme 1, got %d", scheme)
	}
	if !session.IsBlindingEnabled() {
		t.Error("Expected blinding to be enabled after setting scheme")
	}

	// Test SetBlindingFlags
	session.SetBlindingFlags(0x0002)
	if flags := session.BlindingFlags(); flags != 0x0002 {
		t.Errorf("Expected blinding flags 0x0002, got 0x%04x", flags)
	}

	// Test SetBlindingParams
	testParams := []byte{0x01, 0x02, 0x03, 0x04}
	session.SetBlindingParams(testParams)
	params := session.BlindingParams()
	if len(params) != len(testParams) {
		t.Errorf("Expected params length %d, got %d", len(testParams), len(params))
	}
	for i := range testParams {
		if params[i] != testParams[i] {
			t.Errorf("Expected params[%d] = 0x%02x, got 0x%02x", i, testParams[i], params[i])
		}
	}

	// Verify params are copied (not same slice)
	params[0] = 0xFF
	if session.BlindingParams()[0] == 0xFF {
		t.Error("BlindingParams should return a copy, not the original slice")
	}

	// Test SetBlindingParams with nil
	session.SetBlindingParams(nil)
	if session.BlindingParams() != nil {
		t.Error("Expected blinding params to be nil after setting to nil")
	}

	// Test ClearBlinding
	session.SetBlindingScheme(5)
	session.SetBlindingFlags(0x1234)
	session.SetBlindingParams([]byte{0xAA, 0xBB})
	session.ClearBlinding()

	if session.BlindingScheme() != 0 {
		t.Errorf("Expected blinding scheme 0 after clear, got %d", session.BlindingScheme())
	}
	if session.BlindingFlags() != 0 {
		t.Errorf("Expected blinding flags 0 after clear, got %d", session.BlindingFlags())
	}
	if session.BlindingParams() != nil {
		t.Errorf("Expected blinding params nil after clear, got %v", session.BlindingParams())
	}
	if session.IsBlindingEnabled() {
		t.Error("Expected blinding to be disabled after clear")
	}
}

// TestSession_BlindingConcurrency tests thread-safety of blinding operations
// per I2CP specification 0.9.43+
func TestSession_BlindingConcurrency(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{})

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writes
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingScheme(uint16(i % 10))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingFlags(uint16(i % 100))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			session.SetBlindingParams([]byte{byte(i), byte(i + 1)})
		}
	}()

	// Concurrent reads
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingScheme()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingFlags()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.BlindingParams()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = session.IsBlindingEnabled()
		}
	}()

	wg.Wait()
	// If we reach here without race detector errors, test passes
}

// TestDispatchBlindingInfo tests the blinding info dispatch method
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo(t *testing.T) {
	tests := []struct {
		name           string
		setupCallback  func(*Session)
		blindingScheme uint16
		blindingFlags  uint16
		blindingParams []byte
		expectDispatch bool
	}{
		{
			name: "successful dispatch",
			setupCallback: func(s *Session) {
				s.callbacks = &SessionCallbacks{
					OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
						if scheme != 1 {
							t.Errorf("Expected scheme 1, got %d", scheme)
						}
						if flags != 0x0002 {
							t.Errorf("Expected flags 0x0002, got 0x%04x", flags)
						}
						if len(params) != 4 {
							t.Errorf("Expected params length 4, got %d", len(params))
						}
					},
				}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01, 0x02, 0x03, 0x04},
			expectDispatch: true,
		},
		{
			name: "no callback registered",
			setupCallback: func(s *Session) {
				s.callbacks = &SessionCallbacks{}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01, 0x02},
			expectDispatch: false,
		},
		{
			name: "nil callbacks",
			setupCallback: func(s *Session) {
				s.callbacks = nil
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01},
			expectDispatch: false,
		},
		{
			name: "closed session",
			setupCallback: func(s *Session) {
				s.closed = true
				s.callbacks = &SessionCallbacks{
					OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
						t.Error("Callback should not be called for closed session")
					},
				}
			},
			blindingScheme: 1,
			blindingFlags:  0x0002,
			blindingParams: []byte{0x01},
			expectDispatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}
			session := newSession(client, SessionCallbacks{})
			tt.setupCallback(session)

			session.dispatchBlindingInfo(tt.blindingScheme, tt.blindingFlags, tt.blindingParams)

			// Give async callback time to execute
			time.Sleep(10 * time.Millisecond)
		})
	}
}

// TestDispatchBlindingInfo_CallbackPanic tests panic recovery in blinding callback
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo_CallbackPanic(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}
	session := newSession(client, SessionCallbacks{
		OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
			panic("intentional test panic")
		},
	})

	// Should not panic - panic should be recovered
	session.dispatchBlindingInfo(1, 0x0002, []byte{0x01, 0x02})

	// Give async callback time to execute
	time.Sleep(10 * time.Millisecond)

	// If we reach here without panic propagating, test passes
}

// TestDispatchBlindingInfo_AsyncCallback tests asynchronous callback execution
// per I2CP specification 0.9.43+
func TestDispatchBlindingInfo_AsyncCallback(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{
		lock:     sync.Mutex{},
		sessions: make(map[uint16]*Session),
		crypto:   crypto,
	}

	callbackCalled := make(chan bool, 1)
	session := newSession(client, SessionCallbacks{
		OnBlindingInfo: func(session *Session, scheme, flags uint16, params []byte) {
			time.Sleep(5 * time.Millisecond) // Simulate work
			callbackCalled <- true
		},
	})
	session.syncCallbacks = false // Enable async mode

	session.dispatchBlindingInfo(1, 0x0002, []byte{0x01, 0x02})

	// Dispatch should return immediately in async mode
	select {
	case <-callbackCalled:
		t.Error("Callback should not have completed yet (async mode)")
	case <-time.After(1 * time.Millisecond):
		// Expected - callback still running
	}

	// Wait for callback to complete
	select {
	case <-callbackCalled:
		// Expected - callback completed
	case <-time.After(100 * time.Millisecond):
		t.Error("Callback did not complete within timeout")
	}
}

// TestOnMsgBlindingInfo tests the BlindingInfoMessage handler
// per I2CP specification 0.9.43+
func TestOnMsgBlindingInfo(t *testing.T) {
	tests := []struct {
		name            string
		sessionId       uint16
		authScheme      uint8
		flags           uint16
		params          []byte
		sessionExists   bool
		expectError     bool
		validateSession func(*testing.T, *Session)
		callbackCalled  *bool
	}{
		{
			name:          "successful blinding info",
			sessionId:     1,
			authScheme:    1,
			flags:         0x0002,
			params:        []byte{0x01, 0x02, 0x03, 0x04},
			sessionExists: true,
			expectError:   false,
			validateSession: func(t *testing.T, s *Session) {
				if scheme := s.BlindingScheme(); scheme != 1 {
					t.Errorf("Expected blinding scheme 1, got %d", scheme)
				}
				if flags := s.BlindingFlags(); flags != 0x0002 {
					t.Errorf("Expected blinding flags 0x0002, got 0x%04x", flags)
				}
				params := s.BlindingParams()
				if len(params) != 4 {
					t.Errorf("Expected params length 4, got %d", len(params))
				}
				if !s.IsBlindingEnabled() {
					t.Error("Expected blinding to be enabled")
				}
			},
		},
		{
			name:          "blinding with empty params",
			sessionId:     1,
			authScheme:    2,
			flags:         0x0000,
			params:        []byte{},
			sessionExists: true,
			expectError:   false,
			validateSession: func(t *testing.T, s *Session) {
				if scheme := s.BlindingScheme(); scheme != 2 {
					t.Errorf("Expected blinding scheme 2, got %d", scheme)
				}
				params := s.BlindingParams()
				if len(params) != 0 {
					t.Errorf("Expected empty params, got length %d", len(params))
				}
			},
		},
		{
			name:          "unknown session",
			sessionId:     999,
			authScheme:    1,
			flags:         0x0002,
			params:        []byte{0x01},
			sessionExists: false,
			expectError:   true,
		},
		{
			name:           "callback dispatched",
			sessionId:      1,
			authScheme:     1,
			flags:          0x0002,
			params:         []byte{0xAA, 0xBB},
			sessionExists:  true,
			expectError:    false,
			callbackCalled: new(bool),
			validateSession: func(t *testing.T, s *Session) {
				// Callback validation happens in setupCallback
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}

			var session *Session
			if tt.sessionExists {
				callbacks := SessionCallbacks{}
				if tt.callbackCalled != nil {
					callbacks.OnBlindingInfo = func(s *Session, scheme, flags uint16, params []byte) {
						*tt.callbackCalled = true
						if scheme != uint16(tt.authScheme) {
							t.Errorf("Callback: expected scheme %d, got %d", tt.authScheme, scheme)
						}
						if flags != tt.flags {
							t.Errorf("Callback: expected flags 0x%04x, got 0x%04x", tt.flags, flags)
						}
						if len(params) != len(tt.params) {
							t.Errorf("Callback: expected params length %d, got %d", len(tt.params), len(params))
						}
					}
				}
				session = newSession(client, callbacks)
				session.id = tt.sessionId
				client.sessions[tt.sessionId] = session
			}

			// Create message stream
			stream := NewStream(make([]byte, 0, 256))
			stream.WriteUint16(tt.sessionId)
			stream.WriteByte(tt.authScheme)
			stream.WriteUint16(tt.flags)
			stream.WriteUint16(uint16(len(tt.params)))
			stream.Write(tt.params)

			// Reset stream position for reading
			stream = NewStream(stream.Bytes())

			// Call handler
			client.onMsgBlindingInfo(stream)

			// Validate session state
			if tt.sessionExists && tt.validateSession != nil && !tt.expectError {
				tt.validateSession(t, session)
			}

			// Validate callback was called
			if tt.callbackCalled != nil {
				time.Sleep(10 * time.Millisecond) // Allow async callback to execute
				if !*tt.callbackCalled {
					t.Error("Expected callback to be called")
				}
			}
		})
	}
}

// TestOnMsgBlindingInfo_InvalidData tests error handling for malformed BlindingInfo messages
// per I2CP specification 0.9.43+
func TestOnMsgBlindingInfo_InvalidData(t *testing.T) {
	tests := []struct {
		name        string
		setupStream func() *Stream
	}{
		{
			name: "truncated session id",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteByte(0x01) // Only 1 byte instead of 2 for session ID
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated auth scheme",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1) // Session ID
				// Missing auth scheme
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated flags",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1) // Session ID
				stream.WriteByte(1)   // Auth scheme
				// Missing flags
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated param length",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1)      // Session ID
				stream.WriteByte(1)        // Auth scheme
				stream.WriteUint16(0x0002) // Flags
				// Missing param length
				return NewStream(stream.Bytes())
			},
		},
		{
			name: "truncated params",
			setupStream: func() *Stream {
				stream := NewStream(make([]byte, 0, 256))
				stream.WriteUint16(1)            // Session ID
				stream.WriteByte(1)              // Auth scheme
				stream.WriteUint16(0x0002)       // Flags
				stream.WriteUint16(10)           // Param length = 10
				stream.Write([]byte{0x01, 0x02}) // Only 2 bytes instead of 10
				return NewStream(stream.Bytes())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCrypto()
			client := &Client{
				lock:     sync.Mutex{},
				sessions: make(map[uint16]*Session),
				crypto:   crypto,
			}

			// Create session
			session := newSession(client, SessionCallbacks{
				OnBlindingInfo: func(s *Session, scheme, flags uint16, params []byte) {
					t.Error("Callback should not be called for invalid data")
				},
			})
			session.id = 1
			client.sessions[1] = session

			// Call handler with malformed stream
			stream := tt.setupStream()
			client.onMsgBlindingInfo(stream)

			// If we reach here without panic, error handling worked
			// Callback should not have been called (verified above)
		})
	}
}
