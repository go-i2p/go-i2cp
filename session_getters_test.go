package go_i2cp

import (
	"testing"
)

// TestSessionID verifies session ID getter/setter operations
func TestSessionID(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial ID (should be 0)
	if id := session.ID(); id != 0 {
		t.Errorf("expected initial ID to be 0, got %d", id)
	}

	// Test setting ID
	testID := uint16(12345)
	session.SetID(testID)

	// Verify ID was set correctly
	if id := session.ID(); id != testID {
		t.Errorf("expected ID %d, got %d", testID, id)
	}

	// Test multiple sets
	newID := uint16(54321)
	session.SetID(newID)
	if id := session.ID(); id != newID {
		t.Errorf("expected ID %d after second set, got %d", newID, id)
	}
}

// TestSessionIDAlias verifies SessionID() is an alias for ID()
func TestSessionIDAlias(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial ID with both methods
	if session.ID() != session.SessionID() {
		t.Error("ID() and SessionID() should return the same value")
	}

	// Test after setting ID
	testID := uint16(9876)
	session.SetID(testID)

	if session.SessionID() != testID {
		t.Errorf("expected SessionID() to return %d, got %d", testID, session.SessionID())
	}

	if session.ID() != session.SessionID() {
		t.Error("ID() and SessionID() should always return the same value")
	}
}

// TestSessionIsPrimary verifies primary session flag operations
func TestSessionIsPrimary(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Test initial state (should be true by default)
	if !session.IsPrimary() {
		t.Error("expected new session to be primary by default")
	}

	// Test setting to false
	session.SetPrimary(false)
	if session.IsPrimary() {
		t.Error("expected session to be non-primary after SetPrimary(false)")
	}

	// Test setting back to true
	session.SetPrimary(true)
	if !session.IsPrimary() {
		t.Error("expected session to be primary after SetPrimary(true)")
	}
}

// TestSessionPrimarySession verifies primary session reference operations
func TestSessionPrimarySession(t *testing.T) {
	client := NewClient(nil)
	primarySession := NewSession(client, SessionCallbacks{})
	subsession := NewSession(client, SessionCallbacks{})

	// Test initial state (should be nil)
	if ps := subsession.PrimarySession(); ps != nil {
		t.Error("expected initial primary session to be nil")
	}

	// Test setting valid primary session
	primarySession.SetID(1)
	subsession.SetID(2)

	err := subsession.SetPrimarySession(primarySession)
	if err != nil {
		t.Fatalf("unexpected error setting primary session: %v", err)
	}

	// Verify primary session was set correctly
	if ps := subsession.PrimarySession(); ps != primarySession {
		t.Error("primary session reference not set correctly")
	}

	// Verify subsession flag was automatically set to false
	if subsession.IsPrimary() {
		t.Error("expected subsession to be marked as non-primary")
	}
}

// TestSetPrimarySessionErrors verifies error handling in SetPrimarySession
func TestSetPrimarySessionErrors(t *testing.T) {
	client := NewClient(nil)
	subsession := NewSession(client, SessionCallbacks{})

	// Test nil primary session
	err := subsession.SetPrimarySession(nil)
	if err == nil {
		t.Error("expected error when setting nil primary session")
	}
	if err != nil && err.Error() != "primary session cannot be nil" {
		t.Errorf("unexpected error message: %v", err)
	}

	// Test setting non-primary session as primary
	nonPrimarySession := NewSession(client, SessionCallbacks{})
	nonPrimarySession.SetPrimary(false) // Explicitly set as non-primary

	err = subsession.SetPrimarySession(nonPrimarySession)
	if err == nil {
		t.Error("expected error when setting non-primary session as primary")
	}
	if err != nil && err.Error() != "referenced session is not a primary session" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSessionIDThreadSafety verifies concurrent ID operations are thread-safe
func TestSessionIDThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Run concurrent reads and writes
	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func(id uint16) {
			session.SetID(id)
			done <- true
		}(uint16(i))
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = session.ID()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read the ID without panic
	_ = session.ID()
}

// TestSessionPrimaryThreadSafety verifies concurrent primary flag operations are thread-safe
func TestSessionPrimaryThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func(isPrimary bool) {
			session.SetPrimary(isPrimary)
			done <- true
		}(i%2 == 0)
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = session.IsPrimary()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_ = session.IsPrimary()
}

// TestSessionPrimaryReferenceThreadSafety verifies concurrent primary session reference operations
func TestSessionPrimaryReferenceThreadSafety(t *testing.T) {
	client := NewClient(nil)
	primarySession := NewSession(client, SessionCallbacks{})
	subsession := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Writers
	for i := 0; i < 50; i++ {
		go func() {
			_ = subsession.SetPrimarySession(primarySession)
			done <- true
		}()
	}

	// Readers
	for i := 0; i < 50; i++ {
		go func() {
			_ = subsession.PrimarySession()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_ = subsession.PrimarySession()
}

// TestSessionSigningKeyPair verifies SigningKeyPair() returns the correct key pair
func TestSessionSigningKeyPair(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error getting signing key pair: %v", err)
	}

	if keyPair == nil {
		t.Fatal("expected non-nil key pair")
	}

	// Verify it's the same key pair as in the destination
	dest := session.Destination()
	if dest == nil {
		t.Fatal("expected non-nil destination")
	}

	if dest.sgk.ed25519KeyPair != keyPair {
		t.Error("SigningKeyPair() should return the same key pair as destination's sgk.ed25519KeyPair")
	}

	// Verify key pair has valid public and private keys
	pubKey := keyPair.PublicKey()
	if len(pubKey) != 32 {
		t.Errorf("expected public key length 32, got %d", len(pubKey))
	}

	privKey := keyPair.PrivateKey()
	if len(privKey) != 64 {
		t.Errorf("expected private key length 64, got %d", len(privKey))
	}
}

// TestSessionSigningKeyPairForSigning verifies SigningKeyPair() can be used for signing
func TestSessionSigningKeyPairForSigning(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error getting signing key pair: %v", err)
	}

	// Test data to sign (simulating a packet)
	testData := []byte("test packet data for I2P streaming protocol")

	// Sign the data
	signature, err := keyPair.Sign(testData)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("expected non-empty signature")
	}

	// Verify the signature
	valid := keyPair.Verify(testData, signature)
	if !valid {
		t.Error("signature verification failed for data signed with same key pair")
	}

	// Verify with wrong data fails
	wrongData := []byte("wrong data")
	valid = keyPair.Verify(wrongData, signature)
	if valid {
		t.Error("signature verification should fail for wrong data")
	}
}

// TestSessionSigningKeyPairNilConfig verifies error handling when config is nil
func TestSessionSigningKeyPairNilConfig(t *testing.T) {
	// Create session with nil config (simulating uninitialized state)
	session := &Session{}

	keyPair, err := session.SigningKeyPair()
	if err == nil {
		t.Error("expected error when session config is nil")
	}

	if keyPair != nil {
		t.Error("expected nil key pair when session config is nil")
	}

	if err != ErrSessionNotInitialized {
		t.Errorf("expected ErrSessionNotInitialized, got: %v", err)
	}
}

// TestSessionSigningKeyPairNilDestination verifies error handling when destination is nil
func TestSessionSigningKeyPairNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Manually set destination to nil to test error handling
	session.mu.Lock()
	session.config.destination = nil
	session.mu.Unlock()

	keyPair, err := session.SigningKeyPair()
	if err == nil {
		t.Error("expected error when destination is nil")
	}

	if keyPair != nil {
		t.Error("expected nil key pair when destination is nil")
	}

	expectedError := "session has no destination"
	if err.Error() != expectedError {
		t.Errorf("expected error '%s', got: %v", expectedError, err)
	}
}

// TestSessionSigningKeyPairThreadSafety verifies concurrent access to SigningKeyPair()
func TestSessionSigningKeyPairThreadSafety(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	done := make(chan bool, 100)

	// Multiple readers
	for i := 0; i < 100; i++ {
		go func() {
			keyPair, err := session.SigningKeyPair()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if keyPair == nil {
				t.Error("expected non-nil key pair")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify we can still read without panic
	_, _ = session.SigningKeyPair()
}

// TestSessionSigningKeyPairConsistency verifies key pair remains consistent across calls
func TestSessionSigningKeyPairConsistency(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	// Get key pair multiple times
	keyPair1, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyPair2, err := session.SigningKeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's the same instance
	if keyPair1 != keyPair2 {
		t.Error("SigningKeyPair() should return the same instance across multiple calls")
	}

	// Verify public keys are identical
	pubKey1 := keyPair1.PublicKey()
	pubKey2 := keyPair2.PublicKey()

	if len(pubKey1) != len(pubKey2) {
		t.Error("public key lengths should match")
	}

	for i := range pubKey1 {
		if pubKey1[i] != pubKey2[i] {
			t.Error("public keys should be identical")
			break
		}
	}
}
