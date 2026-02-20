package go_i2cp

import (
	"testing"
	"time"
)

// TestSession_IsOffline_NotConfigured tests that IsOffline returns false
// when offline signing is not configured.
func TestSession_IsOffline_NotConfigured(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	if session.IsOffline() {
		t.Error("IsOffline() should return false for session without offline signing configured")
	}
}

// TestSession_IsOffline_Configured tests that IsOffline returns true
// when offline signing is properly configured.
func TestSession_IsOffline_Configured(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Configure offline signing with test values
	expiration := uint32(time.Now().Unix() + 3600) // 1 hour from now
	transientKey := make([]byte, 32)
	for i := range transientKey {
		transientKey[i] = byte(i)
	}
	signature := make([]byte, 64)
	for i := range signature {
		signature[i] = byte(i + 100)
	}

	err := session.config.SetOfflineSignature(expiration, transientKey, signature)
	if err != nil {
		t.Fatalf("SetOfflineSignature failed: %v", err)
	}

	if !session.IsOffline() {
		t.Error("IsOffline() should return true for session with offline signing configured")
	}
}

// TestSession_IsOffline_NilConfig tests that IsOffline handles nil config gracefully.
func TestSession_IsOffline_NilConfig(t *testing.T) {
	session := &Session{}

	// Should not panic with nil config
	if session.IsOffline() {
		t.Error("IsOffline() should return false for session with nil config")
	}
}

// TestSession_ValidateProtocol_Datagram1Offline tests that ValidateProtocol
// returns an error when Datagram1 is used with an offline-signed session.
func TestSession_ValidateProtocol_Datagram1Offline(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Configure offline signing
	expiration := uint32(time.Now().Unix() + 3600)
	transientKey := make([]byte, 32)
	signature := make([]byte, 64)
	_ = session.config.SetOfflineSignature(expiration, transientKey, signature)

	// Datagram1 should fail validation for offline sessions
	err := session.ValidateProtocol(ProtoDatagram)
	if err == nil {
		t.Error("ValidateProtocol(ProtoDatagram) should return error for offline session")
	}
}

// TestSession_ValidateProtocol_Datagram2Offline tests that ValidateProtocol
// accepts Datagram2 for offline-signed sessions.
func TestSession_ValidateProtocol_Datagram2Offline(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Configure offline signing
	expiration := uint32(time.Now().Unix() + 3600)
	transientKey := make([]byte, 32)
	signature := make([]byte, 64)
	_ = session.config.SetOfflineSignature(expiration, transientKey, signature)

	// Datagram2 should be valid for offline sessions
	err := session.ValidateProtocol(ProtoDatagram2)
	if err != nil {
		t.Errorf("ValidateProtocol(ProtoDatagram2) should not return error for offline session: %v", err)
	}
}

// TestSession_ValidateProtocol_Datagram1Online tests that ValidateProtocol
// accepts Datagram1 for regular (non-offline) sessions.
func TestSession_ValidateProtocol_Datagram1Online(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// No offline signing configured
	err := session.ValidateProtocol(ProtoDatagram)
	if err != nil {
		t.Errorf("ValidateProtocol(ProtoDatagram) should not return error for online session: %v", err)
	}
}

// TestSession_ValidateProtocol_AllProtocols tests ValidateProtocol for all protocol types
// on a regular (non-offline) session.
func TestSession_ValidateProtocol_AllProtocols(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	protocols := []uint8{
		ProtoStreaming,
		ProtoDatagram,
		ProtoDatagramRaw,
		ProtoDatagram2,
		ProtoDatagram3,
	}

	for _, proto := range protocols {
		err := session.ValidateProtocol(proto)
		if err != nil {
			t.Errorf("ValidateProtocol(%d) should not return error for online session: %v", proto, err)
		}
	}
}

// TestSession_TransientSigningKeyPair_NotOffline tests that TransientSigningKeyPair
// returns an error when the session is not configured for offline signing.
func TestSession_TransientSigningKeyPair_NotOffline(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	_, err := session.TransientSigningKeyPair()
	if err == nil {
		t.Error("TransientSigningKeyPair() should return error for non-offline session")
	}
}

// TestSession_TransientSigningKeyPair_NoKeyPairConfigured tests that TransientSigningKeyPair
// returns an error when offline is configured but transient key pair is not set.
func TestSession_TransientSigningKeyPair_NoKeyPairConfigured(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Configure offline signing (without transient key pair)
	expiration := uint32(time.Now().Unix() + 3600)
	transientPubKey := make([]byte, 32)
	signature := make([]byte, 64)
	_ = session.config.SetOfflineSignature(expiration, transientPubKey, signature)

	_, err := session.TransientSigningKeyPair()
	if err == nil {
		t.Error("TransientSigningKeyPair() should return error when transient key pair not configured")
	}
}

// TestSession_TransientSigningKeyPair_Configured tests that TransientSigningKeyPair
// returns the transient key pair when properly configured.
func TestSession_TransientSigningKeyPair_Configured(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Generate transient key pair
	transientKP, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate transient key pair: %v", err)
	}

	// Configure offline signing with transient public key
	expiration := uint32(time.Now().Unix() + 3600)
	transientPubKey := transientKP.PublicKey()
	signature := make([]byte, 64)
	err = session.config.SetOfflineSignature(expiration, transientPubKey, signature)
	if err != nil {
		t.Fatalf("SetOfflineSignature failed: %v", err)
	}

	// Set transient key pair
	err = session.config.SetTransientKeyPair(transientKP)
	if err != nil {
		t.Fatalf("SetTransientKeyPair failed: %v", err)
	}

	// Should now return the transient key pair
	gotKP, err := session.TransientSigningKeyPair()
	if err != nil {
		t.Fatalf("TransientSigningKeyPair() returned unexpected error: %v", err)
	}

	if gotKP == nil {
		t.Fatal("TransientSigningKeyPair() returned nil key pair")
	}

	// Verify it's the same key pair
	if string(gotKP.PublicKey()) != string(transientKP.PublicKey()) {
		t.Error("Returned key pair does not match configured key pair")
	}
}

// TestSession_TransientSigningKeyPair_CanSign tests that the transient key pair
// can be used for signing.
func TestSession_TransientSigningKeyPair_CanSign(t *testing.T) {
	crypto := NewCrypto()
	client := &Client{crypto: crypto}
	session := NewSession(client, SessionCallbacks{})

	// Generate and configure transient key pair
	transientKP, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate transient key pair: %v", err)
	}

	expiration := uint32(time.Now().Unix() + 3600)
	transientPubKey := transientKP.PublicKey()
	signature := make([]byte, 64)
	_ = session.config.SetOfflineSignature(expiration, transientPubKey, signature)
	_ = session.config.SetTransientKeyPair(transientKP)

	// Get transient key pair from session
	gotKP, err := session.TransientSigningKeyPair()
	if err != nil {
		t.Fatalf("TransientSigningKeyPair() returned error: %v", err)
	}

	// Test signing
	testData := []byte("test payload for Datagram2 signing")
	sig, err := gotKP.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign with transient key pair: %v", err)
	}

	if len(sig) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(sig))
	}

	// Verify signature
	if !gotKP.Verify(testData, sig) {
		t.Error("Signature verification failed")
	}
}

// TestSessionConfig_SetTransientKeyPair_Nil tests error handling for nil key pair.
func TestSessionConfig_SetTransientKeyPair_Nil(t *testing.T) {
	config := &SessionConfig{}

	err := config.SetTransientKeyPair(nil)
	if err == nil {
		t.Error("SetTransientKeyPair(nil) should return error")
	}
}

// TestSessionConfig_GetTransientKeyPair_NotSet tests that GetTransientKeyPair returns nil
// when not configured.
func TestSessionConfig_GetTransientKeyPair_NotSet(t *testing.T) {
	config := &SessionConfig{}

	kp := config.GetTransientKeyPair()
	if kp != nil {
		t.Error("GetTransientKeyPair() should return nil when not configured")
	}
}
