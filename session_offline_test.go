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
