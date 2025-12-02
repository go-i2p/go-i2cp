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
