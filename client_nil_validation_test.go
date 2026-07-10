package go_i2cp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// assertInvalidArgError verifies that an error is not nil, contains the expected message,
// and optionally checks that it wraps ErrInvalidArgument (for client methods)
func assertInvalidArgError(t *testing.T, err error, expectedMsg string, checkInvalidArg bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if checkInvalidArg && !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got: %v", err)
	}

	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestClientCreateSessionNilSession verifies that CreateSession returns an error when session is nil
// per Task 1.3 requirement: "Add nil checks for destination, session, payload parameters"
func TestClientCreateSessionNilSession(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()

	err := client.CreateSession(ctx, nil)
	assertInvalidArgError(t, err, "session cannot be nil", true)
}

// TestClientDestinationLookupNilSession verifies that DestinationLookup returns an error when session is nil
func TestClientDestinationLookupNilSession(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()

	_, err := client.DestinationLookup(ctx, nil, "example.i2p")
	assertInvalidArgError(t, err, "session cannot be nil", true)
}

// TestClientDestinationLookupEmptyAddress verifies that DestinationLookup returns an error when address is empty
func TestClientDestinationLookupEmptyAddress(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()
	session := NewSession(client, SessionCallbacks{})

	_, err := client.DestinationLookup(ctx, session, "")
	assertInvalidArgError(t, err, "address cannot be empty", true)
}

// TestSessionSendMessageNilDestination verifies that SendMessage returns an error when destination is nil
func TestSessionSendMessageNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	payload := NewStream([]byte("test"))

	err := session.SendMessage(nil, 1, 80, 80, payload, 12345)
	assertInvalidArgError(t, err, "destination cannot be nil", false)
}

// TestSessionSendMessageNilPayload verifies that SendMessage returns an error when payload is nil
func TestSessionSendMessageNilPayload(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}

	err = session.SendMessage(dest, 1, 80, 80, nil, 12345)
	assertInvalidArgError(t, err, "payload cannot be nil", false)
}

// TestSessionSendMessageWithContextNilContext verifies context validation
func TestSessionSendMessageWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}
	payload := NewStream([]byte("test"))

	err = session.SendMessageWithContext(nil, dest, 1, 80, 80, payload, 12345) //nolint:SA1012 // intentionally testing nil context handling
	assertInvalidArgError(t, err, "context cannot be nil", false)
}

// TestSessionSendMessageExpiresNilDestination verifies that SendMessageExpires returns an error when destination is nil
func TestSessionSendMessageExpiresNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	payload := NewStream([]byte("test"))

	err := session.SendMessageExpires(nil, 1, 80, 80, payload, 0, 3600)
	assertInvalidArgError(t, err, "destination cannot be nil", false)
}

// TestSessionSendMessageExpiresNilPayload verifies that SendMessageExpires returns an error when payload is nil
func TestSessionSendMessageExpiresNilPayload(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}

	err = session.SendMessageExpires(dest, 1, 80, 80, nil, 0, 3600)
	assertInvalidArgError(t, err, "payload cannot be nil", false)
}

// TestSessionSendMessageExpiresWithContextNilContext verifies context validation
func TestSessionSendMessageExpiresWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("failed to create destination: %v", err)
	}
	payload := NewStream([]byte("test"))

	err = session.SendMessageExpiresWithContext(nil, dest, 1, 80, 80, payload, 0, 3600) //nolint:SA1012 // intentionally testing nil context handling
	assertInvalidArgError(t, err, "context cannot be nil", false)
}

// TestSessionReconfigureSessionNilProperties verifies that ReconfigureSession returns an error when properties is nil
func TestSessionReconfigureSessionNilProperties(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.ReconfigureSession(nil)
	assertInvalidArgError(t, err, "properties cannot be nil or empty", false)
}

// TestSessionReconfigureSessionEmptyProperties verifies that ReconfigureSession returns an error when properties is empty
func TestSessionReconfigureSessionEmptyProperties(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.ReconfigureSession(map[string]string{})
	assertInvalidArgError(t, err, "properties cannot be nil or empty", false)
}

// TestSessionReconfigureSessionWithContextNilContext verifies context validation
func TestSessionReconfigureSessionWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	properties := map[string]string{"test": "value"}

	err := session.ReconfigureSessionWithContext(nil, properties) //nolint:SA1012 // intentionally testing nil context handling
	assertInvalidArgError(t, err, "context cannot be nil", false)
}

// TestSessionSetPrimarySessionNilPrimary verifies that SetPrimarySession returns an error when primary is nil
func TestSessionSetPrimarySessionNilPrimary(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.SetPrimarySession(nil)
	assertInvalidArgError(t, err, "primary session cannot be nil", false)
}

// TestSessionLookupDestinationEmptyAddress verifies that LookupDestination returns an error when address is empty
func TestSessionLookupDestinationEmptyAddress(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.LookupDestination("", 30*time.Second)
	assertInvalidArgError(t, err, "address cannot be empty", false)
}

// TestSessionLookupDestinationWithContextNilContext verifies context validation
func TestSessionLookupDestinationWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.LookupDestinationWithContext(nil, "example.i2p", 30*time.Second) //nolint:SA1012 // intentionally testing nil context handling
	assertInvalidArgError(t, err, "context cannot be nil", false)
}

// TestNewSessionWithContextNilClient verifies that NewSessionWithContext returns an error when client is nil
func TestNewSessionWithContextNilClient(t *testing.T) {
	ctx := context.Background()

	_, err := NewSessionWithContext(ctx, nil, SessionCallbacks{})
	assertInvalidArgError(t, err, "client cannot be nil", false)
}

// TestNilParameterErrorWrapping verifies that nil parameter errors properly wrap ErrInvalidArgument
// This allows users to check errors using errors.Is(err, ErrInvalidArgument)
func TestNilParameterErrorWrapping(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func() error
		wantErr  error
	}{
		{
			name: "CreateSession nil session",
			testFunc: func() error {
				client := NewClient(nil)
				return client.CreateSession(context.Background(), nil)
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "DestinationLookup nil session",
			testFunc: func() error {
				client := NewClient(nil)
				_, err := client.DestinationLookup(context.Background(), nil, "example.i2p")
				return err
			},
			wantErr: ErrInvalidArgument,
		},
		{
			name: "DestinationLookup empty address",
			testFunc: func() error {
				client := NewClient(nil)
				session := NewSession(client, SessionCallbacks{})
				_, err := client.DestinationLookup(context.Background(), session, "")
				return err
			},
			wantErr: ErrInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFunc()
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error should wrap %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
