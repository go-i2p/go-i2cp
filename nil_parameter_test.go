package go_i2cp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestClientCreateSessionNilSession verifies that CreateSession returns an error when session is nil
// per Task 1.3 requirement: "Add nil checks for destination, session, payload parameters"
func TestClientCreateSessionNilSession(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()

	err := client.CreateSession(ctx, nil)
	if err == nil {
		t.Fatal("expected error when session is nil, got nil")
	}

	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got: %v", err)
	}

	expectedMsg := "session cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestClientDestinationLookupNilSession verifies that DestinationLookup returns an error when session is nil
func TestClientDestinationLookupNilSession(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()

	_, err := client.DestinationLookup(ctx, nil, "example.i2p")
	if err == nil {
		t.Fatal("expected error when session is nil, got nil")
	}

	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got: %v", err)
	}

	expectedMsg := "session cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestClientDestinationLookupEmptyAddress verifies that DestinationLookup returns an error when address is empty
func TestClientDestinationLookupEmptyAddress(t *testing.T) {
	client := NewClient(nil)
	ctx := context.Background()
	session := NewSession(client, SessionCallbacks{})

	_, err := client.DestinationLookup(ctx, session, "")
	if err == nil {
		t.Fatal("expected error when address is empty, got nil")
	}

	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got: %v", err)
	}

	expectedMsg := "address cannot be empty"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionSendMessageNilDestination verifies that SendMessage returns an error when destination is nil
func TestSessionSendMessageNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	payload := NewStream([]byte("test"))

	err := session.SendMessage(nil, 1, 80, 80, payload, 12345)
	if err == nil {
		t.Fatal("expected error when destination is nil, got nil")
	}

	expectedMsg := "destination cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
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
	if err == nil {
		t.Fatal("expected error when payload is nil, got nil")
	}

	expectedMsg := "payload cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
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
	if err == nil {
		t.Fatal("expected error when context is nil, got nil")
	}

	expectedMsg := "context cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionSendMessageExpiresNilDestination verifies that SendMessageExpires returns an error when destination is nil
func TestSessionSendMessageExpiresNilDestination(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	payload := NewStream([]byte("test"))

	err := session.SendMessageExpires(nil, 1, 80, 80, payload, 0, 3600)
	if err == nil {
		t.Fatal("expected error when destination is nil, got nil")
	}

	expectedMsg := "destination cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
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
	if err == nil {
		t.Fatal("expected error when payload is nil, got nil")
	}

	expectedMsg := "payload cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
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
	if err == nil {
		t.Fatal("expected error when context is nil, got nil")
	}

	expectedMsg := "context cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionReconfigureSessionNilProperties verifies that ReconfigureSession returns an error when properties is nil
func TestSessionReconfigureSessionNilProperties(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.ReconfigureSession(nil)
	if err == nil {
		t.Fatal("expected error when properties is nil, got nil")
	}

	expectedMsg := "properties cannot be nil or empty"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionReconfigureSessionEmptyProperties verifies that ReconfigureSession returns an error when properties is empty
func TestSessionReconfigureSessionEmptyProperties(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.ReconfigureSession(map[string]string{})
	if err == nil {
		t.Fatal("expected error when properties is empty, got nil")
	}

	expectedMsg := "properties cannot be nil or empty"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionReconfigureSessionWithContextNilContext verifies context validation
func TestSessionReconfigureSessionWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})
	properties := map[string]string{"test": "value"}

	err := session.ReconfigureSessionWithContext(nil, properties) //nolint:SA1012 // intentionally testing nil context handling
	if err == nil {
		t.Fatal("expected error when context is nil, got nil")
	}

	expectedMsg := "context cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionSetPrimarySessionNilPrimary verifies that SetPrimarySession returns an error when primary is nil
func TestSessionSetPrimarySessionNilPrimary(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	err := session.SetPrimarySession(nil)
	if err == nil {
		t.Fatal("expected error when primary is nil, got nil")
	}

	expectedMsg := "primary session cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionLookupDestinationEmptyAddress verifies that LookupDestination returns an error when address is empty
func TestSessionLookupDestinationEmptyAddress(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	_, err := session.LookupDestination("", 30*time.Second)
	if err == nil {
		t.Fatal("expected error when address is empty, got nil")
	}

	expectedMsg := "address cannot be empty"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestSessionLookupDestinationWithContextNilContext verifies context validation
func TestSessionLookupDestinationWithContextNilContext(t *testing.T) {
	client := NewClient(nil)
	session := NewSession(client, SessionCallbacks{})

	_, err := session.LookupDestinationWithContext(nil, "example.i2p", 30*time.Second) //nolint:SA1012 // intentionally testing nil context handling
	if err == nil {
		t.Fatal("expected error when context is nil, got nil")
	}

	expectedMsg := "context cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
}

// TestNewSessionWithContextNilClient verifies that NewSessionWithContext returns an error when client is nil
func TestNewSessionWithContextNilClient(t *testing.T) {
	ctx := context.Background()

	_, err := NewSessionWithContext(ctx, nil, SessionCallbacks{})
	if err == nil {
		t.Fatal("expected error when client is nil, got nil")
	}

	expectedMsg := "client cannot be nil"
	if !containsSubstring(err.Error(), expectedMsg) {
		t.Errorf("expected error message to contain %q, got: %v", expectedMsg, err)
	}
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
