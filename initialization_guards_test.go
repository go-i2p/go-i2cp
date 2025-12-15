package go_i2cp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestZeroValueClientPanics tests that zero-value Client{} returns errors instead of panicking
// per PLAN.md Task 1.1 - zero-value safety for Client
func TestZeroValueClientReturnsErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func(*Client) error
	}{
		{
			name: "Connect",
			fn: func(c *Client) error {
				return c.Connect(ctx)
			},
		},
		{
			name: "CreateSession",
			fn: func(c *Client) error {
				sess := NewSession(c, SessionCallbacks{})
				return c.CreateSession(ctx, sess)
			},
		},
		{
			name: "ProcessIO",
			fn: func(c *Client) error {
				return c.ProcessIO(ctx)
			},
		},
		{
			name: "DestinationLookup",
			fn: func(c *Client) error {
				sess := NewSession(c, SessionCallbacks{})
				_, err := c.DestinationLookup(ctx, sess, "example.i2p")
				return err
			},
		},
		{
			name: "Close",
			fn: func(c *Client) error {
				return c.Close()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create zero-value client (DANGEROUS - should fail gracefully)
			var client Client

			// Call method - should return ErrClientNotInitialized, not panic
			err := tt.fn(&client)

			if err == nil {
				t.Fatalf("expected error from zero-value Client, got nil")
			}

			if !errors.Is(err, ErrClientNotInitialized) {
				t.Errorf("expected ErrClientNotInitialized, got %v", err)
			}
		})
	}
}

// TestZeroValueClientSetPropertySafe tests that SetProperty is safe on zero-value Client
// SetProperty should silently return when called on uninitialized client
func TestZeroValueClientSetPropertySafe(t *testing.T) {
	var client Client

	// Should not panic, just silently return
	client.SetProperty("test", "value")

	// Verify properties are still nil (no initialization happened)
	if client.properties != nil {
		t.Error("SetProperty should not initialize properties on zero-value Client")
	}
}

// TestZeroValueClientDisconnectSafe tests that Disconnect is safe on zero-value Client
func TestZeroValueClientDisconnectSafe(t *testing.T) {
	var client Client

	// Should not panic, just silently return
	client.Disconnect()
}

// TestZeroValueClientMetricsSafe tests that metrics methods are safe on zero-value Client
func TestZeroValueClientMetricsSafe(t *testing.T) {
	var client Client

	// SetMetrics should silently return
	client.SetMetrics(NewInMemoryMetrics())

	// GetMetrics should return nil
	metrics := client.GetMetrics()
	if metrics != nil {
		t.Error("GetMetrics should return nil on zero-value Client")
	}
}

// TestZeroValueClientBatchingSafe tests that batching methods are safe on zero-value Client
func TestZeroValueClientBatchingSafe(t *testing.T) {
	var client Client

	// EnableBatching should silently return
	client.EnableBatching(10*time.Millisecond, 16*1024)

	// IsBatchingEnabled should return false
	if client.IsBatchingEnabled() {
		t.Error("IsBatchingEnabled should return false on zero-value Client")
	}

	// DisableBatching should return nil
	if err := client.DisableBatching(); err != nil {
		t.Errorf("DisableBatching should return nil on zero-value Client, got %v", err)
	}
}

// TestZeroValueSessionReturnsErrors tests that zero-value Session{} returns errors instead of panicking
// per PLAN.md Task 1.1 - zero-value safety for Session
func TestZeroValueSessionReturnsErrors(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*Session) error
	}{
		{
			name: "SendMessage",
			fn: func(s *Session) error {
				dest, _ := NewDestination(NewCrypto())
				payload := NewStream(make([]byte, 10))
				return s.SendMessage(dest, 0, 0, 0, payload, 1234)
			},
		},
		{
			name: "SendMessageExpires",
			fn: func(s *Session) error {
				dest, _ := NewDestination(NewCrypto())
				payload := NewStream(make([]byte, 10))
				return s.SendMessageExpires(dest, 0, 0, 0, payload, 0, 3600)
			},
		},
		{
			name: "ReconfigureSession",
			fn: func(s *Session) error {
				props := map[string]string{"test": "value"}
				return s.ReconfigureSession(props)
			},
		},
		{
			name: "Close",
			fn: func(s *Session) error {
				return s.Close()
			},
		},
		{
			name: "LookupDestination",
			fn: func(s *Session) error {
				_, err := s.LookupDestination("example.i2p", 30*time.Second)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create zero-value session (DANGEROUS - should fail gracefully)
			var session Session

			// Call method - should return ErrSessionNotInitialized, not panic
			err := tt.fn(&session)

			if err == nil {
				t.Fatalf("expected error from zero-value Session, got nil")
			}

			if !errors.Is(err, ErrSessionNotInitialized) {
				t.Errorf("expected ErrSessionNotInitialized, got %v", err)
			}
		})
	}
}

// TestProperlyInitializedClientWorks tests that properly initialized Client works correctly
func TestProperlyInitializedClientWorks(t *testing.T) {
	// Create properly initialized client
	client := NewClient(&ClientCallBacks{})

	// Verify initialization
	if err := client.ensureInitialized(); err != nil {
		t.Errorf("properly initialized client should pass ensureInitialized, got %v", err)
	}

	// Verify critical fields are set
	if client.crypto == nil {
		t.Error("client.crypto should not be nil after NewClient()")
	}

	if client.properties == nil {
		t.Error("client.properties should not be nil after NewClient()")
	}

	if client.sessions == nil {
		t.Error("client.sessions should not be nil after NewClient()")
	}
}

// TestProperlyInitializedSessionWorks tests that properly initialized Session works correctly
func TestProperlyInitializedSessionWorks(t *testing.T) {
	// Create properly initialized client and session
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})

	// Verify initialization
	if err := session.ensureInitialized(); err != nil {
		t.Errorf("properly initialized session should pass ensureInitialized, got %v", err)
	}

	// Verify critical fields are set
	if session.client == nil {
		t.Error("session.client should not be nil after NewSession()")
	}

	if session.config == nil {
		t.Error("session.config should not be nil after NewSession()")
	}

	if session.callbacks == nil {
		t.Error("session.callbacks should not be nil after NewSession()")
	}
}

// TestEnsureInitializedErrors tests that ensureInitialized returns correct errors
func TestEnsureInitializedErrors(t *testing.T) {
	t.Run("Client with nil crypto", func(t *testing.T) {
		client := &Client{
			properties: make(map[string]string),
			sessions:   make(map[uint16]*Session),
			// crypto is nil
		}

		err := client.ensureInitialized()
		if !errors.Is(err, ErrClientNotInitialized) {
			t.Errorf("expected ErrClientNotInitialized for nil crypto, got %v", err)
		}
	})

	t.Run("Client with nil properties", func(t *testing.T) {
		client := &Client{
			crypto:   NewCrypto(),
			sessions: make(map[uint16]*Session),
			// properties is nil
		}

		err := client.ensureInitialized()
		if !errors.Is(err, ErrClientNotInitialized) {
			t.Errorf("expected ErrClientNotInitialized for nil properties, got %v", err)
		}
	})

	t.Run("Client with nil sessions", func(t *testing.T) {
		client := &Client{
			crypto:     NewCrypto(),
			properties: make(map[string]string),
			// sessions is nil
		}

		err := client.ensureInitialized()
		if !errors.Is(err, ErrClientNotInitialized) {
			t.Errorf("expected ErrClientNotInitialized for nil sessions, got %v", err)
		}
	})

	t.Run("Session with nil client", func(t *testing.T) {
		session := &Session{
			config:    &SessionConfig{},
			callbacks: &SessionCallbacks{},
			// client is nil
		}

		err := session.ensureInitialized()
		if !errors.Is(err, ErrSessionNotInitialized) {
			t.Errorf("expected ErrSessionNotInitialized for nil client, got %v", err)
		}
	})

	t.Run("Session with nil config", func(t *testing.T) {
		client := NewClient(&ClientCallBacks{})
		session := &Session{
			client:    client,
			callbacks: &SessionCallbacks{},
			// config is nil
		}

		err := session.ensureInitialized()
		if !errors.Is(err, ErrSessionNotInitialized) {
			t.Errorf("expected ErrSessionNotInitialized for nil config, got %v", err)
		}
	})

	t.Run("Session with nil callbacks", func(t *testing.T) {
		client := NewClient(&ClientCallBacks{})
		session := &Session{
			client: client,
			config: &SessionConfig{},
			// callbacks is nil
		}

		err := session.ensureInitialized()
		if !errors.Is(err, ErrSessionNotInitialized) {
			t.Errorf("expected ErrSessionNotInitialized for nil callbacks, got %v", err)
		}
	})
}
