package go_i2cp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestConnectWithContext tests the Connect method with various context scenarios
func TestConnectWithContext(t *testing.T) {
	tests := []struct {
		name        string
		setupCtx    func() context.Context
		wantErr     bool
		errContains string
	}{
		{
			name: "successful connect with background context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr: false,
		},
		{
			name: "cancelled context before connect",
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx
			},
			wantErr:     true,
			errContains: "context cancelled before connect",
		},
		{
			name: "timeout context",
			setupCtx: func() context.Context {
				// Very short timeout to ensure it fails
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				defer cancel()
				time.Sleep(2 * time.Millisecond) // Ensure timeout occurs
				return ctx
			},
			wantErr:     true,
			errContains: "context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test cannot actually connect to a router in unit tests
			// In a real scenario, you'd need a mock router or integration test
			client := NewClient(&ClientCallBacks{})
			ctx := tt.setupCtx()

			err := client.Connect(ctx)

			// We expect an error in most cases since we're not connected to a real router
			// This test primarily validates the context checking logic
			if tt.wantErr {
				if err == nil {
					t.Errorf("Connect() expected error containing %q, got nil", tt.errContains)
				} else if tt.errContains != "" && !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("Connect() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestCreateSessionWithContext tests session creation with context support
func TestCreateSessionWithContext(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *Client
		setupCtx    func() context.Context
		wantErr     bool
		errContains string
	}{
		{
			name: "cancelled context before session creation",
			setupClient: func() *Client {
				return NewClient(&ClientCallBacks{})
			},
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr:     true,
			errContains: "context cancelled before session creation",
		},
		{
			name: "max sessions reached",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				client.n_sessions = I2CP_MAX_SESSIONS_PER_CLIENT
				return client
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr:     true,
			errContains: "maximum sessions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			ctx := tt.setupCtx()
			session := NewSession(client, SessionCallbacks{})

			err := client.CreateSession(ctx, session)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateSession() expected error, got nil")
				} else if tt.errContains != "" && !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("CreateSession() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestProcessIOWithContext tests ProcessIO with context cancellation
func TestProcessIOWithContext(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *Client
		setupCtx    func() context.Context
		wantErr     bool
		errContains string
	}{
		{
			name: "cancelled context before ProcessIO",
			setupClient: func() *Client {
				return NewClient(&ClientCallBacks{})
			},
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr:     true,
			errContains: "context cancelled before ProcessIO",
		},
		{
			name: "shutdown signal during ProcessIO",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				close(client.shutdown) // Signal shutdown
				return client
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr:     true,
			errContains: "client is closed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			ctx := tt.setupCtx()

			err := client.ProcessIO(ctx)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ProcessIO() expected error, got nil")
				} else if tt.errContains != "" && !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("ProcessIO() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestDestinationLookupWithContext tests destination lookup with context support
func TestDestinationLookupWithContext(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *Client
		setupCtx    func() context.Context
		address     string
		wantErr     bool
		errContains string
	}{
		{
			name: "cancelled context before lookup",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				// Set router capabilities to support host lookup
				client.router.capabilities = ROUTER_CAN_HOST_LOOKUP
				return client
			},
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			address:     "example.i2p",
			wantErr:     true,
			errContains: "context cancelled before lookup",
		},
		{
			name: "invalid destination without host lookup support",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				// Router doesn't support host lookup
				client.router.capabilities = 0
				return client
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			address:     "invalid",
			wantErr:     true,
			errContains: "invalid destination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			ctx := tt.setupCtx()
			session := NewSession(client, SessionCallbacks{})

			_, err := client.DestinationLookup(ctx, session, tt.address)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DestinationLookup() expected error, got nil")
				} else if tt.errContains != "" && !containsSubstring(err.Error(), tt.errContains) {
					t.Errorf("DestinationLookup() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

// TestClientClose tests graceful shutdown
func TestClientClose(t *testing.T) {
	tests := []struct {
		name        string
		setupClient func() *Client
		wantErr     bool
	}{
		{
			name: "successful close",
			setupClient: func() *Client {
				return NewClient(&ClientCallBacks{})
			},
			wantErr: false,
		},
		{
			name: "double close returns error",
			setupClient: func() *Client {
				client := NewClient(&ClientCallBacks{})
				// Close once
				client.Close()
				return client
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			err := client.Close()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Close() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Close() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestClientCloseWithSessions tests that Close destroys all sessions
func TestClientCloseWithSessions(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Add some mock sessions
	session1 := NewSession(client, SessionCallbacks{})
	session1.id = 1
	client.sessions[1] = session1

	session2 := NewSession(client, SessionCallbacks{})
	session2.id = 2
	client.sessions[2] = session2

	err := client.Close()
	if err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}

	// Verify client is marked as not connected
	if client.connected {
		t.Errorf("Close() client still marked as connected")
	}

	// Verify shutdown channel is closed
	select {
	case <-client.shutdown:
		// Expected - channel should be closed
	default:
		t.Errorf("Close() shutdown channel not closed")
	}
}

// TestContextTimeout tests operations with timeout context
func TestContextTimeout(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Test with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout to occur
	time.Sleep(2 * time.Millisecond)

	// All operations should fail with context error
	err := client.Connect(ctx)
	if err == nil {
		t.Errorf("Connect() with timed out context should fail")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !containsSubstring(err.Error(), "context") {
		t.Errorf("Connect() error should be context-related, got: %v", err)
	}
}

// TestShutdownSignal tests that operations respect shutdown signal
func TestShutdownSignal(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Signal shutdown
	close(client.shutdown)

	// ProcessIO should fail immediately
	ctx := context.Background()
	err := client.ProcessIO(ctx)

	if err == nil {
		t.Errorf("ProcessIO() should fail after shutdown signal")
	}

	if !errors.Is(err, ErrClientClosed) {
		t.Errorf("ProcessIO() should return ErrClientClosed, got: %v", err)
	}
}

// TestBackwardCompatibilityDisconnect tests that Disconnect still works
func TestBackwardCompatibilityDisconnect(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Disconnect should work (calls Close internally)
	client.Disconnect()

	// Verify shutdown channel is closed
	select {
	case <-client.shutdown:
		// Expected
	default:
		t.Errorf("Disconnect() should close shutdown channel")
	}
}
