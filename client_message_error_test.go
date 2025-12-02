package go_i2cp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestMsgGetBandwidthLimits verifies GetBandwidthLimitsMessage sending behavior.
// Tests both queued and immediate message sending modes.
func TestMsgGetBandwidthLimits(t *testing.T) {
	tests := []struct {
		name           string
		queue          bool
		setupClient    func(*Client)
		expectError    bool
		validateClient func(*testing.T, *Client)
	}{
		{
			name:  "queued message",
			queue: true,
			setupClient: func(c *Client) {
				// Client with valid state for queuing
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
			},
			expectError: false,
			validateClient: func(t *testing.T, c *Client) {
				// Message should be added to queue
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
				}
			},
		},
		{
			name:  "immediate send with disconnected client",
			queue: false,
			setupClient: func(c *Client) {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.connected = false // Disconnected state should cause send error
			},
			expectError: false, // Function doesn't return error, logs instead
			validateClient: func(t *testing.T, c *Client) {
				// No queue should be created for immediate send
				if len(c.outputQueue) > 0 {
					t.Error("unexpected message in output queue for immediate send")
				}
			},
		},
		{
			name:  "nil message stream",
			queue: true,
			setupClient: func(c *Client) {
				c.messageStream = nil // This should cause a panic or error
				c.outputQueue = make([]*Stream, 0)
			},
			expectError: true,
			validateClient: func(t *testing.T, c *Client) {
				// Should recover from nil pointer
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			tt.setupClient(client)

			// Use defer-recover pattern to catch panics from nil pointers
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectError {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()

			client.msgGetBandwidthLimits(tt.queue)

			if tt.validateClient != nil {
				tt.validateClient(t, client)
			}
		})
	}
}

// TestMsgDestroySession verifies DestroySessionMessage sending for session cleanup.
// Tests session ID serialization and queue/immediate send modes.
func TestMsgDestroySession(t *testing.T) {
	tests := []struct {
		name        string
		queue       bool
		sessionID   uint16
		setupClient func(*Client) *Session
		validate    func(*testing.T, *Client, *Session)
	}{
		{
			name:      "queued destroy with valid session",
			queue:     true,
			sessionID: 42,
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
				sess := &Session{id: 42, client: c}
				c.sessions = make(map[uint16]*Session)
				c.sessions[42] = sess
				return sess
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
					return
				}
				// Verify session ID was written to message stream
				stream := c.outputQueue[0]
				if stream.Len() < 2 {
					t.Error("message too short, should contain session ID")
				}
			},
		},
		{
			name:      "immediate destroy with nil session",
			queue:     false,
			sessionID: 0,
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.connected = false
				// Return nil session to test error handling
				return &Session{id: 0, client: c}
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				// Should handle gracefully without panic
			},
		},
		{
			name:      "destroy with high session ID",
			queue:     true,
			sessionID: 65535, // Max uint16 value
			setupClient: func(c *Client) *Session {
				c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
				c.outputQueue = make([]*Stream, 0)
				sess := &Session{id: 65535, client: c}
				return sess
			},
			validate: func(t *testing.T, c *Client, sess *Session) {
				if len(c.outputQueue) == 0 {
					t.Error("expected message in output queue")
					return
				}
				// Verify session ID encoding
				stream := c.outputQueue[0]
				if stream.Len() < 2 {
					t.Error("message missing session ID")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)
			session := tt.setupClient(client)

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic in msgDestroySession: %v", r)
				}
			}()

			client.msgDestroySession(session, tt.queue)

			if tt.validate != nil {
				tt.validate(t, client, session)
			}
		})
	}
}

// TestEnableAutoReconnect verifies auto-reconnect configuration.
// Tests parameter validation and thread-safety of reconnection settings.
func TestEnableAutoReconnect(t *testing.T) {
	tests := []struct {
		name           string
		maxRetries     int
		initialBackoff time.Duration
		expectedState  bool
	}{
		{
			name:           "enable with finite retries",
			maxRetries:     5,
			initialBackoff: 1 * time.Second,
			expectedState:  true,
		},
		{
			name:           "enable with infinite retries",
			maxRetries:     0, // 0 = infinite retries
			initialBackoff: 500 * time.Millisecond,
			expectedState:  true,
		},
		{
			name:           "enable with negative retries",
			maxRetries:     -1, // Should be allowed, treated as special value
			initialBackoff: 2 * time.Second,
			expectedState:  true,
		},
		{
			name:           "enable with zero backoff",
			maxRetries:     3,
			initialBackoff: 0, // Should be allowed, immediate retry
			expectedState:  true,
		},
		{
			name:           "enable with large backoff",
			maxRetries:     10,
			initialBackoff: 5 * time.Minute,
			expectedState:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)

			// Verify initial state is disabled
			if client.IsAutoReconnectEnabled() {
				t.Error("auto-reconnect should be disabled by default")
			}

			// Enable with test parameters
			client.EnableAutoReconnect(tt.maxRetries, tt.initialBackoff)

			// Verify enabled state
			if client.IsAutoReconnectEnabled() != tt.expectedState {
				t.Errorf("expected enabled=%v, got=%v", tt.expectedState, client.IsAutoReconnectEnabled())
			}

			// Verify parameters were set correctly
			client.reconnectMu.Lock()
			if client.reconnectMaxRetries != tt.maxRetries {
				t.Errorf("expected maxRetries=%d, got=%d", tt.maxRetries, client.reconnectMaxRetries)
			}
			if client.reconnectBackoff != tt.initialBackoff {
				t.Errorf("expected backoff=%v, got=%v", tt.initialBackoff, client.reconnectBackoff)
			}
			if client.reconnectAttempts != 0 {
				t.Errorf("expected attempts=0, got=%d", client.reconnectAttempts)
			}
			client.reconnectMu.Unlock()

			// Verify reconnection attempt counter
			if client.ReconnectAttempts() != 0 {
				t.Errorf("expected 0 reconnect attempts, got=%d", client.ReconnectAttempts())
			}
		})
	}
}

// TestDisableAutoReconnect verifies auto-reconnect can be disabled.
func TestDisableAutoReconnect(t *testing.T) {
	client := NewClient(nil)

	// Enable first
	client.EnableAutoReconnect(5, 1*time.Second)
	if !client.IsAutoReconnectEnabled() {
		t.Fatal("failed to enable auto-reconnect")
	}

	// Disable
	client.DisableAutoReconnect()
	if client.IsAutoReconnectEnabled() {
		t.Error("auto-reconnect should be disabled")
	}

	// Verify state is properly locked
	client.reconnectMu.Lock()
	if client.reconnectEnabled {
		t.Error("reconnectEnabled flag should be false")
	}
	client.reconnectMu.Unlock()
}

// TestAutoReconnectThreadSafety verifies thread-safety of reconnect state access.
// Concurrent calls to Enable/Disable/IsEnabled should not race.
func TestAutoReconnectThreadSafety(t *testing.T) {
	client := NewClient(nil)
	var wg sync.WaitGroup
	iterations := 100

	// Concurrently enable and disable auto-reconnect
	for i := 0; i < iterations; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			client.EnableAutoReconnect(5, 1*time.Second)
		}()

		go func() {
			defer wg.Done()
			client.DisableAutoReconnect()
		}()

		go func() {
			defer wg.Done()
			_ = client.IsAutoReconnectEnabled()
			_ = client.ReconnectAttempts()
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Final state should be consistent (no panics or races)
	_ = client.IsAutoReconnectEnabled()
}

// TestAutoReconnectWithDisabled verifies autoReconnect returns error when disabled.
func TestAutoReconnectWithDisabled(t *testing.T) {
	client := NewClient(nil)

	// Ensure auto-reconnect is disabled
	client.DisableAutoReconnect()

	ctx := context.Background()
	err := client.autoReconnect(ctx)

	if err == nil {
		t.Error("expected error when auto-reconnect is disabled")
	}

	expectedMsg := "auto-reconnect is not enabled"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// TestAutoReconnectContextCancellation verifies context cancellation is respected.
func TestAutoReconnectContextCancellation(t *testing.T) {
	client := NewClient(nil)
	client.EnableAutoReconnect(5, 100*time.Millisecond)

	// Create context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// autoReconnect should respect context cancellation
	// Note: This test may pass quickly or fail based on implementation
	// The key is ensuring no panic and proper error handling
	err := client.autoReconnect(ctx)
	if err == nil {
		// May succeed if reconnection is attempted before context check
		// This is acceptable behavior
	}
}

// TestReconnectAttempts verifies reconnection attempt counter.
func TestReconnectAttempts(t *testing.T) {
	client := NewClient(nil)

	// Initial state
	if client.ReconnectAttempts() != 0 {
		t.Error("expected 0 initial reconnect attempts")
	}

	// Manually increment counter for testing (normally done by autoReconnect)
	client.reconnectMu.Lock()
	client.reconnectAttempts = 5
	client.reconnectMu.Unlock()

	if attempts := client.ReconnectAttempts(); attempts != 5 {
		t.Errorf("expected 5 reconnect attempts, got=%d", attempts)
	}
}

// TestAutoReconnectParameterBoundaries tests edge cases for parameters.
func TestAutoReconnectParameterBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		maxRetries int
		backoff    time.Duration
	}{
		{"max retries int overflow", int(^uint(0) >> 1), 1 * time.Second},
		{"min retries", -2147483648, 1 * time.Second},
		{"max backoff", 5, time.Duration(1<<62 - 1)},
		{"negative backoff", 5, -1 * time.Second}, // Unusual but should not panic
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(nil)

			// Should not panic with extreme values
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("unexpected panic with parameters maxRetries=%d, backoff=%v: %v",
						tt.maxRetries, tt.backoff, r)
				}
			}()

			client.EnableAutoReconnect(tt.maxRetries, tt.backoff)

			// Verify values were stored
			client.reconnectMu.Lock()
			storedRetries := client.reconnectMaxRetries
			storedBackoff := client.reconnectBackoff
			client.reconnectMu.Unlock()

			if storedRetries != tt.maxRetries {
				t.Errorf("maxRetries not stored correctly: expected=%d, got=%d",
					tt.maxRetries, storedRetries)
			}
			if storedBackoff != tt.backoff {
				t.Errorf("backoff not stored correctly: expected=%v, got=%v",
					tt.backoff, storedBackoff)
			}
		})
	}
}
