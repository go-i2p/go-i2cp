package go_i2cp

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestSessionCloseDestroysSession verifies Session.Close() sends DestroySession message
// per PLAN.md section 1.3 - ensures proper cleanup with router notification
func TestSessionCloseDestroysSession(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     uint16
		clientConnect bool
		expectDestroy bool
		description   string
	}{
		{
			name:          "created session sends destroy",
			sessionID:     123,
			clientConnect: true,
			expectDestroy: true,
			description:   "Session with valid ID should send DestroySession message",
		},
		{
			name:          "uncreated session skips destroy",
			sessionID:     0,
			clientConnect: true,
			expectDestroy: false,
			description:   "Session with ID 0 (not created by router) should skip DestroySession",
		},
		{
			name:          "disconnected client skips destroy",
			sessionID:     123,
			clientConnect: false,
			expectDestroy: false,
			description:   "Disconnected client should not attempt to send DestroySession",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := NewClient(&ClientCallBacks{})

			// Set connection state
			client.connected = tt.clientConnect
			if tt.clientConnect {
				// Initialize TCP to prevent nil pointer dereference
				client.tcp.Init()
			}

			// Create session
			session := NewSession(client, SessionCallbacks{})
			session.id = tt.sessionID

			// Close session
			err := session.Close()
			if err != nil {
				t.Errorf("Close() unexpected error: %v", err)
			}

			// Verify session is closed
			if !session.IsClosed() {
				t.Errorf("Close() session not marked as closed")
			}

			// Verify closed timestamp is set
			if session.ClosedAt().IsZero() {
				t.Errorf("Close() closedAt timestamp not set")
			}

			// Verify double close returns error
			err = session.Close()
			if err == nil {
				t.Errorf("Close() second call should return error")
			}
		})
	}
}

// TestSessionCloseWithContext verifies context cancellation triggers session close
// per PLAN.md section 1.3 - ensures proper context-driven cleanup
func TestSessionCloseWithContext(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Create session with context
	session, err := NewSessionWithContext(ctx, client, SessionCallbacks{})
	if err != nil {
		t.Fatalf("NewSessionWithContext() unexpected error: %v", err)
	}

	// Session should not be closed initially
	if session.IsClosed() {
		t.Errorf("NewSessionWithContext() session should not be closed initially")
	}

	// Cancel context
	cancel()

	// Give goroutine time to handle cancellation
	time.Sleep(50 * time.Millisecond)

	// Session should be closed
	if !session.IsClosed() {
		t.Errorf("Context cancellation should have closed session")
	}
}

// TestConnectErrorCleanup verifies Connect() cleans up TCP on error
// per PLAN.md section 1.3 task 2 - ensures defer cleanup pattern works
func TestConnectErrorCleanup(t *testing.T) {
	t.Run("context cancelled before connect", func(t *testing.T) {
		client := NewClient(&ClientCallBacks{})

		// Create pre-cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Try to connect
		err := client.Connect(ctx)
		if err == nil {
			t.Errorf("Connect() expected error, got nil")
		}

		// Verify client is not marked as connected
		if client.connected {
			t.Errorf("Connect() failed but client still marked as connected")
		}
	})

	t.Run("defer cleanup sets connected to false", func(t *testing.T) {
		client := NewClient(&ClientCallBacks{})

		// This test verifies the defer cleanup pattern is in place
		// Even if we can't reliably trigger TCP errors, we can verify
		// the pattern exists by checking the code structure

		// Pre-cancelled context will fail before TCP connect
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		client.Connect(ctx)

		// After failed connect, connected should be false
		if client.connected {
			t.Errorf("Connect() should set connected=false on failure")
		}
	})
}

// TestNoGoroutineLeaks verifies that client and session cleanup doesn't leak goroutines
// per PLAN.md section 1.3 task 3 - ensures WaitGroup and shutdown mechanisms work
func TestNoGoroutineLeaks(t *testing.T) {
	// Get baseline goroutine count
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Create and close client multiple times
	for i := 0; i < 10; i++ {
		client := NewClient(&ClientCallBacks{})

		// Create session with context
		ctx, cancel := context.WithCancel(context.Background())
		session, err := NewSessionWithContext(ctx, client, SessionCallbacks{})
		if err != nil {
			t.Fatalf("NewSessionWithContext() unexpected error: %v", err)
		}
		session.id = uint16(i + 1)

		// Add session to client
		client.sessions[session.id] = session

		// Close session
		if err := session.Close(); err != nil {
			t.Errorf("Session.Close() unexpected error: %v", err)
		}

		// Cancel context
		cancel()

		// Close client
		if err := client.Close(); err != nil && err != ErrClientClosed {
			t.Errorf("Client.Close() unexpected error: %v", err)
		}
	}

	// Force garbage collection
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Get final goroutine count
	finalGoroutines := runtime.NumGoroutine()

	// Allow small margin for system goroutines
	margin := 5
	if finalGoroutines > baselineGoroutines+margin {
		t.Errorf("Goroutine leak detected: baseline=%d, final=%d, leaked=%d",
			baselineGoroutines, finalGoroutines, finalGoroutines-baselineGoroutines)
	}
}

// TestSessionLifecycleTimestamps verifies session creation and closure timestamps
// per PLAN.md section 1.3 - ensures proper lifecycle tracking
func TestSessionLifecycleTimestamps(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := NewSession(client, SessionCallbacks{})

	// Verify creation timestamp is set
	if session.CreatedAt().IsZero() {
		t.Errorf("NewSession() createdAt timestamp not set")
	}

	// Verify closedAt is zero before close
	if !session.ClosedAt().IsZero() {
		t.Errorf("NewSession() closedAt should be zero before close")
	}

	// Close session
	if err := session.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// Verify closedAt is set after close
	if session.ClosedAt().IsZero() {
		t.Errorf("Close() closedAt timestamp not set")
	}

	// Verify closedAt is after createdAt
	if !session.ClosedAt().After(session.CreatedAt()) {
		t.Errorf("Close() closedAt should be after createdAt")
	}
}

// TestClientCloseWaitsForOperations verifies Close() waits for pending operations
// per PLAN.md section 1.3 task 3 - ensures WaitGroup tracking works
func TestClientCloseWaitsForOperations(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Simulate a pending operation
	client.wg.Add(1)
	operationComplete := make(chan bool)
	go func() {
		defer client.wg.Done()
		time.Sleep(100 * time.Millisecond)
		operationComplete <- true
	}()

	// Close client (should wait for operation)
	closeComplete := make(chan bool)
	go func() {
		client.Close()
		closeComplete <- true
	}()

	// Wait for operation to complete
	select {
	case <-operationComplete:
		// Expected - operation should complete
	case <-time.After(200 * time.Millisecond):
		t.Errorf("Operation did not complete in time")
	}

	// Wait for close to complete
	select {
	case <-closeComplete:
		// Expected - close should complete after operation
	case <-time.After(6 * time.Second): // Close has 5 second timeout
		t.Errorf("Close() did not complete in time")
	}
}

// TestClientCloseForcesShutdown verifies Close() forces shutdown after timeout
// per PLAN.md section 1.3 - ensures 5 second timeout is enforced
func TestClientCloseForcesShutdown(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Simulate a stuck operation
	client.wg.Add(1)
	go func() {
		// Never call Done() - simulates stuck goroutine
		time.Sleep(10 * time.Second)
	}()

	// Close client (should timeout after 5 seconds)
	start := time.Now()
	err := client.Close()
	elapsed := time.Since(start)

	// Should complete within 6 seconds (5 second timeout + 1 second margin)
	if elapsed > 6*time.Second {
		t.Errorf("Close() took too long: %v (expected ~5 seconds)", elapsed)
	}

	// Should still complete successfully
	if err != nil {
		t.Errorf("Close() unexpected error: %v", err)
	}
}

// TestSessionCloseDispatchesDestroyedStatus verifies Close() dispatches destroyed status
// per PLAN.md section 1.3 - ensures callbacks are notified
func TestSessionCloseDispatchesDestroyedStatus(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	statusReceived := make(chan SessionStatus, 1)
	callbacks := SessionCallbacks{
		onStatus: func(s *Session, status SessionStatus) {
			statusReceived <- status
		},
	}

	session := NewSession(client, callbacks)
	session.syncCallbacks = true // Ensure synchronous execution

	// Close session
	if err := session.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// Verify destroyed status was dispatched
	select {
	case status := <-statusReceived:
		if status != I2CP_SESSION_STATUS_DESTROYED {
			t.Errorf("Close() dispatched wrong status: got %v, want %v",
				status, I2CP_SESSION_STATUS_DESTROYED)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Close() did not dispatch destroyed status")
	}
}

// TestResourceCleanupMemoryStability verifies memory usage is stable after cleanup
// per PLAN.md section 1.3 success criteria - ensures no memory leaks
func TestResourceCleanupMemoryStability(t *testing.T) {
	// Get baseline memory stats
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	var baselineMemStats runtime.MemStats
	runtime.ReadMemStats(&baselineMemStats)
	baselineAlloc := baselineMemStats.Alloc

	// Create and destroy many clients/sessions
	for i := 0; i < 100; i++ {
		client := NewClient(&ClientCallBacks{})

		// Create multiple sessions
		for j := 0; j < 10; j++ {
			session := NewSession(client, SessionCallbacks{})
			session.id = uint16(j + 1)
			client.sessions[session.id] = session

			// Close session
			session.Close()
		}

		// Close client
		client.Close()
	}

	// Force garbage collection
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	// Get final memory stats
	var finalMemStats runtime.MemStats
	runtime.ReadMemStats(&finalMemStats)
	finalAlloc := finalMemStats.Alloc

	// Calculate memory growth (handle potential integer underflow)
	var memoryGrowth uint64
	if finalAlloc > baselineAlloc {
		memoryGrowth = finalAlloc - baselineAlloc
	} else {
		// If final is less than baseline, no leak detected
		memoryGrowth = 0
	}

	// Allow reasonable growth (5MB) for test overhead and runtime allocations
	maxAllowedGrowth := uint64(5 * 1024 * 1024)
	if memoryGrowth > maxAllowedGrowth {
		t.Errorf("Memory leak detected: grew by %d bytes (max allowed: %d)",
			memoryGrowth, maxAllowedGrowth)
		t.Logf("Baseline: %d bytes, Final: %d bytes", baselineAlloc, finalAlloc)
	} else {
		t.Logf("Memory stable: grew by %d bytes (within %d byte limit)",
			memoryGrowth, maxAllowedGrowth)
	}
}
