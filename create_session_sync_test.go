package go_i2cp

import (
	"context"
	"testing"
	"time"
)

// TestCreateSessionSync verifies that CreateSessionSync works correctly
// This test ensures the fix for the "CreateSession hangs with Java I2P router" bug
func TestCreateSessionSync(t *testing.T) {
	// This test requires a running I2P router on 127.0.0.1:7654
	// Skip if not available
	t.Skip("Requires running I2P router - manual test only")

	client := NewClient(&ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to router
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Create session with status tracking
	statusReceived := false
	session := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				statusReceived = true
				t.Logf("Session %d created", s.ID())
			}
		},
	})

	// Create session synchronously
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.CreateSessionSync(ctx, session)
	if err != nil {
		t.Fatalf("CreateSessionSync failed: %v", err)
	}

	// Verify session was created
	if session.ID() == 0 {
		t.Error("Session ID not assigned")
	}

	if !statusReceived {
		t.Error("OnStatus callback not invoked")
	}

	t.Logf("Session created successfully with ID %d", session.ID())
}

// TestCreateSessionAsync verifies the async pattern with manual ProcessIO
func TestCreateSessionAsync(t *testing.T) {
	// This test requires a running I2P router on 127.0.0.1:7654
	// Skip if not available
	t.Skip("Requires running I2P router - manual test only")

	client := NewClient(&ClientCallBacks{})

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Start ProcessIO loop
	processIOCtx, cancelProcessIO := context.WithCancel(context.Background())
	defer cancelProcessIO()

	processIOErrors := make(chan error, 10)
	go func() {
		for {
			select {
			case <-processIOCtx.Done():
				return
			default:
			}

			err := client.ProcessIO(processIOCtx)
			if err != nil {
				if err != ErrClientClosed {
					processIOErrors <- err
				}
				return
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Give ProcessIO time to start
	time.Sleep(500 * time.Millisecond)

	// Create session
	sessionReady := make(chan bool, 1)
	session := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				t.Logf("Session %d created via callback", s.ID())
				sessionReady <- true
			}
		},
	})

	err = client.CreateSession(ctx, session)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Wait for session creation
	select {
	case <-sessionReady:
		t.Logf("Session created successfully with ID %d", session.ID())
	case err := <-processIOErrors:
		t.Fatalf("ProcessIO error: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("Timeout waiting for session creation")
	}

	// Verify session
	if session.ID() == 0 {
		t.Error("Session ID not assigned")
	}
}

// Benchmark CreateSessionSync performance
func BenchmarkCreateSessionSync(b *testing.B) {
	b.Skip("Requires running I2P router - manual test only")

	client := NewClient(&ClientCallBacks{})

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		b.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		session := NewSession(client, SessionCallbacks{})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = client.CreateSessionSync(ctx, session)
		cancel()

		if err != nil {
			b.Fatalf("CreateSessionSync failed: %v", err)
		}

		// Clean up session
		session.Close()
	}
}
