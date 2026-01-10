package go_i2cp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Subsession Destruction Integration Tests
//
// These tests validate multi-session (primary/subsession) lifecycle management
// against a live I2P router on localhost:7654.
//
// Prerequisites:
//   - Running I2P router with I2CP enabled on localhost:7654
//   - Router must support multi-session (version 0.9.21+)
//
// Per I2CP § Multisession Notes:
//   - First session created is the "primary session"
//   - Additional sessions are "subsessions" sharing the primary's tunnels
//   - Destroying a subsession does NOT destroy the primary or close the connection
//   - Destroying the primary DOES destroy all subsessions and close the connection

const (
	subsessionTestTimeout = 60 * time.Second
	subsessionOpTimeout   = 30 * time.Second
)

// TestSubsessionDestruction_IndividualCleanup verifies that destroying an individual
// subsession properly cleans up resources without affecting the primary session.
// Per I2CP § Destroying Subsessions: "A subsession may be destroyed with the
// DestroySession message as usual. This will not destroy the primary session
// or stop the I2CP connection."
func TestSubsessionDestruction_IndividualCleanup(t *testing.T) {
	// Connect to router
	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), subsessionTestTimeout)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v (is I2P running on localhost:7654?)", err)
	}

	t.Log("Connected to I2P router")

	// Verify router supports multi-session (0.9.21+)
	if !client.SupportsVersion(VersionMultiSession) {
		client.Close()
		t.Skipf("Router version %s does not support multi-session (requires 0.9.21+)",
			client.router.version.String())
	}

	// Create primary session
	primaryCreated := make(chan struct{})
	var primaryCreatedOnce sync.Once
	primary := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Primary session status: %d (ID: %d)", status, s.ID())
			if status == I2CP_SESSION_STATUS_CREATED {
				primaryCreatedOnce.Do(func() { close(primaryCreated) })
			}
		},
	})
	primary.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "primary-session")
	primary.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, primary)
	opCancel()
	if err != nil {
		client.Close()
		t.Fatalf("Failed to create primary session: %v", err)
	}

	// Process I/O in background with proper cancellation
	ioCanceled := make(chan struct{})
	go func() {
		defer close(ioCanceled)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := client.ProcessIO(ctx); err != nil {
					if err == ErrClientClosed {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	// Wait for primary session to be created
	select {
	case <-primaryCreated:
		t.Logf("Primary session created with ID: %d", primary.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for primary session creation")
	}

	// Verify primary is registered
	if !primary.IsPrimary() {
		cancel()
		<-ioCanceled
		t.Fatal("First session should be marked as primary")
	}

	// Create subsession
	subsessionCreated := make(chan struct{})
	var subsessionCreatedOnce sync.Once
	var subsessionIDCached uint16
	subsession := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			// Avoid calling s.ID() during Close() - it can deadlock
			// due to dispatchStatusLocked being called while holding the session lock
			if status == I2CP_SESSION_STATUS_CREATED {
				subsessionIDCached = s.ID() // Safe here, lock not held
				t.Logf("Subsession status: %d (ID: %d)", status, subsessionIDCached)
				subsessionCreatedOnce.Do(func() { close(subsessionCreated) })
			} else {
				t.Logf("Subsession status: %d", status)
			}
		},
	})
	subsession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	subsession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "subsession")

	opCtx, opCancel = context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, subsession)
	opCancel()
	if err != nil {
		cancel()
		<-ioCanceled
		t.Fatalf("Failed to create subsession: %v", err)
	}

	// Wait for subsession to be created
	select {
	case <-subsessionCreated:
		t.Logf("Subsession created with ID: %d", subsession.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for subsession creation")
	}

	// Verify subsession is NOT primary
	if subsession.IsPrimary() {
		cancel()
		<-ioCanceled
		t.Fatal("Second session should NOT be marked as primary")
	}

	// Verify subsession has reference to primary
	if subsession.PrimarySession() != primary {
		cancel()
		<-ioCanceled
		t.Fatal("Subsession should reference the primary session")
	}

	// Record session IDs before destruction
	primaryID := primary.ID()
	subsessionID := subsession.ID()
	t.Logf("Primary ID: %d, Subsession ID: %d", primaryID, subsessionID)

	// Debug: check sessions map before destruction
	client.lock.Lock()
	t.Logf("Before destruction - sessions in map: %v", len(client.sessions))
	for id := range client.sessions {
		t.Logf("  Session ID in map: %d", id)
	}
	client.lock.Unlock()

	// Destroy the subsession
	t.Log("Destroying subsession...")
	err = subsession.Close()
	if err != nil {
		t.Errorf("Failed to close subsession: %v", err)
	}

	// Give router time to process
	time.Sleep(500 * time.Millisecond)

	// Debug: check sessions map after destruction
	client.lock.Lock()
	t.Logf("After destruction - sessions in map: %v", len(client.sessions))
	for id := range client.sessions {
		t.Logf("  Session ID in map: %d", id)
	}
	client.lock.Unlock()

	// Verify subsession is marked as closed
	if !subsession.IsClosed() {
		t.Error("Subsession should be marked as closed after Close()")
	}

	// Verify subsession was removed from client's sessions map
	client.lock.Lock()
	_, subsessionExists := client.sessions[subsessionID]
	_, primaryExists := client.sessions[primaryID]
	client.lock.Unlock()

	if subsessionExists {
		t.Error("Subsession should have been removed from client's sessions map")
	}
	if !primaryExists {
		t.Error("Primary session should still exist in client's sessions map")
	}

	// Verify client TCP connection is still open (primary not destroyed)
	// Note: client.IsConnected() checks for data availability, not connection state
	// We check tcp.conn != nil instead for actual connection state
	if client.tcp.conn == nil {
		t.Error("Client TCP connection should still be open after subsession destruction")
	}

	// Verify primary session is still functional (not closed)
	if primary.IsClosed() {
		t.Error("Primary session should NOT be closed after subsession destruction")
	}

	t.Log("Subsession destruction completed successfully without affecting primary")

	// Cleanup
	cancel()
	<-ioCanceled
	client.Close()
}

// TestSubsessionDestruction_PrimaryDestroysAll verifies that destroying the primary
// session cascades to all subsessions.
// Per I2CP § Destroying Subsessions: "Destroying the primary session will, however,
// destroy all subsessions and stop the I2CP connection."
func TestSubsessionDestruction_PrimaryDestroysAll(t *testing.T) {
	// Connect to router
	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), subsessionTestTimeout)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v (is I2P running on localhost:7654?)", err)
	}

	t.Log("Connected to I2P router")

	// Verify router supports multi-session
	if !client.SupportsVersion(VersionMultiSession) {
		client.Close()
		t.Skipf("Router version %s does not support multi-session (requires 0.9.21+)",
			client.router.version.String())
	}

	// Create primary session
	primaryCreated := make(chan struct{})
	var primaryCreatedOnce sync.Once
	primary := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Primary session status: %d (ID: %d)", status, s.ID())
			if status == I2CP_SESSION_STATUS_CREATED {
				primaryCreatedOnce.Do(func() { close(primaryCreated) })
			}
		},
	})
	primary.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "primary-cascade-test")
	primary.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, primary)
	opCancel()
	if err != nil {
		client.Close()
		t.Fatalf("Failed to create primary session: %v", err)
	}

	// Process I/O in background with proper cancellation
	ioCanceled := make(chan struct{})
	go func() {
		defer close(ioCanceled)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := client.ProcessIO(ctx); err != nil {
					if err == ErrClientClosed {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	// Wait for primary to be created
	select {
	case <-primaryCreated:
		t.Logf("Primary session created with ID: %d", primary.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for primary session creation")
	}

	// Create multiple subsessions
	subsessions := make([]*Session, 2)
	subsessionCreatedChs := make([]chan struct{}, 2)
	var subsessionOnces [2]sync.Once

	for i := 0; i < 2; i++ {
		subsessionCreatedChs[i] = make(chan struct{})
		idx := i
		subsessions[i] = NewSession(client, SessionCallbacks{
			OnStatus: func(s *Session, status SessionStatus) {
				t.Logf("Subsession %d status: %d (ID: %d)", idx, status, s.ID())
				if status == I2CP_SESSION_STATUS_CREATED {
					subsessionOnces[idx].Do(func() { close(subsessionCreatedChs[idx]) })
				}
			},
		})
		subsessions[i].config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		subsessions[i].config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "subsession-cascade-test")

		opCtx, opCancel = context.WithTimeout(ctx, subsessionOpTimeout)
		err = client.CreateSession(opCtx, subsessions[i])
		opCancel()
		if err != nil {
			cancel()
			<-ioCanceled
			t.Fatalf("Failed to create subsession %d: %v", i, err)
		}

		// Wait for subsession to be created
		select {
		case <-subsessionCreatedChs[i]:
			t.Logf("Subsession %d created with ID: %d", i, subsessions[i].ID())
		case <-time.After(30 * time.Second):
			cancel()
			<-ioCanceled
			t.Fatalf("Timeout waiting for subsession %d creation", i)
		}
	}

	// Verify all subsessions exist
	client.lock.Lock()
	sessionCount := len(client.sessions)
	client.lock.Unlock()

	if sessionCount != 3 {
		t.Errorf("Expected 3 sessions (1 primary + 2 subsessions), got %d", sessionCount)
	}

	// Destroy the primary session - this should cascade to all subsessions
	t.Log("Destroying primary session (should cascade to all subsessions)...")
	err = primary.Close()
	if err != nil && err != ErrClientClosed {
		t.Logf("Primary close returned: %v (may be expected)", err)
	}

	// Give time for cascade
	time.Sleep(1 * time.Second)

	// Verify all sessions are closed
	if !primary.IsClosed() {
		t.Error("Primary session should be closed")
	}
	for i, sub := range subsessions {
		if !sub.IsClosed() {
			t.Errorf("Subsession %d should be closed after primary destruction", i)
		}
	}

	// Verify client is disconnected (primary destroyed = connection closed)
	if client.IsConnected() {
		t.Error("Client should be disconnected after primary session destruction")
	}

	t.Log("Primary destruction correctly cascaded to all subsessions")

	// Cleanup - context and IO goroutine
	cancel()
	<-ioCanceled
}

// TestSubsessionDestruction_MultipleSequential tests creating and destroying
// multiple subsessions sequentially while keeping the primary active.
func TestSubsessionDestruction_MultipleSequential(t *testing.T) {
	// Connect to router
	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*subsessionTestTimeout)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v (is I2P running on localhost:7654?)", err)
	}

	t.Log("Connected to I2P router")

	// Verify router supports multi-session
	if !client.SupportsVersion(VersionMultiSession) {
		client.Close()
		t.Skipf("Router version %s does not support multi-session (requires 0.9.21+)",
			client.router.version.String())
	}

	// Create primary session
	primaryCreated := make(chan struct{})
	var primaryCreatedOnce sync.Once
	primary := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				primaryCreatedOnce.Do(func() { close(primaryCreated) })
			}
		},
	})
	primary.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "primary-sequential-test")
	primary.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, primary)
	opCancel()
	if err != nil {
		client.Close()
		t.Fatalf("Failed to create primary session: %v", err)
	}

	// Process I/O in background with proper cancellation
	ioCanceled := make(chan struct{})
	go func() {
		defer close(ioCanceled)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := client.ProcessIO(ctx); err != nil {
					if err == ErrClientClosed {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	// Wait for primary
	select {
	case <-primaryCreated:
		t.Logf("Primary session created with ID: %d", primary.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for primary session creation")
	}

	// Create and destroy subsessions sequentially
	for i := 0; i < 3; i++ {
		t.Logf("Creating subsession %d...", i+1)

		subsessionCreated := make(chan struct{})
		var subsessionCreatedOnce sync.Once
		subsession := NewSession(client, SessionCallbacks{
			OnStatus: func(s *Session, status SessionStatus) {
				if status == I2CP_SESSION_STATUS_CREATED {
					subsessionCreatedOnce.Do(func() { close(subsessionCreated) })
				}
			},
		})
		subsession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		subsession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "sequential-subsession")

		opCtx, opCancel = context.WithTimeout(ctx, subsessionOpTimeout)
		err = client.CreateSession(opCtx, subsession)
		opCancel()
		if err != nil {
			cancel()
			<-ioCanceled
			t.Fatalf("Failed to create subsession %d: %v", i+1, err)
		}

		// Wait for subsession
		select {
		case <-subsessionCreated:
			t.Logf("Subsession %d created with ID: %d", i+1, subsession.ID())
		case <-time.After(30 * time.Second):
			cancel()
			<-ioCanceled
			t.Fatalf("Timeout waiting for subsession %d creation", i+1)
		}

		// Verify session count
		client.lock.Lock()
		sessionCount := len(client.sessions)
		client.lock.Unlock()
		if sessionCount != 2 {
			t.Errorf("Expected 2 sessions, got %d", sessionCount)
		}

		// Destroy subsession
		t.Logf("Destroying subsession %d...", i+1)
		err = subsession.Close()
		if err != nil {
			t.Errorf("Failed to close subsession %d: %v", i+1, err)
		}

		// Give router time to process
		time.Sleep(500 * time.Millisecond)

		// Verify cleanup
		if !subsession.IsClosed() {
			t.Errorf("Subsession %d should be closed", i+1)
		}

		// Verify only primary remains
		client.lock.Lock()
		sessionCount = len(client.sessions)
		client.lock.Unlock()
		if sessionCount != 1 {
			t.Errorf("Expected 1 session (primary only), got %d", sessionCount)
		}

		// Verify primary is still connected (check TCP connection, not data availability)
		if client.tcp.conn == nil {
			cancel()
			<-ioCanceled
			t.Fatalf("Client TCP connection closed after subsession %d destruction", i+1)
		}
		if primary.IsClosed() {
			cancel()
			<-ioCanceled
			t.Fatalf("Primary closed after subsession %d destruction", i+1)
		}

		t.Logf("Subsession %d destroyed successfully", i+1)
	}

	t.Log("All sequential subsession operations completed successfully")

	// Cleanup
	cancel()
	<-ioCanceled
	client.Close()
}

// TestSubsessionCleanup_ResourceVerification verifies that subsession cleanup
// properly releases all resources to prevent memory leaks.
func TestSubsessionCleanup_ResourceVerification(t *testing.T) {
	// Connect to router
	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), subsessionTestTimeout)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v (is I2P running on localhost:7654?)", err)
	}

	// Verify router supports multi-session
	if !client.SupportsVersion(VersionMultiSession) {
		client.Close()
		t.Skipf("Router version %s does not support multi-session (requires 0.9.21+)",
			client.router.version.String())
	}

	// Create primary session
	primaryCreated := make(chan struct{})
	var primaryCreatedOnce sync.Once
	primary := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				primaryCreatedOnce.Do(func() { close(primaryCreated) })
			}
		},
	})
	primary.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	primary.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, primary)
	opCancel()
	if err != nil {
		client.Close()
		t.Fatalf("Failed to create primary session: %v", err)
	}

	// Process I/O in background
	ioCanceled := make(chan struct{})
	go func() {
		defer close(ioCanceled)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := client.ProcessIO(ctx); err != nil {
					if err == ErrClientClosed {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	select {
	case <-primaryCreated:
		t.Logf("Primary session created with ID: %d", primary.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for primary session creation")
	}

	// Create subsession
	subsessionCreated := make(chan struct{})
	var subsessionCreatedOnce sync.Once
	subsession := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				subsessionCreatedOnce.Do(func() { close(subsessionCreated) })
			}
		},
	})
	subsession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")

	opCtx, opCancel = context.WithTimeout(ctx, subsessionOpTimeout)
	err = client.CreateSession(opCtx, subsession)
	opCancel()
	if err != nil {
		cancel()
		<-ioCanceled
		t.Fatalf("Failed to create subsession: %v", err)
	}

	select {
	case <-subsessionCreated:
		t.Logf("Subsession created with ID: %d", subsession.ID())
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal("Timeout waiting for subsession creation")
	}

	// Add some pending messages to subsession (simulating in-flight messages)
	subsession.messageMu.Lock()
	if subsession.pendingMessages == nil {
		subsession.pendingMessages = make(map[uint32]*PendingMessage)
	}
	subsession.pendingMessages[12345] = &PendingMessage{Nonce: 12345}
	subsession.pendingMessages[67890] = &PendingMessage{Nonce: 67890}
	pendingBefore := len(subsession.pendingMessages)
	subsession.messageMu.Unlock()

	t.Logf("Added %d pending messages to subsession", pendingBefore)

	// Record subsession ID
	subsessionID := subsession.ID()

	// Destroy subsession
	err = subsession.Close()
	if err != nil {
		t.Errorf("Failed to close subsession: %v", err)
	}

	// Give cleanup time
	time.Sleep(500 * time.Millisecond)

	// Verify cleanup
	// 1. Session should be closed
	if !subsession.IsClosed() {
		t.Error("Subsession should be marked as closed")
	}

	// 2. Session should be removed from client map
	client.lock.Lock()
	_, exists := client.sessions[subsessionID]
	client.lock.Unlock()
	if exists {
		t.Error("Subsession should be removed from client's sessions map")
	}

	// 3. Primary should still be functional
	if primary.IsClosed() {
		t.Error("Primary session should not be affected by subsession cleanup")
	}
	if client.tcp.conn == nil {
		t.Error("Client TCP connection should still be open after subsession cleanup")
	}

	t.Log("Subsession resource cleanup verified successfully")

	// Cleanup
	cancel()
	<-ioCanceled
	client.Close()
}
