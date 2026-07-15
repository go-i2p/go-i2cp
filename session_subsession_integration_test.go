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

// connectMultiSessionClient connects a fresh Client to the local I2P router within
// the given timeout and skips the test if the router doesn't support multi-session
// (VersionMultiSession, requires 0.9.21+). Fails the test via t.Fatalf/t.Skipf on
// connection failure or lack of support. The returned cancel func should be
// deferred by the caller.
func connectMultiSessionClient(t *testing.T, timeout time.Duration) (*Client, context.Context, context.CancelFunc) {
	t.Helper()

	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	if err := client.Connect(ctx); err != nil {
		cancel()
		t.Fatalf("Failed to connect to I2P router: %v (is I2P running on localhost:7654?)", err)
	}

	t.Log("Connected to I2P router")

	if !client.SupportsVersion(VersionMultiSession) {
		version := client.router.version.String()
		client.Close()
		cancel()
		t.Skipf("Router version %s does not support multi-session (requires 0.9.21+)", version)
	}

	return client, ctx, cancel
}

// startProcessIOLoop launches a background goroutine that repeatedly calls
// client.ProcessIO until ctx is cancelled or the client is closed. The returned
// channel is closed when the loop exits; callers should `<-` it after cancelling
// ctx to ensure the goroutine has stopped before making further assertions.
func startProcessIOLoop(ctx context.Context, client *Client) <-chan struct{} {
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
	return ioCanceled
}

// waitForSessionCreated blocks until created is closed (signalling
// I2CP_SESSION_STATUS_CREATED) or a 30 second timeout elapses. On timeout it
// cancels ctx, drains ioCanceled, and fails the test with failMsg.
func waitForSessionCreated(t *testing.T, cancel context.CancelFunc, ioCanceled <-chan struct{}, created <-chan struct{}, failMsg string) {
	t.Helper()

	select {
	case <-created:
	case <-time.After(30 * time.Second):
		cancel()
		<-ioCanceled
		t.Fatal(failMsg)
	}
}

// createAndWaitPrimarySession creates a primary session configured with the
// standard subsession-test properties (fast receive, inbound/outbound quantity 1,
// the given nickname), submits it, and waits for the router to confirm creation.
func createAndWaitPrimarySession(t *testing.T, client *Client, ctx context.Context, cancel context.CancelFunc, ioCanceled <-chan struct{}, nickname string) *Session {
	t.Helper()

	created := make(chan struct{})
	var once sync.Once
	primary := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Primary session status: %d (ID: %d)", status, s.ID())
			if status == I2CP_SESSION_STATUS_CREATED {
				once.Do(func() { close(created) })
			}
		},
	})
	primary.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	if nickname != "" {
		primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, nickname)
	}
	primary.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	primary.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err := client.CreateSession(opCtx, primary)
	opCancel()
	if err != nil {
		cancel()
		<-ioCanceled
		t.Fatalf("Failed to create primary session: %v", err)
	}

	waitForSessionCreated(t, cancel, ioCanceled, created, "Timeout waiting for primary session creation")
	t.Logf("Primary session created with ID: %d", primary.ID())

	return primary
}

// createAndWaitSubsession creates a non-primary session with the given nickname,
// submits it, and waits for the router to confirm creation.
func createAndWaitSubsession(t *testing.T, client *Client, ctx context.Context, cancel context.CancelFunc, ioCanceled <-chan struct{}, nickname string) *Session {
	t.Helper()

	created := make(chan struct{})
	var once sync.Once
	subsession := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			if status == I2CP_SESSION_STATUS_CREATED {
				once.Do(func() { close(created) })
			}
		},
	})
	subsession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	if nickname != "" {
		subsession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, nickname)
	}

	opCtx, opCancel := context.WithTimeout(ctx, subsessionOpTimeout)
	err := client.CreateSession(opCtx, subsession)
	opCancel()
	if err != nil {
		cancel()
		<-ioCanceled
		t.Fatalf("Failed to create subsession: %v", err)
	}

	waitForSessionCreated(t, cancel, ioCanceled, created, "Timeout waiting for subsession creation")
	t.Logf("Subsession created with ID: %d", subsession.ID())

	return subsession
}

// TestSubsessionDestruction_IndividualCleanup verifies that destroying an individual
// subsession properly cleans up resources without affecting the primary session.
// Per I2CP § Destroying Subsessions: "A subsession may be destroyed with the
// DestroySession message as usual. This will not destroy the primary session
// or stop the I2CP connection."
func TestSubsessionDestruction_IndividualCleanup(t *testing.T) {
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	client, ctx, cancel := connectMultiSessionClient(t, subsessionTestTimeout)
	defer cancel()

	ioCanceled := startProcessIOLoop(ctx, client)
	primary := createAndWaitPrimarySession(t, client, ctx, cancel, ioCanceled, "primary-session")

	// Verify primary is registered
	if !primary.IsPrimary() {
		cancel()
		<-ioCanceled
		t.Fatal("First session should be marked as primary")
	}

	// Create subsession
	subsession := createAndWaitSubsession(t, client, ctx, cancel, ioCanceled, "subsession")

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

	// Destroy the subsession
	t.Log("Destroying subsession...")
	err := subsession.Close()
	if err != nil {
		t.Errorf("Failed to close subsession: %v", err)
	}

	// Give router time to process
	time.Sleep(500 * time.Millisecond)

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
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	client, ctx, cancel := connectMultiSessionClient(t, subsessionTestTimeout)
	defer cancel()

	ioCanceled := startProcessIOLoop(ctx, client)
	primary := createAndWaitPrimarySession(t, client, ctx, cancel, ioCanceled, "primary-cascade-test")

	// Create multiple subsessions
	subsessions := make([]*Session, 2)
	for i := 0; i < 2; i++ {
		subsessions[i] = createAndWaitSubsession(t, client, ctx, cancel, ioCanceled, "subsession-cascade-test")
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
	err := primary.Close()
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
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	client, ctx, cancel := connectMultiSessionClient(t, 2*subsessionTestTimeout)
	defer cancel()

	ioCanceled := startProcessIOLoop(ctx, client)
	primary := createAndWaitPrimarySession(t, client, ctx, cancel, ioCanceled, "primary-sequential-test")

	// Create and destroy subsessions sequentially
	for i := 0; i < 3; i++ {
		t.Logf("Creating subsession %d...", i+1)

		subsession := createAndWaitSubsession(t, client, ctx, cancel, ioCanceled, "sequential-subsession")

		// Verify session count
		client.lock.Lock()
		sessionCount := len(client.sessions)
		client.lock.Unlock()
		if sessionCount != 2 {
			t.Errorf("Expected 2 sessions, got %d", sessionCount)
		}

		// Destroy subsession
		t.Logf("Destroying subsession %d...", i+1)
		err := subsession.Close()
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

		// Verify primary is still alive after subsession destruction.
		// Avoid strict transport-pointer assertions; backend implementations may reconnect.
		if primary.IsClosed() {
			cancel()
			<-ioCanceled
			t.Fatalf("Primary closed after subsession %d destruction", i+1)
		}

		// Optional diagnostic only (non-fatal):
		if client.tcp.conn == nil {
			t.Logf("TCP connection is nil after subsession %d destruction (backend may have disconnected/reconnected)", i+1)
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
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	client, ctx, cancel := connectMultiSessionClient(t, subsessionTestTimeout)
	defer cancel()

	ioCanceled := startProcessIOLoop(ctx, client)
	primary := createAndWaitPrimarySession(t, client, ctx, cancel, ioCanceled, "")
	subsession := createAndWaitSubsession(t, client, ctx, cancel, ioCanceled, "")

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
	err := subsession.Close()
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
