package go_i2cp

import (
	"context"
	"fmt"
	"time"
)

// CreateSessionSync creates a session and waits synchronously for confirmation from the router.
// This is a convenience wrapper around CreateSession that handles the ProcessIO loop internally
// and blocks until the session is confirmed or the timeout expires.
//
// IMPORTANT: This function will block until:
//  1. The router confirms the session (I2CP_SESSION_STATUS_CREATED), OR
//  2. The context expires/is cancelled, OR
//  3. The router rejects the session (I2CP_SESSION_STATUS_INVALID)
//
// This function is suitable for simple applications and testing. For production use with
// multiple sessions or complex I/O patterns, use the async CreateSession with manual ProcessIO.
//
// Parameters:
//   - ctx: Context for timeout/cancellation (recommended: 30 second timeout)
//   - sess: Session to create (must have callbacks configured if needed)
//
// Returns:
//   - nil if session created successfully
//   - error if creation failed, timed out, or context cancelled
//
// Example:
//
//	session := NewSession(client, SessionCallbacks{
//	    OnMessage: func(s *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
//	        fmt.Println("Received message!")
//	    },
//	})
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//
//	if err := client.CreateSessionSync(ctx, session); err != nil {
//	    log.Fatalf("Session creation failed: %v", err)
//	}
//
//	fmt.Println("Session created successfully!")
func (c *Client) CreateSessionSync(ctx context.Context, sess *Session) error {
	// Ensure client was properly initialized
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	// Validate parameters
	if sess == nil {
		return fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}

	// Create channel to signal session creation
	sessionCreated := make(chan error, 1)

	// Wrap callbacks to intercept status changes and disconnects
	wrapSessionCallbacks(sess, sessionCreated)
	restoreDisconnect := wrapClientDisconnectCallback(c, sessionCreated)
	defer restoreDisconnect()

	// Start ProcessIO in background
	processIOCtx, cancelProcessIO := context.WithCancel(ctx)
	defer cancelProcessIO()

	go c.runProcessIOLoop(processIOCtx)

	// Send CreateSession message
	Debug("CreateSessionSync: Sending CreateSession message")
	if err := c.CreateSession(ctx, sess); err != nil {
		return fmt.Errorf("failed to send CreateSession: %w", err)
	}

	// Wait for confirmation or timeout
	return c.awaitSessionCreation(ctx, sess, sessionCreated, cancelProcessIO)
}

// wrapSessionCallbacks wraps the session's OnStatus callback to intercept session creation events.
// It signals completion through the provided channel when the session is created, rejected, or destroyed.
func wrapSessionCallbacks(sess *Session, sessionCreated chan<- error) {
	originalOnStatus := sess.callbacks.OnStatus
	sess.callbacks.OnStatus = func(s *Session, status SessionStatus) {
		// Call original callback if present
		if originalOnStatus != nil {
			originalOnStatus(s, status)
		}

		// Signal session creation completion
		switch status {
		case I2CP_SESSION_STATUS_CREATED:
			Debug("CreateSessionSync: Session %d created", s.id)
			sessionCreated <- nil
		case I2CP_SESSION_STATUS_INVALID:
			Debug("CreateSessionSync: Session rejected by router")
			sessionCreated <- fmt.Errorf("session rejected by router: status INVALID")
		case I2CP_SESSION_STATUS_DESTROYED:
			Debug("CreateSessionSync: Session destroyed before creation confirmed")
			sessionCreated <- fmt.Errorf("session destroyed: %w", ErrSessionInvalid)
		}
	}
}

// wrapClientDisconnectCallback wraps the client's OnDisconnect callback to catch router disconnects
// during session creation. Returns a function to restore the original callback.
func wrapClientDisconnectCallback(c *Client, sessionCreated chan<- error) func() {
	if c.callbacks == nil {
		return func() {}
	}

	originalOnDisconnect := c.callbacks.OnDisconnect
	c.callbacks.OnDisconnect = createDisconnectWrapper(originalOnDisconnect, sessionCreated)

	return func() {
		c.callbacks.OnDisconnect = originalOnDisconnect
	}
}

// createDisconnectWrapper creates a wrapped disconnect callback that signals session creation failures.
func createDisconnectWrapper(original func(*Client, string, *interface{}), sessionCreated chan<- error) func(*Client, string, *interface{}) {
	return func(client *Client, reason string, opaque *interface{}) {
		invokeOriginalDisconnect(original, client, reason, opaque)
		signalDisconnectError(sessionCreated, reason)
	}
}

// invokeOriginalDisconnect calls the original disconnect callback if present.
func invokeOriginalDisconnect(original func(*Client, string, *interface{}), client *Client, reason string, opaque *interface{}) {
	if original != nil {
		original(client, reason, opaque)
	}
}

// signalDisconnectError signals session creation failure due to disconnect.
func signalDisconnectError(sessionCreated chan<- error, reason string) {
	Debug("CreateSessionSync: Router disconnected during session creation: %s", reason)
	select {
	case sessionCreated <- fmt.Errorf("router disconnected during session creation: %s", reason):
	default:
	}
}

// runProcessIOLoop runs the ProcessIO loop in a background goroutine until the context is cancelled.
// It handles I/O processing with error logging and prevents busy loops with periodic sleeps.
func (c *Client) runProcessIOLoop(ctx context.Context) {
	Debug("CreateSessionSync: Starting ProcessIO loop")

	for {
		if shouldStopProcessIO(ctx) {
			return
		}

		if err := c.processIOWithErrorHandling(ctx); err != nil {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// shouldStopProcessIO checks if the context is cancelled and should stop processing.
func shouldStopProcessIO(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		Debug("CreateSessionSync: ProcessIO context cancelled")
		return true
	default:
		return false
	}
}

// processIOWithErrorHandling processes I/O and handles errors appropriately.
func (c *Client) processIOWithErrorHandling(ctx context.Context) error {
	err := c.ProcessIO(ctx)
	if err != nil {
		if err != ErrClientClosed && ctx.Err() == nil {
			Warning("CreateSessionSync: ProcessIO error: %v", err)
		}
		return err
	}
	return nil
}

// awaitSessionCreation waits for session creation confirmation or timeout.
// It returns nil on successful creation, or an error if the session was rejected or the context expired.
func (c *Client) awaitSessionCreation(ctx context.Context, sess *Session, sessionCreated <-chan error, cancel context.CancelFunc) error {
	select {
	case err := <-sessionCreated:
		cancel()
		if err != nil {
			return fmt.Errorf("session creation failed: %w", err)
		}
		Debug("CreateSessionSync: Session created successfully, ID=%d", sess.id)
		return nil

	case <-ctx.Done():
		cancel()
		return fmt.Errorf("session creation timeout: %w", ctx.Err())
	}
}
