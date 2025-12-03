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
//	    OnMessage: func(s *Session, protocol uint8, srcPort, destPort uint16, payload *Stream) {
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

	// Wrap the session callbacks to intercept status changes
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

	// Start ProcessIO in background goroutine
	processIOCtx, cancelProcessIO := context.WithCancel(ctx)
	defer cancelProcessIO()

	processIODone := make(chan struct{})
	go func() {
		defer close(processIODone)
		Debug("CreateSessionSync: Starting ProcessIO loop")

		for {
			select {
			case <-processIOCtx.Done():
				Debug("CreateSessionSync: ProcessIO context cancelled")
				return
			default:
			}

			err := c.ProcessIO(processIOCtx)
			if err != nil {
				// Only log errors that aren't expected during shutdown
				if err != ErrClientClosed && processIOCtx.Err() == nil {
					Warning("CreateSessionSync: ProcessIO error: %v", err)
				}
				return
			}

			// Small sleep to prevent busy loop
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Send CreateSession message (async, waits for ProcessIO to handle response)
	Debug("CreateSessionSync: Sending CreateSession message")
	if err := c.CreateSession(ctx, sess); err != nil {
		cancelProcessIO()
		return fmt.Errorf("failed to send CreateSession: %w", err)
	}

	// Wait for session creation confirmation or timeout
	select {
	case err := <-sessionCreated:
		cancelProcessIO()
		if err != nil {
			return fmt.Errorf("session creation failed: %w", err)
		}
		Debug("CreateSessionSync: Session created successfully, ID=%d", sess.id)
		return nil

	case <-ctx.Done():
		cancelProcessIO()
		return fmt.Errorf("session creation timeout: %w", ctx.Err())
	}
}
