package go_i2cp

import (
	"context"
	"fmt"
	"time"
)

// RetryWithBackoff executes a function with exponential backoff retry logic.
// It respects context cancellation and distinguishes between temporary and fatal errors.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - maxRetries: Maximum number of retry attempts (0 = no retries, negative = infinite)
//   - initialBackoff: Initial delay between retries (doubles each attempt)
//   - fn: Function to execute, should return nil on success
//
// The backoff strategy uses exponential backoff with a cap at 5 minutes:
//   - Attempt 1: initialBackoff
//   - Attempt 2: initialBackoff * 2
//   - Attempt 3: initialBackoff * 4
//   - ...continuing to double up to a maximum of 5 minutes
//
// Fatal errors (those not implementing Temporary() bool or returning false)
// cause immediate return without further retries.
//
// Example:
//
//	err := RetryWithBackoff(ctx, 5, time.Second, func() error {
//	    return client.Connect(ctx)
//	})
//	if err != nil {
//	    log.Printf("Failed after retries: %v", err)
//	}
func RetryWithBackoff(ctx context.Context, maxRetries int, initialBackoff time.Duration, fn func() error) error {
	const maxBackoff = 5 * time.Minute

	attempt := 0
	backoff := initialBackoff

	for {
		// Try to execute the function
		err := fn()

		// Success!
		if err == nil {
			if attempt > 0 {
				Debug("Retry succeeded after %d attempts", attempt)
			}
			return nil
		}

		// Check if error is temporary
		if !isTemporary(err) {
			Debug("Encountered fatal error (not retrying): %v", err)
			return fmt.Errorf("fatal error: %w", err)
		}

		// Check if we've exhausted retries
		attempt++
		if maxRetries >= 0 && attempt > maxRetries {
			return fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, err)
		}

		// Check context cancellation before sleeping
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled after %d attempts: %w", attempt, ctx.Err())
		default:
		}

		// Log and wait before retrying
		Debug("Retry attempt %d failed: %v (waiting %v before retry)", attempt, err, backoff)

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled during backoff after %d attempts: %w", attempt, ctx.Err())
		case <-time.After(backoff):
			// Continue to next attempt
		}

		// Exponential backoff with cap
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// isTemporary checks if an error is temporary and should be retried.
// It checks for errors implementing the Temporary() bool interface.
func isTemporary(err error) bool {
	// Check if error implements Temporary() interface
	type temporary interface {
		Temporary() bool
	}

	if temp, ok := err.(temporary); ok {
		return temp.Temporary()
	}

	// If no Temporary() method, assume it's temporary
	// (conservative approach - retry by default)
	return true
}

// RetryableFunc is a function that can be retried.
// It should return an error implementing Temporary() for retry control.
type RetryableFunc func() error

// MaxRetriesExceededError is returned when the maximum number of retries is exceeded.
type MaxRetriesExceededError struct {
	Attempts int
	LastErr  error
}

func (e *MaxRetriesExceededError) Error() string {
	return fmt.Sprintf("max retries (%d) exceeded: %v", e.Attempts, e.LastErr)
}

func (e *MaxRetriesExceededError) Unwrap() error {
	return e.LastErr
}
