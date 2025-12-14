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
//
// shouldRetryAfterError determines if a retry should occur based on the error type and attempt count.
// Returns an error if retry should not occur (either fatal error or max retries exceeded), nil otherwise.
func shouldRetryAfterError(err error, attempt int, maxRetries int) error {
	// Check if error is temporary
	if !isTemporary(err) {
		Debug("Encountered fatal error (not retrying): %v", err)
		return fmt.Errorf("fatal error: %w", err)
	}

	// Check if we've exhausted retries
	if maxRetries >= 0 && attempt > maxRetries {
		return fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, err)
	}

	return nil
}

// checkContextCancellation checks if the context has been cancelled and returns an appropriate error.
// Returns nil if context is still active.
func checkContextCancellation(ctx context.Context, attempt int, phase string) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("retry cancelled %s after %d attempts: %w", phase, attempt, ctx.Err())
	default:
		return nil
	}
}

// waitWithBackoff sleeps for the specified backoff duration while respecting context cancellation.
// Returns an error if context is cancelled during the wait.
func waitWithBackoff(ctx context.Context, backoff time.Duration, attempt int, err error) error {
	Debug("Retry attempt %d failed: %v (waiting %v before retry)", attempt, err, backoff)

	select {
	case <-ctx.Done():
		return fmt.Errorf("retry cancelled during backoff after %d attempts: %w", attempt, ctx.Err())
	case <-time.After(backoff):
		return nil
	}
}

// calculateNextBackoff computes the next backoff duration using exponential backoff with a maximum cap.
func calculateNextBackoff(current time.Duration, maxBackoff time.Duration) time.Duration {
	next := current * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

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

		// Increment attempt counter
		attempt++

		// Determine if we should retry
		if retryErr := shouldRetryAfterError(err, attempt, maxRetries); retryErr != nil {
			return retryErr
		}

		// Check context cancellation before sleeping
		if ctxErr := checkContextCancellation(ctx, attempt, "before backoff"); ctxErr != nil {
			return ctxErr
		}

		// Wait before retrying
		if waitErr := waitWithBackoff(ctx, backoff, attempt, err); waitErr != nil {
			return waitErr
		}

		// Calculate next backoff duration
		backoff = calculateNextBackoff(backoff, maxBackoff)
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
