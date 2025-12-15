package go_i2cp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRetryWithBackoffSuccess tests successful execution without retries
func TestRetryWithBackoffSuccess(t *testing.T) {
	callCount := 0

	err := RetryWithBackoff(context.Background(), 3, time.Millisecond, func() error {
		callCount++
		return nil
	})
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}
}

// TestRetryWithBackoffEventualSuccess tests retry until success
func TestRetryWithBackoffEventualSuccess(t *testing.T) {
	callCount := 0
	maxCalls := 3

	err := RetryWithBackoff(context.Background(), 5, time.Millisecond, func() error {
		callCount++
		if callCount < maxCalls {
			return errors.New("temporary error")
		}
		return nil
	})
	if err != nil {
		t.Errorf("Expected success after retries, got %v", err)
	}

	if callCount != maxCalls {
		t.Errorf("Expected %d calls, got %d", maxCalls, callCount)
	}
}

// TestRetryWithBackoffMaxRetriesExceeded tests max retries limit
func TestRetryWithBackoffMaxRetriesExceeded(t *testing.T) {
	callCount := 0
	testErr := errors.New("persistent error")

	err := RetryWithBackoff(context.Background(), 3, time.Millisecond, func() error {
		callCount++
		return testErr
	})

	if err == nil {
		t.Error("Expected error after max retries exceeded")
	}

	// Should be called initial attempt + 3 retries = 4 total
	if callCount != 4 {
		t.Errorf("Expected 4 calls (1 initial + 3 retries), got %d", callCount)
	}
}

// TestRetryWithBackoffContextCancellation tests context cancellation
func TestRetryWithBackoffContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	// Cancel after first failure
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := RetryWithBackoff(ctx, 10, 50*time.Millisecond, func() error {
		callCount++
		return errors.New("test error")
	})

	if err == nil {
		t.Error("Expected error from context cancellation")
	}

	if callCount > 2 {
		t.Errorf("Expected ≤2 calls before cancellation, got %d", callCount)
	}
}

// TestRetryWithBackoffContextTimeout tests context timeout
func TestRetryWithBackoffContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	callCount := 0

	err := RetryWithBackoff(ctx, 100, 50*time.Millisecond, func() error {
		callCount++
		return errors.New("test error")
	})

	if err == nil {
		t.Error("Expected error from context timeout")
	}

	// Should have made a few attempts before timeout
	if callCount < 1 {
		t.Error("Expected at least one call before timeout")
	}

	if callCount > 5 {
		t.Errorf("Expected few calls before timeout, got %d", callCount)
	}
}

// TestRetryWithBackoffZeroRetries tests with no retries allowed
func TestRetryWithBackoffZeroRetries(t *testing.T) {
	callCount := 0
	testErr := errors.New("test error")

	err := RetryWithBackoff(context.Background(), 0, time.Millisecond, func() error {
		callCount++
		return testErr
	})

	if err == nil {
		t.Error("Expected error with zero retries")
	}

	// Should only call once (no retries)
	if callCount != 1 {
		t.Errorf("Expected 1 call (no retries), got %d", callCount)
	}
}

// TestRetryWithBackoffInfiniteRetries tests infinite retry mode
func TestRetryWithBackoffInfiniteRetries(t *testing.T) {
	callCount := 0
	maxCalls := 10

	err := RetryWithBackoff(context.Background(), -1, time.Millisecond, func() error {
		callCount++
		if callCount >= maxCalls {
			return nil // Success after many attempts
		}
		return errors.New("test error")
	})
	if err != nil {
		t.Errorf("Expected success with infinite retries, got %v", err)
	}

	if callCount != maxCalls {
		t.Errorf("Expected %d calls, got %d", maxCalls, callCount)
	}
}

// TestRetryWithBackoffBackoffProgression tests that backoff increases
func TestRetryWithBackoffBackoffProgression(t *testing.T) {
	callTimes := []time.Time{}

	RetryWithBackoff(context.Background(), 3, 10*time.Millisecond, func() error {
		callTimes = append(callTimes, time.Now())
		return errors.New("test error")
	})

	if len(callTimes) < 2 {
		t.Fatal("Not enough calls to test backoff progression")
	}

	// Check that delays increase (approximately)
	for i := 1; i < len(callTimes)-1; i++ {
		delay1 := callTimes[i].Sub(callTimes[i-1])
		delay2 := callTimes[i+1].Sub(callTimes[i])

		// Second delay should be roughly 2x first (with some tolerance)
		if delay2 < delay1 {
			t.Errorf("Backoff not increasing: delay%d=%v, delay%d=%v",
				i, delay1, i+1, delay2)
		}
	}
}

// TestIsTemporaryForRetry tests the isTemporary error checking in retry logic
func TestIsTemporaryForRetry(t *testing.T) {
	// Error without Temporary() method - should default to true
	err1 := errors.New("regular error")
	if !isTemporary(err1) {
		t.Error("Regular errors should be considered temporary")
	}

	// Test with temporary error
	tempErr := &temporaryErrorRetry{temporary: true}
	if !isTemporary(tempErr) {
		t.Error("temporaryError{true} should be temporary")
	}

	// Test with non-temporary error
	fatalErr := &temporaryErrorRetry{temporary: false}
	if isTemporary(fatalErr) {
		t.Error("temporaryError{false} should not be temporary")
	}
}

// TestRetryWithBackoffFatalError tests that fatal errors stop retries
func TestRetryWithBackoffFatalError(t *testing.T) {
	callCount := 0
	fatalErr := &temporaryErrorRetry{
		err:       errors.New("fatal error"),
		temporary: false,
	}

	err := RetryWithBackoff(context.Background(), 5, time.Millisecond, func() error {
		callCount++
		return fatalErr
	})

	if err == nil {
		t.Error("Expected error from fatal error")
	}

	// Should only be called once (no retries for fatal errors)
	if callCount != 1 {
		t.Errorf("Expected 1 call for fatal error, got %d", callCount)
	}
}

// temporaryErrorRetry is a test error type that implements Temporary()
type temporaryErrorRetry struct {
	err       error
	temporary bool
}

func (e *temporaryErrorRetry) Error() string {
	return e.err.Error()
}

func (e *temporaryErrorRetry) Temporary() bool {
	return e.temporary
}
