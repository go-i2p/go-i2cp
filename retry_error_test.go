package go_i2cp

import (
	"errors"
	"strings"
	"testing"
)

// TestMaxRetriesExceededError verifies MaxRetriesExceededError implementation
func TestMaxRetriesExceededError(t *testing.T) {
	baseErr := errors.New("connection refused")

	retryErr := &MaxRetriesExceededError{
		Attempts: 5,
		LastErr:  baseErr,
	}

	// Test Error() method
	errMsg := retryErr.Error()
	if !strings.Contains(errMsg, "max retries") {
		t.Errorf("expected error message to contain 'max retries', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "5") {
		t.Errorf("expected error message to contain attempt count '5', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "connection refused") {
		t.Errorf("expected error message to contain underlying error, got: %s", errMsg)
	}

	// Test Unwrap() method
	unwrapped := retryErr.Unwrap()
	if unwrapped != baseErr {
		t.Errorf("expected Unwrap() to return base error, got: %v", unwrapped)
	}
}

// TestMaxRetriesExceededErrorWithNilLastErr verifies behavior with nil last error
func TestMaxRetriesExceededErrorWithNilLastErr(t *testing.T) {
	retryErr := &MaxRetriesExceededError{
		Attempts: 3,
		LastErr:  nil,
	}

	// Test Error() doesn't panic with nil LastErr
	errMsg := retryErr.Error()
	if !strings.Contains(errMsg, "max retries") {
		t.Errorf("expected error message to contain 'max retries', got: %s", errMsg)
	}

	// Test Unwrap() returns nil
	unwrapped := retryErr.Unwrap()
	if unwrapped != nil {
		t.Errorf("expected Unwrap() to return nil, got: %v", unwrapped)
	}
}

// TestMaxRetriesExceededErrorZeroAttempts verifies behavior with zero attempts
func TestMaxRetriesExceededErrorZeroAttempts(t *testing.T) {
	retryErr := &MaxRetriesExceededError{
		Attempts: 0,
		LastErr:  errors.New("immediate failure"),
	}

	errMsg := retryErr.Error()
	if !strings.Contains(errMsg, "0") {
		t.Errorf("expected error message to contain '0' attempts, got: %s", errMsg)
	}
}

// TestMaxRetriesExceededErrorChaining verifies error wrapping chain
func TestMaxRetriesExceededErrorChaining(t *testing.T) {
	baseErr := errors.New("network error")
	retryErr := &MaxRetriesExceededError{
		Attempts: 3,
		LastErr:  baseErr,
	}

	// Test errors.Is() works with unwrapping
	if !errors.Is(retryErr, baseErr) {
		t.Error("expected errors.Is() to find base error through Unwrap()")
	}

	// Test errors.As() works for type checking
	var maxRetryErr *MaxRetriesExceededError
	if !errors.As(retryErr, &maxRetryErr) {
		t.Error("expected errors.As() to match MaxRetriesExceededError type")
	}
	if maxRetryErr.Attempts != 3 {
		t.Errorf("expected attempts to be 3, got: %d", maxRetryErr.Attempts)
	}
}

// TestMaxRetriesExceededErrorWithWrappedError verifies nested error wrapping
func TestMaxRetriesExceededErrorWithWrappedError(t *testing.T) {
	rootErr := errors.New("root cause")
	wrappedErr := errors.New("wrapped: " + rootErr.Error())
	retryErr := &MaxRetriesExceededError{
		Attempts: 2,
		LastErr:  wrappedErr,
	}

	// Verify error chain
	unwrapped := retryErr.Unwrap()
	if unwrapped != wrappedErr {
		t.Errorf("expected unwrapped error to be wrappedErr, got: %v", unwrapped)
	}

	// Verify Error() includes wrapped error message
	errMsg := retryErr.Error()
	if !strings.Contains(errMsg, "wrapped:") {
		t.Errorf("expected error message to include wrapped error, got: %s", errMsg)
	}
}

// TestMaxRetriesExceededErrorFormattingConsistency verifies consistent formatting
func TestMaxRetriesExceededErrorFormattingConsistency(t *testing.T) {
	testCases := []struct {
		name     string
		attempts int
		lastErr  error
	}{
		{"single attempt", 1, errors.New("error1")},
		{"multiple attempts", 10, errors.New("error2")},
		{"large attempt count", 999, errors.New("error3")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			retryErr := &MaxRetriesExceededError{
				Attempts: tc.attempts,
				LastErr:  tc.lastErr,
			}

			errMsg := retryErr.Error()

			// Verify format: "max retries (%d) exceeded: %v"
			expectedPattern := "max retries ("
			if !strings.HasPrefix(errMsg, expectedPattern) {
				t.Errorf("expected error to start with '%s', got: %s", expectedPattern, errMsg)
			}

			if !strings.Contains(errMsg, "exceeded:") {
				t.Errorf("expected error to contain 'exceeded:', got: %s", errMsg)
			}
		})
	}
}
