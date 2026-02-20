package go_i2cp

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestNewCircuitBreaker tests circuit breaker initialization
func TestNewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)

	if cb == nil {
		t.Fatal("NewCircuitBreaker returned nil")
	}

	if cb.State() != CircuitClosed {
		t.Errorf("Initial state = %v, want %v", cb.State(), CircuitClosed)
	}

	if cb.Failures() != 0 {
		t.Errorf("Initial failures = %d, want 0", cb.Failures())
	}
}

// TestCircuitBreakerClosedToOpen tests transition from closed to open state
func TestCircuitBreakerClosedToOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)
	testErr := errors.New("test error")

	// Should be closed initially
	if !cb.IsClosed() {
		t.Error("Circuit should be closed initially")
	}

	// Execute failing operations
	for i := 0; i < 3; i++ {
		err := cb.Execute(func() error {
			return testErr
		})
		if err != testErr {
			t.Errorf("Execute() = %v, want %v", err, testErr)
		}
	}

	// Should be open now
	if !cb.IsOpen() {
		t.Errorf("Circuit should be open after %d failures", cb.maxFailures)
	}

	if cb.Failures() != 3 {
		t.Errorf("Failures = %d, want 3", cb.Failures())
	}
}

// TestCircuitBreakerOpenRejectsRequests tests that open circuit rejects requests
func TestCircuitBreakerOpenRejectsRequests(t *testing.T) {
	cb := NewCircuitBreaker(2, 100*time.Millisecond)
	testErr := errors.New("test error")

	// Trip the circuit
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return testErr })
	}

	if !cb.IsOpen() {
		t.Fatal("Circuit should be open")
	}

	// Attempt to execute - should fail immediately without calling function
	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if called {
		t.Error("Function should not be called when circuit is open")
	}

	if err == nil {
		t.Error("Execute() should return error when circuit is open")
	}
}

// TestCircuitBreakerHalfOpenTransition tests transition to half-open state
func TestCircuitBreakerHalfOpenTransition(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	testErr := errors.New("test error")

	// Trip the circuit
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return testErr })
	}

	if !cb.IsOpen() {
		t.Fatal("Circuit should be open")
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Next execution should transition to half-open
	called := false
	cb.Execute(func() error {
		called = true
		return nil // Success
	})

	if !called {
		t.Error("Function should be called in half-open state")
	}

	// Should be closed after successful half-open test
	if !cb.IsClosed() {
		t.Error("Circuit should be closed after successful half-open test")
	}

	if cb.Failures() != 0 {
		t.Errorf("Failures should be reset to 0, got %d", cb.Failures())
	}
}

// TestCircuitBreakerHalfOpenFailure tests half-open failure reopens circuit
func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	testErr := errors.New("test error")

	// Trip the circuit
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return testErr })
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Fail the half-open test
	cb.Execute(func() error { return testErr })

	// Should be open again
	if !cb.IsOpen() {
		t.Error("Circuit should be open after half-open failure")
	}
}

// TestCircuitBreakerSuccessResetsFailures tests that success resets failure count
func TestCircuitBreakerSuccessResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)
	testErr := errors.New("test error")

	// Fail twice (not enough to open)
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return testErr })
	}

	if cb.Failures() != 2 {
		t.Errorf("Failures = %d, want 2", cb.Failures())
	}

	// Succeed once
	cb.Execute(func() error { return nil })

	// Failures should be reset
	if cb.Failures() != 0 {
		t.Errorf("Failures = %d, want 0 after success", cb.Failures())
	}

	if !cb.IsClosed() {
		t.Error("Circuit should remain closed")
	}
}

// TestCircuitBreakerReset tests manual reset
func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(2, 30*time.Second)
	testErr := errors.New("test error")

	// Trip the circuit
	for i := 0; i < 2; i++ {
		cb.Execute(func() error { return testErr })
	}

	if !cb.IsOpen() {
		t.Fatal("Circuit should be open")
	}

	// Manual reset
	cb.Reset()

	if !cb.IsClosed() {
		t.Error("Circuit should be closed after reset")
	}

	if cb.Failures() != 0 {
		t.Errorf("Failures = %d, want 0 after reset", cb.Failures())
	}
}

// TestCircuitBreakerConcurrency tests thread-safety
func TestCircuitBreakerConcurrency(t *testing.T) {
	cb := NewCircuitBreaker(10, 100*time.Millisecond)
	var wg sync.WaitGroup
	numGoroutines := 20

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.Execute(func() error {
					if j%3 == 0 {
						return errors.New("test error")
					}
					return nil
				})
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Should not panic and should have valid state
	state := cb.State()
	if state != CircuitClosed && state != CircuitOpen && state != CircuitHalfOpen {
		t.Errorf("Invalid state: %v", state)
	}
}

// TestCircuitBreakerString tests String() method
func TestCircuitBreakerString(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)

	str := cb.String()
	if str == "" {
		t.Error("String() returned empty string")
	}

	// Should contain state information
	if !containsSubstring(str, "state=") {
		t.Error("String() should contain state information")
	}
}

// TestCircuitBreakerStates tests state query methods
func TestCircuitBreakerStates(t *testing.T) {
	cb := NewCircuitBreaker(1, 50*time.Millisecond)

	// Initially closed
	if !cb.IsClosed() || cb.IsOpen() || cb.IsHalfOpen() {
		t.Error("Initial state should be closed only")
	}

	// Trip to open
	cb.Execute(func() error { return errors.New("fail") })
	if cb.IsClosed() || !cb.IsOpen() || cb.IsHalfOpen() {
		t.Error("State should be open only after failure")
	}

	// Transition to half-open
	time.Sleep(60 * time.Millisecond)
	cb.Execute(func() error { return nil })

	// Should be closed again
	if !cb.IsClosed() || cb.IsOpen() || cb.IsHalfOpen() {
		t.Error("State should be closed only after successful half-open")
	}
}

// TestCircuitBreakerZeroFailures tests circuit with max failures = 0
func TestCircuitBreakerZeroFailures(t *testing.T) {
	cb := NewCircuitBreaker(0, 30*time.Second)

	// Single failure should not open circuit (maxFailures=0 means never open)
	err := cb.Execute(func() error {
		return fmt.Errorf("test error")
	})

	if err == nil {
		t.Error("Expected error from failed execution")
	}

	// Circuit should remain closed with maxFailures=0
	if !cb.IsClosed() {
		t.Error("Circuit should remain closed with maxFailures=0")
	}
}
