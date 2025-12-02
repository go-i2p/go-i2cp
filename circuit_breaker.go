package go_i2cp

import (
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the current state of a circuit breaker.
type CircuitState string

const (
	// CircuitClosed means the circuit is allowing requests through normally.
	CircuitClosed CircuitState = "closed"

	// CircuitOpen means the circuit is blocking requests due to too many failures.
	CircuitOpen CircuitState = "open"

	// CircuitHalfOpen means the circuit is testing if the service has recovered.
	CircuitHalfOpen CircuitState = "half-open"
)

// CircuitBreaker implements the circuit breaker pattern to prevent cascading failures.
// It monitors operation failures and automatically opens the circuit after a threshold,
// preventing additional attempts that are likely to fail. After a timeout period,
// it transitions to half-open state to test if the service has recovered.
//
// States:
//   - Closed: Normal operation, failures are counted
//   - Open: Circuit is tripped, all operations fail fast without attempting
//   - Half-Open: Testing recovery, limited operations allowed
//
// This is particularly useful for I2CP router connections to prevent hammering
// a router that is down or overloaded.
type CircuitBreaker struct {
	maxFailures  int           // Number of failures before opening circuit
	resetTimeout time.Duration // How long to wait before attempting half-open
	failures     int           // Current failure count
	lastFailure  time.Time     // When the last failure occurred
	state        CircuitState  // Current circuit state
	mu           sync.Mutex    // Protects all fields
}

// NewCircuitBreaker creates a new circuit breaker with the specified parameters.
//
// Parameters:
//   - maxFailures: Number of consecutive failures before opening the circuit
//   - resetTimeout: Duration to wait in open state before attempting half-open
//
// Example:
//
//	// Open circuit after 3 failures, try recovery after 30 seconds
//	cb := NewCircuitBreaker(3, 30*time.Second)
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Execute runs the given function if the circuit breaker allows it.
// Returns an error if the circuit is open or if the function fails.
//
// The circuit breaker tracks the success/failure of the operation and
// automatically manages state transitions.
//
// Example:
//
//	err := circuitBreaker.Execute(func() error {
//	    return client.Connect(ctx)
//	})
//	if err != nil {
//	    if circuitBreaker.IsOpen() {
//	        // Circuit is open, don't retry immediately
//	    }
//	}
func (cb *CircuitBreaker) Execute(fn func() error) error {
	// Check if we can execute
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	// Execute the function
	err := fn()

	// Record the result
	cb.afterRequest(err)

	return err
}

// beforeRequest checks if the circuit allows the request.
// Returns an error if the circuit is open.
func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitOpen:
		// Check if we should transition to half-open
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
			Debug("Circuit breaker transitioning to half-open state")
			return nil
		}
		return fmt.Errorf("circuit breaker is open (last failure: %v ago)",
			time.Since(cb.lastFailure).Round(time.Second))

	case CircuitHalfOpen:
		// Allow one request in half-open state
		return nil

	case CircuitClosed:
		// Normal operation
		return nil

	default:
		return fmt.Errorf("circuit breaker in unknown state: %s", cb.state)
	}
}

// afterRequest records the result of a request and updates circuit state.
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.recordFailure()
	} else {
		cb.recordSuccess()
	}
}

// recordFailure increments the failure count and opens circuit if threshold reached.
func (cb *CircuitBreaker) recordFailure() {
	cb.failures++
	cb.lastFailure = time.Now()

	switch cb.state {
	case CircuitClosed:
		// Don't open circuit if maxFailures is 0 (never open automatically)
		if cb.maxFailures > 0 && cb.failures >= cb.maxFailures {
			cb.state = CircuitOpen
			Debug("Circuit breaker opened after %d failures", cb.failures)
		}

	case CircuitHalfOpen:
		// Failed during half-open test, go back to open
		cb.state = CircuitOpen
		Debug("Circuit breaker re-opened after half-open failure")
	}
}

// recordSuccess resets the failure count and closes the circuit.
func (cb *CircuitBreaker) recordSuccess() {
	switch cb.state {
	case CircuitHalfOpen:
		// Success in half-open state means we can close the circuit
		cb.state = CircuitClosed
		cb.failures = 0
		Debug("Circuit breaker closed after successful half-open test")

	case CircuitClosed:
		// Reset failure count on success
		cb.failures = 0
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// IsOpen returns true if the circuit is currently open.
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.State() == CircuitOpen
}

// IsClosed returns true if the circuit is currently closed.
func (cb *CircuitBreaker) IsClosed() bool {
	return cb.State() == CircuitClosed
}

// IsHalfOpen returns true if the circuit is currently half-open.
func (cb *CircuitBreaker) IsHalfOpen() bool {
	return cb.State() == CircuitHalfOpen
}

// Failures returns the current failure count.
func (cb *CircuitBreaker) Failures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}

// Reset manually resets the circuit breaker to closed state with zero failures.
// This is useful for testing or manual intervention.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitClosed
	cb.failures = 0
	Debug("Circuit breaker manually reset")
}

// String returns a human-readable representation of the circuit breaker state.
func (cb *CircuitBreaker) String() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return fmt.Sprintf("CircuitBreaker{state=%s, failures=%d/%d, lastFailure=%v}",
		cb.state, cb.failures, cb.maxFailures,
		time.Since(cb.lastFailure).Round(time.Second))
}
