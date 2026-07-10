package go_i2cp

// temporaryError is a test helper type that implements both the Error and
// Temporary interfaces. This is used by tests to simulate temporary errors.
type temporaryError struct {
	msg       string
	temporary bool
}

func (e *temporaryError) Error() string {
	return e.msg
}

func (e *temporaryError) Temporary() bool {
	return e.temporary
}

// newTemporaryError creates a new temporary error with the given message and temporary flag.
func newTemporaryError(msg string, temporary bool) *temporaryError {
	return &temporaryError{
		msg:       msg,
		temporary: temporary,
	}
}
