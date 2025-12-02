// Session struct definition
// Moved from: session.go
package go_i2cp

import (
	"context"
	"sync"
	"time"
)

// Session represents an I2CP session with modern concurrency and lifecycle management
// per I2CP specification - supports primary/subsession relationships and proper resource cleanup
type Session struct {
	// Core session data
	id        uint16
	config    *SessionConfig
	client    *Client
	callbacks *SessionCallbacks

	// Multi-session support (I2CP 0.9.21+)
	isPrimary      bool
	primarySession *Session

	// Lifecycle management
	created  time.Time
	closed   bool
	closedAt time.Time

	// Context and cancellation support
	ctx    context.Context
	cancel context.CancelFunc

	// Blinding support (I2CP 0.9.43+)
	// Enables encrypted LeaseSet access with blinding parameters
	blindingScheme uint16 // Blinding cryptographic scheme (0 = disabled)
	blindingFlags  uint16 // Blinding flags per I2CP spec
	blindingParams []byte // Scheme-specific blinding parameters

	// Thread safety
	mu sync.RWMutex

	// Callback behavior control (for testing)
	syncCallbacks bool
}
