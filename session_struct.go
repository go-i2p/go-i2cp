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

	// Message tracking (Phase 2.3)
	// Tracks pending messages from send to status callback
	pendingMessages map[uint32]*PendingMessage // key: nonce
	messageMu       sync.RWMutex               // Separate mutex for message tracking

	// Thread safety
	mu sync.RWMutex

	// Callback behavior control (for testing)
	syncCallbacks bool
}

// PendingMessage represents a message awaiting delivery status
// Tracks messages from SendMessage call to MessageStatus callback
type PendingMessage struct {
	Nonce       uint32               // Message nonce (unique identifier)
	Destination *Destination         // Target destination
	Protocol    uint8                // Protocol identifier
	SrcPort     uint16               // Source port
	DestPort    uint16               // Destination port
	PayloadSize uint32               // Payload size in bytes
	SentAt      time.Time            // When message was sent
	Status      SessionMessageStatus // Current delivery status (0 if pending)
	CompletedAt time.Time            // When status was received (zero if pending)
	Flags       uint16               // Message flags (for SendMessageExpires)
	Expiration  uint64               // Expiration time in seconds (0 if no expiration)
}
