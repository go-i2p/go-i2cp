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
	// MINOR FIX: Blinding/Offline Signature Limitations Documentation
	//
	// These fields store blinding parameters from BlindingInfoMessage, but the
	// cryptographic operations required to USE them are not yet implemented.
	//
	// Current Status:
	//   - ✅ BlindingInfoMessage received and parsed correctly
	//   - ✅ Blinding parameters stored in session
	//   - ❌ Blinding key derivation NOT implemented
	//   - ❌ Encrypted LeaseSet decryption NOT implemented
	//   - ❌ Per-client authentication NOT implemented
	//
	// Impact:
	//   - Encrypted LeaseSets with DH/PSK authentication will be stored but unusable
	//   - Applications requiring blinded destinations should verify router.version >= 0.9.43
	//     AND implement custom crypto using these stored parameters
	//
	// For encrypted LeaseSet access, applications must implement:
	//   1. Key derivation: crypto.DeriveBlindingKey(blindingParams, privateKey)
	//   2. LeaseSet decryption: crypto.DecryptLeaseSet2(encryptedLS, derivedKey)
	//   3. Per-client auth: crypto.AuthenticateClient(blindingScheme, authData)
	//
	// See I2CP § BlindingInfoMessage and § Encrypted LeaseSet2 for specifications.
	blindingScheme uint16 // Blinding cryptographic scheme (0 = disabled, 1 = DH, 2 = PSK)
	blindingFlags  uint16 // Blinding flags per I2CP spec (bit 0 = per-client auth required)
	blindingParams []byte // Scheme-specific blinding parameters (NOT CRYPTOGRAPHICALLY PROCESSED)

	// Message tracking (Phase 2.3)
	// Tracks pending messages from send to status callback
	pendingMessages map[uint32]*PendingMessage // key: nonce
	messageMu       sync.RWMutex               // Separate mutex for message tracking

	// Thread safety
	mu sync.RWMutex

	// Callback behavior control (for testing)
	syncCallbacks bool

	// DestroySession response tracking (I2CP spec compliance)
	// Closed when SessionStatus(Destroyed) received from router
	destroyConfirmed chan struct{}
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
