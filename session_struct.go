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
	// Blinding key derivation is NOW IMPLEMENTED in blinding_crypto.go
	//
	// Current Status:
	//   - ✅ BlindingInfoMessage received and parsed correctly
	//   - ✅ Blinding parameters stored in session
	//   - ✅ Blinding key derivation IMPLEMENTED (DeriveBlindingFactor, BlindPublicKey, etc.)
	//   - ❌ Encrypted LeaseSet decryption NOT implemented
	//   - ❌ Per-client authentication NOT fully integrated
	//
	// Implemented Functions (see blinding_crypto.go):
	//   - DeriveBlindingFactor(secret, date) - HKDF-SHA256 derivation per I2P Proposal 123
	//   - BlindPublicKey(publicKey, alpha) - Ed25519 point blinding
	//   - BlindPrivateKey(privateKey, alpha) - Ed25519 scalar blinding
	//   - UnblindPublicKey(blindedPublicKey, alpha) - Reverse operation
	//   - DeriveBlindingKeys/DeriveBlindingKeysWithPrivate - Complete derivation
	//   - Session.DeriveBlindingKeysForDestination(date) - Session helper
	//
	// For encrypted LeaseSet access, applications must still implement:
	//   1. LeaseSet decryption: crypto.DecryptLeaseSet2(encryptedLS, derivedKey)
	//   2. Per-client auth integration with BlindingInfoMessage parameters
	//
	// See I2CP § BlindingInfoMessage and § Encrypted LeaseSet2 for specifications.
	blindingScheme uint16 // Blinding cryptographic scheme (0 = disabled, 1 = DH, 2 = PSK)
	blindingFlags  uint16 // Blinding flags per I2CP spec (bit 0 = per-client auth required)
	blindingParams []byte // Scheme-specific blinding parameters

	// Encryption key pair for LeaseSet2 (X25519 when i2cp.leaseSetEncType=4)
	// Generated when creating LeaseSet2 response to RequestVariableLeaseSet
	encryptionKeyPair *X25519KeyPair

	// Leases from RequestVariableLeaseSet
	// These are the actual tunnel leases provided by the router
	leases []*Lease

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

	// destroyedDispatched tracks whether DESTROYED status has been dispatched
	// to prevent duplicate callbacks during concurrent close operations
	destroyedDispatched bool
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
