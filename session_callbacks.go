// SessionCallbacks struct definition
// Moved from: session.go
package go_i2cp

// SessionCallbacks provides callback functions for session events.
// All callbacks are optional and can be set to nil if not needed.
// Callbacks may be invoked concurrently, so implementations should be thread-safe.
//
// Example:
//
//	callbacks := SessionCallbacks{
//	    OnMessage: func(sess *Session, proto uint8, src, dest uint16, payload *Stream) {
//	        log.Printf("Received message: protocol=%d, ports=%d->%d", proto, src, dest)
//	    },
//	    OnMessageStatus: func(sess *Session, msgId uint32, status SessionMessageStatus, size, nonce uint32) {
//	        log.Printf("Message %d status: %v", msgId, status)
//	    },
//	}
//	session := NewSession(client, callbacks)
type SessionCallbacks struct {
	// OnMessage is called when a message is received from another I2P destination.
	// Parameters:
	//   - session: The session that received the message
	//   - srcDest: Source I2P destination that sent the message
	//   - protocol: Protocol number (application-defined)
	//   - srcPort: Source port (application-defined)
	//   - destPort: Destination port (application-defined)
	//   - payload: Message payload as a Stream (can be read with ReadUint*/ReadBytes methods)
	OnMessage func(session *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream)

	// OnStatus is called when the session status changes.
	// Parameters:
	//   - session: The session whose status changed
	//   - status: New session status (e.g., SessionCreated, SessionDestroyed)
	OnStatus func(session *Session, status SessionStatus)

	// OnDestination is called when a destination lookup completes.
	// Parameters:
	//   - session: The session that requested the lookup
	//   - requestId: Request identifier from the original lookup call
	//   - address: Destination address that was looked up (Base32 or Base64)
	//   - dest: Resolved destination, or nil if lookup failed
	OnDestination func(session *Session, requestId uint32, address string, dest *Destination)

	// OnMessageStatus is called when a sent message's delivery status is updated.
	// Useful for tracking message delivery and implementing reliable messaging.
	// Parameters:
	//   - session: The session that sent the message
	//   - messageId: Message nonce/identifier from SendMessage
	//   - status: Delivery status (e.g., SendSuccess, SendFailure)
	//   - size: Message size in bytes
	//   - nonce: Message nonce (same as messageId)
	OnMessageStatus func(session *Session, messageId uint32, status SessionMessageStatus, size, nonce uint32)

	// OnLeaseSet2 is called when the router requests LeaseSet publication via RequestVariableLeaseSetMessage.
	// I2CP 0.9.38+ - The router provides lease information; the client creates and publishes the LeaseSet2.
	// Note: This is NOT triggered when receiving a remote destination's LeaseSet - use DestLookup for that.
	// Parameters:
	//   - session: The session that received the LeaseSet request
	//   - leaseSet: The LeaseSet2 structure with destination, leases, and signature to publish
	//
	// Example:
	//
	//	OnLeaseSet2: func(sess *Session, ls *LeaseSet2) {
	//	    log.Printf("LeaseSet2: type=%d, expires=%s", ls.Type(), ls.Expires())
	//	    if ls.IsExpired() {
	//	        log.Println("WARNING: LeaseSet expired")
	//	    }
	//	}
	OnLeaseSet2 func(session *Session, leaseSet *LeaseSet2)

	// OnBlindingInfo is called when the router provides blinding information for encrypted LeaseSet access.
	// I2CP 0.9.43+ - Used for password-protected or key-protected destinations.
	// Parameters:
	//   - session: The session that received blinding info
	//   - blindingScheme: Authentication scheme (0=DH, 1=PSK)
	//   - blindingFlags: Flags indicating required authentication
	//   - blindingParams: Blinding parameters (store securely for future access)
	//
	// Important: Store blindingParams securely - they're required to access encrypted destinations.
	//
	// Example:
	//
	//	OnBlindingInfo: func(sess *Session, scheme, flags uint16, params []byte) {
	//	    log.Printf("Blinding enabled: scheme=%d, flags=%d", scheme, flags)
	//	    // Store params securely for future connections
	//	    if err := storeBlindingParams(params); err != nil {
	//	        log.Printf("Failed to store blinding params: %v", err)
	//	    }
	//	}
	OnBlindingInfo func(session *Session, blindingScheme, blindingFlags uint16, blindingParams []byte)

	// OnMetaLeaseSet is called when a send attempt fails because the destination uses a MetaLeaseSet.
	// I2CP 0.9.41+ (MessageStatus code 22) - Indicates multi-homed destination requiring resolution.
	// Parameters:
	//   - session: The session that attempted to send
	//   - originalDest: The MetaLeaseSet destination that was targeted
	//   - messageNonce: Nonce of the failed message (for retry tracking)
	//
	// Recovery procedure:
	//  1. Call session.LookupDestination() with the originalDest hash to retrieve MetaLeaseSet contents
	//  2. Parse the MetaLeaseSet to extract available destination hashes
	//  3. Select one hash (application logic - e.g., random, round-robin, or preference-based)
	//  4. Retry SendMessage using the selected destination hash
	//
	// Example:
	//
	//	OnMetaLeaseSet: func(sess *Session, dest *Destination, nonce uint32) {
	//	    log.Printf("Destination is MetaLeaseSet, resolving...")
	//	    // Request MetaLeaseSet contents via HostLookup
	//	    sess.LookupDestination(dest.Base64())
	//	    // In OnDestination callback, parse meta and select actual destination
	//	}
	OnMetaLeaseSet func(session *Session, originalDest *Destination, messageNonce uint32)
}
