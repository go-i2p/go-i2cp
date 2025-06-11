// SessionCallbacks struct definition
// Moved from: session.go
package go_i2cp

// SessionCallbacks provides callback functions for session events
type SessionCallbacks struct {
	onMessage       func(session *Session, protocol uint8, srcPort, destPort uint16, payload *Stream)
	onStatus        func(session *Session, status SessionStatus)
	onDestination   func(session *Session, requestId uint32, address string, dest *Destination)
	onMessageStatus func(session *Session, messageId uint32, status SessionMessageStatus, size, nonce uint32)
}
