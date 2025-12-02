// SessionCallbacks struct definition
// Moved from: session.go
package go_i2cp

// SessionCallbacks provides callback functions for session events
type SessionCallbacks struct {
	OnMessage       func(session *Session, protocol uint8, srcPort, destPort uint16, payload *Stream)
	OnStatus        func(session *Session, status SessionStatus)
	OnDestination   func(session *Session, requestId uint32, address string, dest *Destination)
	OnMessageStatus func(session *Session, messageId uint32, status SessionMessageStatus, size, nonce uint32)
}
