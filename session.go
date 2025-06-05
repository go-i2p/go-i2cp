package go_i2cp

func NewSession(client *Client, callbacks SessionCallbacks) (sess *Session) {
	sess = &Session{}
	sess.client = client
	dest, _ := NewDestination()
	sess.config = &SessionConfig{destination: dest}
	sess.callbacks = &callbacks
	return
}
func (session *Session) SendMessage(destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) {
	session.client.msgSendMessage(session, destination, protocol, srcPort, destPort, payload, nonce, true)
}
func (session *Session) Destination() *Destination {
	return session.config.destination
}
func (session *Session) dispatchMessage(protocol uint8, srcPort, destPort uint16, payload *Stream) {
	if session.callbacks == nil || session.callbacks.onMessage == nil {
		return
	}
	session.callbacks.onMessage(session, protocol, srcPort, destPort, payload)
}

func (session *Session) dispatchDestination(requestId uint32, address string, destination *Destination) {
	if session.callbacks == nil || session.callbacks.onDestination == nil {
		return
	}
	session.callbacks.onDestination(session, requestId, address, destination)
}

func (session *Session) dispatchStatus(status SessionStatus) {
	switch status {
	case I2CP_SESSION_STATUS_CREATED:
		Debug(SESSION, "Session %p is created", session)
	case I2CP_SESSION_STATUS_DESTROYED:
		Debug(SESSION, "Session %p is destroyed", session)
	case I2CP_SESSION_STATUS_UPDATED:
		Debug(SESSION, "Session %p is updated", session)
	case I2CP_SESSION_STATUS_INVALID:
		Debug(SESSION, "Session %p is invalid", session)
	}
	if session.callbacks == nil || session.callbacks.onStatus == nil {
		return
	}
	session.callbacks.onStatus(session, status)
}
