package go_i2cp

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// NewSession creates a new I2CP session with the specified client and callbacks
// per I2CP specification - creates session with proper initialization and error handling
// This is the exported version of the session constructor for public API usage
func NewSession(client *Client, callbacks SessionCallbacks) *Session {
	return newSession(client, callbacks)
}

// NewSessionWithContext creates a new I2CP session with context support for timeout control
// per I2CP specification 0.9.21+ - supports multi-session contexts and cancellation
func NewSessionWithContext(ctx context.Context, client *Client, callbacks SessionCallbacks) (*Session, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	session := newSession(client, callbacks)
	session.ctx = ctx

	// Set up context cancellation handler
	if ctx != context.Background() {
		go session.handleContextCancellation(ctx)
	}

	return session, nil
}

func newSession(client *Client, callbacks SessionCallbacks) (sess *Session) {
	sess = &Session{
		mu:            sync.RWMutex{},
		created:       time.Now(),
		isPrimary:     true, // Default to primary session, will be updated for subsessions
		syncCallbacks: true, // Default to synchronous for compatibility with tests
	}
	sess.client = client

	// Create destination with proper error handling
	dest, err := NewDestination(client.crypto)
	if err != nil {
		// Log error but continue with nil destination - will be handled later
		Error("Failed to create destination for new session: %v", err)
	}

	sess.config = &SessionConfig{destination: dest}
	sess.callbacks = &callbacks
	sess.ctx = context.Background() // Default context

	return
}

// SendMessage sends a basic message without expiration control
// per I2CP specification - implements basic message delivery via SendMessageMessage (type 5)
func (session *Session) SendMessage(destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) error {
	if session.client == nil {
		return fmt.Errorf("session not connected to client")
	}

	if destination == nil {
		return fmt.Errorf("destination cannot be nil")
	}

	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	// Use structured logging with session context
	Debug("Sending message from session %d: protocol=%d, srcPort=%d, destPort=%d, nonce=%d",
		session.id, protocol, srcPort, destPort, nonce)

	return session.client.msgSendMessage(session, destination, protocol, srcPort, destPort, payload, nonce, true)
}

// SendMessageWithContext sends a message with context support for timeout control
// per I2CP specification - implements context-aware message delivery with cancellation
func (session *Session) SendMessageWithContext(ctx context.Context, destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before sending message: %w", ctx.Err())
	default:
	}

	// Set up timeout handling
	errChan := make(chan error, 1)
	go func() {
		errChan <- session.SendMessage(destination, protocol, srcPort, destPort, payload, nonce)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("message send cancelled: %w", ctx.Err())
	}
}

// ReconfigureSession updates session configuration with new properties
// per I2CP specification section 7.1 - supports dynamic tunnel and crypto parameter updates
// Returns error if reconfiguration fails or properties are invalid
func (session *Session) ReconfigureSession(properties map[string]string) error {
	if session.client == nil {
		return fmt.Errorf("session not connected to client")
	}

	if properties == nil || len(properties) == 0 {
		return fmt.Errorf("properties cannot be nil or empty")
	}

	Debug("Reconfiguring session %d with %d properties", session.id, len(properties))

	// Log each property for debugging
	for key, value := range properties {
		Debug("Reconfigure property: %s = %s", key, value)
	}

	return session.client.msgReconfigureSession(session, properties, true)
}

// ReconfigureSessionWithContext updates session configuration with context support
// per I2CP specification section 7.1 - implements context-aware reconfiguration with timeout
func (session *Session) ReconfigureSessionWithContext(ctx context.Context, properties map[string]string) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before reconfiguration: %w", ctx.Err())
	default:
	}

	// Set up timeout handling
	errChan := make(chan error, 1)
	go func() {
		errChan <- session.ReconfigureSession(properties)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("session reconfiguration cancelled: %w", ctx.Err())
	}
}

// Destination returns the session's destination
// per I2CP specification - provides access to session destination for addressing
func (session *Session) Destination() *Destination {
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.config == nil {
		return nil
	}
	return session.config.destination
}

// ID returns the session ID assigned by the router
// per I2CP specification - unique identifier for session within I2CP connection
func (session *Session) ID() uint16 {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.id
}

// SetID sets the session ID (internal use only)
// per I2CP specification - called by client when session is created by router
func (session *Session) SetID(id uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.id = id

	Debug("Session ID set to %d", id)
}

// IsPrimary returns whether this is a primary session or subsession
// per I2CP specification 0.9.21+ - primary sessions own tunnel pools, subsessions share them
func (session *Session) IsPrimary() bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.isPrimary
}

// SetPrimary sets the primary session flag (internal use only)
// per I2CP specification 0.9.21+ - used for multi-session support
func (session *Session) SetPrimary(isPrimary bool) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.isPrimary = isPrimary

	Debug("Session %d primary status set to %t", session.id, isPrimary)
}

// PrimarySession returns the primary session for this subsession
// per I2CP specification 0.9.21+ - subsessions reference their primary for tunnel sharing
func (session *Session) PrimarySession() *Session {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.primarySession
}

// SetPrimarySession sets the primary session reference (internal use only)
// per I2CP specification 0.9.21+ - links subsession to primary for resource sharing
func (session *Session) SetPrimarySession(primary *Session) error {
	if primary == nil {
		return fmt.Errorf("primary session cannot be nil")
	}

	if !primary.IsPrimary() {
		return fmt.Errorf("referenced session is not a primary session")
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	session.primarySession = primary
	session.isPrimary = false

	Debug("Session %d linked to primary session %d", session.id, primary.id)
	return nil
}

// Close gracefully closes the session and releases resources
// per I2CP specification - implements proper session lifecycle management with cleanup
// Sends DestroySession message to router and waits for cleanup completion
func (session *Session) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.closed {
		return fmt.Errorf("session already closed")
	}

	Debug("Closing session %d", session.id)

	// Send DestroySession message to router if client is connected
	if session.client != nil && session.client.IsConnected() {
		// Only send DestroySession for sessions that have been created by router
		if session.id != 0 {
			session.client.msgDestroySession(session, false)
			Debug("Sent DestroySession message for session %d", session.id)
		}
	}

	// Cancel context if we have one
	if session.cancel != nil {
		session.cancel()
	}

	// Mark as closed
	session.closed = true
	session.closedAt = time.Now()

	// Dispatch destroyed status
	session.dispatchStatusLocked(I2CP_SESSION_STATUS_DESTROYED)

	return nil
}

// IsClosed returns whether the session has been closed
func (session *Session) IsClosed() bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.closed
}

// CreatedAt returns the session creation time
func (session *Session) CreatedAt() time.Time {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.created
}

// ClosedAt returns the session closure time (zero if not closed)
func (session *Session) ClosedAt() time.Time {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.closedAt
}

// handleContextCancellation monitors context cancellation and closes session
func (session *Session) handleContextCancellation(ctx context.Context) {
	<-ctx.Done()

	Debug("Context cancelled for session %d: %v", session.id, ctx.Err())

	// Close session on context cancellation
	if err := session.Close(); err != nil {
		Error("Failed to close session %d on context cancellation: %v", session.id, err)
	}
}

// dispatchMessage dispatches received messages to registered callbacks
// per I2CP specification - handles MessagePayloadMessage (type 31) delivery
func (session *Session) dispatchMessage(protocol uint8, srcPort, destPort uint16, payload *Stream) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring message dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnMessage == nil {
		Debug("No message callback registered for session %d", session.id)
		return
	}

	Debug("Dispatching message to session %d: protocol=%d, srcPort=%d, destPort=%d",
		session.id, protocol, srcPort, destPort)

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in message callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnMessage(session, protocol, srcPort, destPort, payload)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// dispatchDestination dispatches destination lookup results to registered callbacks
// per I2CP specification - handles HostReplyMessage (type 39) responses
func (session *Session) dispatchDestination(requestId uint32, address string, destination *Destination) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring destination dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnDestination == nil {
		Debug("No destination callback registered for session %d", session.id)
		return
	}

	Debug("Dispatching destination lookup result to session %d: requestId=%d, address=%s",
		session.id, requestId, address)

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in destination callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnDestination(session, requestId, address, destination)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// dispatchStatus dispatches session status changes to registered callbacks
// per I2CP specification - handles SessionStatusMessage (type 20) events
func (session *Session) dispatchStatus(status SessionStatus) {
	session.mu.RLock()
	defer session.mu.RUnlock()
	session.dispatchStatusLocked(status)
}

// dispatchStatusLocked is the internal version that requires the mutex to be held
func (session *Session) dispatchStatusLocked(status SessionStatus) {
	// Log status change with structured logging
	switch status {
	case I2CP_SESSION_STATUS_CREATED:
		Info("Session %d created at %v", session.id, session.created)
	case I2CP_SESSION_STATUS_DESTROYED:
		Info("Session %d destroyed after %v", session.id, time.Since(session.created))
	case I2CP_SESSION_STATUS_UPDATED:
		Info("Session %d configuration updated", session.id)
	case I2CP_SESSION_STATUS_INVALID:
		Error("Session %d marked as invalid", session.id)
	default:
		Warning("Session %d received unknown status %d", session.id, status)
	}

	if session.callbacks == nil || session.callbacks.OnStatus == nil {
		return
	}

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in status callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnStatus(session, status)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// dispatchMessageStatus dispatches message delivery status to registered callbacks
// per I2CP specification - handles MessageStatusMessage (type 22) events with all 23 status codes
func (session *Session) dispatchMessageStatus(messageId uint32, status SessionMessageStatus, size, nonce uint32) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring message status dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnMessageStatus == nil {
		Debug("No message status callback registered for session %d", session.id)
		return
	}

	// Log message status with detailed information
	statusName := getMessageStatusName(uint8(status))
	Debug("Dispatching message status to session %d: messageId=%d, status=%d (%s), size=%d, nonce=%d",
		session.id, messageId, status, statusName, size, nonce)

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in message status callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnMessageStatus(session, messageId, status, size, nonce)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// dispatchLeaseSet2 dispatches LeaseSet2 updates to registered callbacks
// per I2CP specification 0.9.38+ - handles CreateLeaseSet2Message (type 41) from router
func (session *Session) dispatchLeaseSet2(leaseSet *LeaseSet2) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring LeaseSet2 dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnLeaseSet2 == nil {
		Debug("No LeaseSet2 callback registered for session %d", session.id)
		return
	}

	// Log LeaseSet2 details
	Debug("Dispatching LeaseSet2 to session %d: type=%d, leases=%d, expires=%s, expired=%v",
		session.id, leaseSet.Type(), leaseSet.LeaseCount(),
		leaseSet.Expires().Format("2006-01-02 15:04:05"), leaseSet.IsExpired())

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in LeaseSet2 callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnLeaseSet2(session, leaseSet)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// dispatchBlindingInfo dispatches blinding information to the session callback
// per I2CP specification 0.9.43+ - called when router provides blinding parameters
func (session *Session) dispatchBlindingInfo(blindingScheme, blindingFlags uint16, blindingParams []byte) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring BlindingInfo dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnBlindingInfo == nil {
		Debug("No BlindingInfo callback registered for session %d", session.id)
		return
	}

	// Log blinding info details
	Debug("Dispatching BlindingInfo to session %d: scheme=%d, flags=%d, params_len=%d",
		session.id, blindingScheme, blindingFlags, len(blindingParams))

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in BlindingInfo callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnBlindingInfo(session, blindingScheme, blindingFlags, blindingParams)
	}

	if session.syncCallbacks {
		// Synchronous execution for testing
		callbackFunc()
	} else {
		// Asynchronous execution for production to prevent blocking
		go callbackFunc()
	}
}

// SendMessageExpires sends a message with expiration time and flags for delivery options
// per I2CP specification 0.7.1+ - implements SendMessageExpiresMessage (type 36) for enhanced delivery control
// Supports per-message reliability override and tag management
func (session *Session) SendMessageExpires(dest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, flags uint16, expirationSeconds uint64) error {
	if session.client == nil {
		return fmt.Errorf("session not connected to client")
	}

	if dest == nil {
		return fmt.Errorf("destination cannot be nil")
	}

	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	// Check if session is closed
	if session.IsClosed() {
		return fmt.Errorf("session %d is closed", session.id)
	}

	// Generate unique nonce for message tracking
	nonce := session.client.crypto.Random32()

	Debug("Sending expiring message from session %d: protocol=%d, srcPort=%d, destPort=%d, flags=0x%04x, expiration=%ds, nonce=%d",
		session.id, protocol, srcPort, destPort, flags, expirationSeconds, nonce)

	return session.client.msgSendMessageExpires(session, dest, protocol, srcPort, destPort, payload, nonce, flags, expirationSeconds, true)
}

// SendMessageExpiresWithContext sends an expiring message with context support
// per I2CP specification 0.7.1+ - implements context-aware expiring message delivery
func (session *Session) SendMessageExpiresWithContext(ctx context.Context, dest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, flags uint16, expirationSeconds uint64) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before sending expiring message: %w", ctx.Err())
	default:
	}

	// Set up timeout handling
	errChan := make(chan error, 1)
	go func() {
		errChan <- session.SendMessageExpires(dest, protocol, srcPort, destPort, payload, flags, expirationSeconds)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("expiring message send cancelled: %w", ctx.Err())
	}
}

// LookupDestination performs a destination lookup using HostLookupMessage
// per I2CP specification 0.9.11+ - implements destination and hostname resolution
func (session *Session) LookupDestination(address string, timeout time.Duration) (*Destination, error) {
	if session.client == nil {
		return nil, fmt.Errorf("session not connected to client")
	}

	if address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	if session.IsClosed() {
		return nil, fmt.Errorf("session %d is closed", session.id)
	}

	// Generate unique request ID
	requestId := session.client.crypto.Random32()

	Debug("Looking up destination from session %d: address=%s, requestId=%d, timeout=%v",
		session.id, address, requestId, timeout)

	// Determine lookup type based on address format
	var lookupType uint8
	var lookupData interface{}

	if len(address) == 64 { // Assume base32 destination hash
		lookupType = 0 // Hash lookup
		// TODO: Decode base32 hash
		lookupData = []byte(address) // Placeholder
	} else {
		lookupType = 1 // Hostname lookup
		lookupData = address
	}

	timeoutMs := uint32(timeout.Milliseconds())

	// Convert lookupData to []byte with proper type assertion
	var lookupDataBytes []byte
	if lookupType == 0 {
		// Hash lookup - lookupData should be []byte
		if data, ok := lookupData.([]byte); ok {
			lookupDataBytes = data
		} else {
			return nil, fmt.Errorf("invalid lookup data type for hash lookup")
		}
	} else {
		// Hostname lookup - lookupData should be string
		if data, ok := lookupData.(string); ok {
			lookupDataBytes = []byte(data)
		} else {
			return nil, fmt.Errorf("invalid lookup data type for hostname lookup")
		}
	}

	return nil, session.client.msgHostLookup(session, requestId, timeoutMs, lookupType, lookupDataBytes, true)
}

// LookupDestinationWithContext performs a destination lookup with context support
// per I2CP specification 0.9.11+ - implements context-aware destination resolution
func (session *Session) LookupDestinationWithContext(ctx context.Context, address string, timeout time.Duration) (*Destination, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	// Check if context is already cancelled
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context cancelled before destination lookup: %w", ctx.Err())
	default:
	}

	// Set up timeout handling
	type result struct {
		dest *Destination
		err  error
	}

	resultChan := make(chan result, 1)
	go func() {
		dest, err := session.LookupDestination(address, timeout)
		resultChan <- result{dest, err}
	}()

	select {
	case res := <-resultChan:
		return res.dest, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("destination lookup cancelled: %w", ctx.Err())
	}
}

// Helper function to work around visibility issues
func getMessageStatusName(status uint8) string {
	switch status {
	case 0:
		return "Available"
	case 1:
		return "Accepted"
	case 2:
		return "BestEffortSuccess"
	case 3:
		return "BestEffortFailure"
	case 4:
		return "GuaranteedSuccess"
	case 5:
		return "GuaranteedFailure"
	case 6:
		return "LocalSuccess"
	case 7:
		return "LocalFailure"
	case 8:
		return "RouterFailure"
	case 9:
		return "NetworkFailure"
	case 10:
		return "BadSession"
	case 11:
		return "BadProtocol"
	case 12:
		return "BadOptions"
	case 13:
		return "OverflowFailure"
	case 14:
		return "MessageExpired"
	case 15:
		return "BadLocalLeaseset"
	case 16:
		return "NoLocalTunnels"
	case 17:
		return "UnsupportedEncryption"
	case 18:
		return "BadDestination"
	case 19:
		return "BadLeaseset"
	case 20:
		return "ExpiredLeaseset"
	case 21:
		return "NoLeaseset"
	case 22:
		return "InsufficientTags"
	case 23:
		return "SendAccepted"
	default:
		return fmt.Sprintf("Unknown(%d)", status)
	}
}

// BlindingScheme returns the current blinding cryptographic scheme
// per I2CP specification 0.9.43+ - returns 0 if blinding is disabled
func (session *Session) BlindingScheme() uint16 {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.blindingScheme
}

// SetBlindingScheme sets the blinding cryptographic scheme
// per I2CP specification 0.9.43+ - use 0 to disable blinding
func (session *Session) SetBlindingScheme(scheme uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.blindingScheme = scheme
}

// BlindingFlags returns the current blinding flags
// per I2CP specification 0.9.43+
func (session *Session) BlindingFlags() uint16 {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.blindingFlags
}

// SetBlindingFlags sets the blinding flags
// per I2CP specification 0.9.43+
func (session *Session) SetBlindingFlags(flags uint16) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.blindingFlags = flags
}

// BlindingParams returns a copy of the current blinding parameters
// per I2CP specification 0.9.43+ - returns nil if no parameters set
func (session *Session) BlindingParams() []byte {
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.blindingParams == nil {
		return nil
	}

	// Return copy to prevent external modification
	params := make([]byte, len(session.blindingParams))
	copy(params, session.blindingParams)
	return params
}

// SetBlindingParams sets the blinding parameters
// per I2CP specification 0.9.43+ - stores a copy of the provided data
func (session *Session) SetBlindingParams(params []byte) {
	session.mu.Lock()
	defer session.mu.Unlock()

	if params == nil {
		session.blindingParams = nil
		return
	}

	// Store copy to prevent external modification
	session.blindingParams = make([]byte, len(params))
	copy(session.blindingParams, params)
}

// ClearBlinding clears all blinding parameters
// per I2CP specification 0.9.43+ - resets to non-blinded state
func (session *Session) ClearBlinding() {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.blindingScheme = 0
	session.blindingFlags = 0
	session.blindingParams = nil
}

// IsBlindingEnabled returns true if blinding is currently enabled
// per I2CP specification 0.9.43+ - checks if scheme is non-zero
func (session *Session) IsBlindingEnabled() bool {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.blindingScheme != 0
}
