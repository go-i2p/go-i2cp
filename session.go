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
		mu:               sync.RWMutex{},
		created:          time.Now(),
		isPrimary:        true,                // Default to primary session, will be updated for subsessions
		syncCallbacks:    true,                // Default to synchronous for compatibility with tests
		destroyConfirmed: make(chan struct{}), // Channel for DestroySession response
	}
	sess.client = client // Create destination with proper error handling
	// Check if client.crypto is valid before calling NewDestination
	var dest *Destination
	var err error
	if client != nil && client.crypto != nil {
		dest, err = NewDestination(client.crypto)
		if err != nil {
			// Log error but continue with nil destination - will be handled later
			Error("Failed to create destination for new session: %v", err)
		}
	}

	// Use NewSessionConfig to properly initialize with defaults including i2cp.leaseSetEncType
	sess.config = &SessionConfig{destination: dest}
	// Set default encryption type to ECIES-X25519 (type 4) to match destination certificate
	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, "4")
	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	sess.callbacks = &callbacks
	sess.ctx = context.Background() // Default context

	return
}

// ensureInitialized checks if the Session has been properly initialized.
// Returns ErrSessionNotInitialized if the session was created with zero-value (Session{})
// instead of using NewSession() or NewSessionWithContext().
//
// This method checks critical fields that must be non-nil for the session to function:
// - client: Required for all I2CP operations
// - config: Required for session configuration
// - callbacks: Required for message handling
//
// This is a defensive check to prevent nil pointer panics from zero-value Session usage.
func (session *Session) ensureInitialized() error {
	if session.client == nil {
		return ErrSessionNotInitialized
	}
	if session.config == nil {
		return ErrSessionNotInitialized
	}
	if session.callbacks == nil {
		return ErrSessionNotInitialized
	}
	return nil
}

// SendMessage sends a basic message without expiration control
// per I2CP specification - implements basic message delivery via SendMessageMessage (type 5)
func (session *Session) SendMessage(destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) error {
	// Ensure session was properly initialized with NewSession()
	if err := session.ensureInitialized(); err != nil {
		return err
	}

	if destination == nil {
		return fmt.Errorf("destination cannot be nil")
	}

	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	// Validate message size per I2CP specification (max 64KB payload)
	payloadSize := payload.Len()
	if payloadSize > I2CP_MAX_MESSAGE_PAYLOAD_SIZE {
		return fmt.Errorf("message payload size %d exceeds I2CP maximum %d bytes", payloadSize, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
	}

	// Use structured logging with session context
	Debug("Sending message from session %d: protocol=%d, srcPort=%d, destPort=%d, nonce=%d",
		session.id, protocol, srcPort, destPort, nonce)

	// Track message for delivery status (ignore errors if already tracked)
	_ = session.TrackMessage(nonce, destination, protocol, srcPort, destPort, uint32(payload.Len()), 0, 0)

	return session.client.msgSendMessage(session, destination, protocol, srcPort, destPort, payload, nonce, true)
}

// SendMessageWithContext sends a message with context support for timeout control
// per I2CP specification - implements context-aware message delivery with cancellation
func (session *Session) SendMessageWithContext(ctx context.Context, destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) error {
	if err := validateSendContext(ctx); err != nil {
		return err
	}

	return executeSendWithContext(ctx, session, destination, protocol, srcPort, destPort, payload, nonce)
}

// validateSendContext validates the context is non-nil and not already cancelled.
func validateSendContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before sending message: %w", ctx.Err())
	default:
		return nil
	}
}

// executeSendWithContext executes the message send in a goroutine with context cancellation support.
func executeSendWithContext(ctx context.Context, session *Session, destination *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32) error {
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
	// Ensure session was properly initialized with NewSession()
	if err := session.ensureInitialized(); err != nil {
		return err
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
	if err := validateContextNotNilOrCancelled(ctx, "reconfiguration"); err != nil {
		return err
	}

	return executeWithContext(ctx, func() error {
		return session.ReconfigureSession(properties)
	}, "session reconfiguration cancelled")
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

// SigningKeyPair returns the Ed25519 key pair used for this session.
// Returns the key pair that corresponds to the session's destination.
// This key pair is used to sign I2P Streaming Protocol packets and other
// cryptographic operations requiring the session's signing key.
//
// Returns:
//   - *Ed25519KeyPair: The signing key pair if available
//   - error: ErrSessionNotInitialized if session not properly initialized,
//     or an error describing why the key pair is unavailable
//
// Example usage for packet signing:
//
//	keyPair, err := session.SigningKeyPair()
//	if err != nil {
//	    return err
//	}
//	signature, err := keyPair.Sign(packetData)
func (session *Session) SigningKeyPair() (*Ed25519KeyPair, error) {
	session.mu.RLock()
	defer session.mu.RUnlock()

	// Check session initialization
	if session.config == nil {
		return nil, ErrSessionNotInitialized
	}

	// Check destination exists
	dest := session.config.destination
	if dest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Check SignatureKeyPair exists
	if dest.sgk.ed25519KeyPair == nil {
		return nil, fmt.Errorf("destination has no Ed25519 key pair")
	}

	return dest.sgk.ed25519KeyPair, nil
}

// ID returns the session ID assigned by the router
// per I2CP specification - unique identifier for session within I2CP connection
func (session *Session) ID() uint16 {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.id
}

// SessionID returns the session ID assigned by the router
// per I2CP specification - unique identifier for session within I2CP connection
// This is an idiomatic alias for ID() following Go naming conventions
func (session *Session) SessionID() uint16 {
	return session.ID()
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
	if err := session.ensureInitialized(); err != nil {
		return err
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.closed {
		return fmt.Errorf("session already closed")
	}

	Debug("Closing session %d", session.id)

	session.sendDestroyMessage()
	session.cleanupResources()
	session.finalizeClose()

	return nil
}

// sendDestroyMessage sends DestroySession message to router if connected.
func (session *Session) sendDestroyMessage() {
	if session.client != nil && session.client.IsConnected() {
		if session.id != 0 {
			session.client.msgDestroySession(session, false)
			Debug("Sent DestroySession message for session %d", session.id)
		}
	}
}

// cleanupResources cancels context and clears pending messages.
func (session *Session) cleanupResources() {
	if session.cancel != nil {
		session.cancel()
	}

	pendingCount := session.ClearPendingMessages()
	if pendingCount > 0 {
		Debug("Cleared %d pending messages for session %d", pendingCount, session.id)
	}
}

// finalizeClose dispatches status and marks session as closed.
func (session *Session) finalizeClose() {
	session.dispatchStatusLocked(I2CP_SESSION_STATUS_DESTROYED)
	session.closed = true
	session.closedAt = time.Now()
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
// Note: srcDest may be nil for protocols that don't include source destination (streaming, raw datagrams, custom protocols)
func (session *Session) dispatchMessage(srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
	// Check if session is closed
	if session.IsClosed() {
		Warning("Ignoring message dispatch to closed session %d", session.id)
		return
	}

	if session.callbacks == nil || session.callbacks.OnMessage == nil {
		Debug("No message callback registered for session %d", session.id)
		return
	}

	// Log source destination if available (only for repliable datagrams)
	srcAddr := "(no source destination)"
	if srcDest != nil {
		srcAddr = srcDest.Base32()
	}
	Debug("Dispatching message to session %d: from=%s, protocol=%d, srcPort=%d, destPort=%d",
		session.id, srcAddr, protocol, srcPort, destPort)

	// Choose between sync and async callback execution
	callbackFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				Error("Panic in message callback for session %d: %v", session.id, r)
			}
		}()

		session.callbacks.OnMessage(session, srcDest, protocol, srcPort, destPort, payload)
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
	Debug(">>> Dispatching session status %d (%s) to callback for session %d", status, getSessionStatusName(status), session.id)
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
		Warning("Session %d has no OnStatus callback registered - status change not delivered to application", session.id)
		return
	}

	Debug(">>> Invoking OnStatus callback for session %d with status %s", session.id, getSessionStatusName(status))
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

	// Complete tracked message if present
	pending, wasTracked := session.CompleteMessage(nonce, status)
	if wasTracked && pending != nil {
		deliveryTime := pending.CompletedAt.Sub(pending.SentAt)
		Debug("Message delivery completed for session %d: nonce=%d, delivery_time=%v",
			session.id, nonce, deliveryTime)
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
	// Ensure session was properly initialized with NewSession()
	if err := session.ensureInitialized(); err != nil {
		return err
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

	// Track message for delivery status (ignore errors if already tracked)
	_ = session.TrackMessage(nonce, dest, protocol, srcPort, destPort, uint32(payload.Len()), flags, expirationSeconds)

	return session.client.msgSendMessageExpires(session, dest, protocol, srcPort, destPort, payload, nonce, flags, expirationSeconds, true)
}

// SendMessageExpiresWithContext sends an expiring message with context support
// per I2CP specification 0.7.1+ - implements context-aware expiring message delivery
func (session *Session) SendMessageExpiresWithContext(ctx context.Context, dest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, flags uint16, expirationSeconds uint64) error {
	if err := validateContextNotNilOrCancelled(ctx, "sending expiring message"); err != nil {
		return err
	}

	return executeWithContext(ctx, func() error {
		return session.SendMessageExpires(dest, protocol, srcPort, destPort, payload, flags, expirationSeconds)
	}, "expiring message send cancelled")
}

// LookupDestination performs a destination lookup using HostLookupMessage
// per I2CP specification 0.9.11+ - implements destination and hostname resolution
func (session *Session) LookupDestination(address string, timeout time.Duration) (*Destination, error) {
	if err := session.validateLookupRequest(address); err != nil {
		return nil, err
	}

	requestId := session.client.crypto.Random32()
	Debug("Looking up destination from session %d: address=%s, requestId=%d, timeout=%v",
		session.id, address, requestId, timeout)

	lookupType, lookupDataBytes, err := session.prepareLookupData(address)
	if err != nil {
		return nil, err
	}

	timeoutMs := uint32(timeout.Milliseconds())
	return nil, session.client.msgHostLookup(session, requestId, timeoutMs, lookupType, lookupDataBytes, true)
}

// validateLookupRequest validates session state and address for lookup.
func (session *Session) validateLookupRequest(address string) error {
	if err := session.ensureInitialized(); err != nil {
		return err
	}

	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	if session.IsClosed() {
		return fmt.Errorf("session %d is closed", session.id)
	}

	return nil
}

// prepareLookupData determines lookup type and prepares lookup data bytes.
func (session *Session) prepareLookupData(address string) (uint8, []byte, error) {
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

	lookupDataBytes, err := session.convertLookupData(lookupType, lookupData)
	if err != nil {
		return 0, nil, err
	}

	return lookupType, lookupDataBytes, nil
}

// convertLookupData converts lookup data to bytes based on lookup type.
func (session *Session) convertLookupData(lookupType uint8, lookupData interface{}) ([]byte, error) {
	if lookupType == 0 {
		// Hash lookup - lookupData should be []byte
		if data, ok := lookupData.([]byte); ok {
			return data, nil
		}
		return nil, fmt.Errorf("invalid lookup data type for hash lookup")
	}

	// Hostname lookup - lookupData should be string
	if data, ok := lookupData.(string); ok {
		return []byte(data), nil
	}
	return nil, fmt.Errorf("invalid lookup data type for hostname lookup")
}

// LookupDestinationWithContext performs a destination lookup with context support
// per I2CP specification 0.9.11+ - implements context-aware destination resolution
func (session *Session) LookupDestinationWithContext(ctx context.Context, address string, timeout time.Duration) (*Destination, error) {
	if err := validateLookupContext(ctx); err != nil {
		return nil, err
	}

	return executeLookupWithContext(ctx, session, address, timeout)
}

// validateLookupContext validates the context is non-nil and not already cancelled.
func validateLookupContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before destination lookup: %w", ctx.Err())
	default:
		return nil
	}
}

// executeLookupWithContext executes the destination lookup in a goroutine with context cancellation support.
func executeLookupWithContext(ctx context.Context, session *Session, address string, timeout time.Duration) (*Destination, error) {
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
	if name := getMessageSuccessStatusName(status); name != "" {
		return name
	}
	if name := getMessageFailureStatusName(status); name != "" {
		return name
	}
	if name := getMessageErrorStatusName(status); name != "" {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", status)
}

// getMessageSuccessStatusName returns names for successful message delivery statuses.
func getMessageSuccessStatusName(status uint8) string {
	switch status {
	case 0:
		return "Available"
	case 1:
		return "Accepted"
	case 2:
		return "BestEffortSuccess"
	case 4:
		return "GuaranteedSuccess"
	case 6:
		return "LocalSuccess"
	case 23:
		return "SendAccepted"
	default:
		return ""
	}
}

// getMessageFailureStatusName returns names for message delivery failure statuses.
func getMessageFailureStatusName(status uint8) string {
	switch status {
	case 3:
		return "BestEffortFailure"
	case 5:
		return "GuaranteedFailure"
	case 7:
		return "LocalFailure"
	case 8:
		return "RouterFailure"
	case 9:
		return "NetworkFailure"
	case 13:
		return "OverflowFailure"
	case 14:
		return "MessageExpired"
	default:
		return ""
	}
}

// getMessageErrorStatusName returns names for message error conditions.
func getMessageErrorStatusName(status uint8) string {
	switch status {
	case 10:
		return "BadSession"
	case 11:
		return "BadProtocol"
	case 12:
		return "BadOptions"
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
	default:
		return ""
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

// TrackMessage registers a message for delivery tracking
// per I2CP specification - tracks messages from send to status callback (type 22)
// Returns error if nonce is already being tracked
func (session *Session) TrackMessage(nonce uint32, dest *Destination, protocol uint8, srcPort, destPort uint16, payloadSize uint32, flags uint16, expiration uint64) error {
	session.messageMu.Lock()
	defer session.messageMu.Unlock()

	// Initialize map if needed
	if session.pendingMessages == nil {
		session.pendingMessages = make(map[uint32]*PendingMessage)
	}

	// Check for duplicate nonce
	if _, exists := session.pendingMessages[nonce]; exists {
		return fmt.Errorf("message with nonce %d is already being tracked", nonce)
	}

	// Create pending message
	pending := &PendingMessage{
		Nonce:       nonce,
		Destination: dest,
		Protocol:    protocol,
		SrcPort:     srcPort,
		DestPort:    destPort,
		PayloadSize: payloadSize,
		SentAt:      time.Now(),
		Status:      0, // 0 indicates pending
		Flags:       flags,
		Expiration:  expiration,
	}

	session.pendingMessages[nonce] = pending
	Debug("Tracking message for session %d: nonce=%d, protocol=%d, srcPort=%d, destPort=%d, size=%d",
		session.id, nonce, protocol, srcPort, destPort, payloadSize)

	return nil
}

// CompleteMessage marks a message as completed with the given status
// per I2CP specification - called when MessageStatusMessage (type 22) is received
// Returns the pending message and true if found, nil and false otherwise
func (session *Session) CompleteMessage(nonce uint32, status SessionMessageStatus) (*PendingMessage, bool) {
	session.messageMu.Lock()
	defer session.messageMu.Unlock()

	pending, exists := session.pendingMessages[nonce]
	if !exists {
		Debug("No pending message found for nonce %d in session %d", nonce, session.id)
		return nil, false
	}

	// Update status and completion time
	pending.Status = status
	pending.CompletedAt = time.Now()

	// Calculate delivery time
	deliveryTime := pending.CompletedAt.Sub(pending.SentAt)
	statusName := getMessageStatusName(status)
	Debug("Completed message for session %d: nonce=%d, status=%d (%s), delivery_time=%v",
		session.id, nonce, status, statusName, deliveryTime)

	// Remove from pending map (message is no longer pending)
	delete(session.pendingMessages, nonce)

	return pending, true
}

// GetPendingMessage returns a pending message by nonce without completing it
// per I2CP specification - used for status queries and debugging
// Returns the pending message and true if found, nil and false otherwise
func (session *Session) GetPendingMessage(nonce uint32) (*PendingMessage, bool) {
	session.messageMu.RLock()
	defer session.messageMu.RUnlock()

	pending, exists := session.pendingMessages[nonce]
	return pending, exists
}

// GetPendingMessages returns a snapshot of all pending messages
// per I2CP specification - used for monitoring and cleanup
// Returns a copy of the pending messages map to prevent external modification
func (session *Session) GetPendingMessages() map[uint32]*PendingMessage {
	session.messageMu.RLock()
	defer session.messageMu.RUnlock()

	// Return copy to prevent external modification
	snapshot := make(map[uint32]*PendingMessage, len(session.pendingMessages))
	for nonce, pending := range session.pendingMessages {
		snapshot[nonce] = pending
	}

	return snapshot
}

// PendingMessageCount returns the number of messages awaiting status
// per I2CP specification - used for monitoring queue depth
func (session *Session) PendingMessageCount() int {
	session.messageMu.RLock()
	defer session.messageMu.RUnlock()

	return len(session.pendingMessages)
}

// ClearPendingMessages removes all pending messages
// per I2CP specification - called on session close or reset
// Returns the number of messages that were pending
func (session *Session) ClearPendingMessages() int {
	session.messageMu.Lock()
	defer session.messageMu.Unlock()

	count := len(session.pendingMessages)
	session.pendingMessages = make(map[uint32]*PendingMessage)

	if count > 0 {
		Debug("Cleared %d pending messages for session %d", count, session.id)
	}

	return count
}

// Config returns the session's configuration.
// Returns nil if the session was not properly initialized.
//
// The returned SessionConfig contains tunnel settings, cryptographic options,
// and the destination identity for this session.
//
// I2CP Spec: Session configuration is sent during CreateSessionMessage (type 1).
//
// Example:
//
//	config := session.Config()
//	if config != nil {
//	    fmt.Printf("Session destination: %s\n", config.destination.Base64())
//	}
func (session *Session) Config() *SessionConfig {
	session.mu.RLock()
	defer session.mu.RUnlock()
	return session.config
}

// GetTunnelQuantity returns the number of tunnels configured for this session.
// The inbound parameter determines which direction: true for inbound, false for outbound.
// Returns 0 if the session is not properly initialized or the property is not set.
//
// Tunnel quantity affects anonymity and performance:
//   - Higher values (3-5): Better anonymity and reliability, more overhead
//   - Lower values (1-2): Lower latency, less anonymity
//   - Default (from client properties): 3 tunnels for balanced anonymity/performance
//
// I2CP Spec: Tunnel configuration is part of session properties mapping.
//
// Example:
//
//	inboundCount := session.GetTunnelQuantity(true)
//	outboundCount := session.GetTunnelQuantity(false)
//	fmt.Printf("Tunnels: %d inbound, %d outbound\n", inboundCount, outboundCount)
func (session *Session) GetTunnelQuantity(inbound bool) int {
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.config == nil {
		return 0
	}

	var prop SessionConfigProperty
	if inbound {
		prop = SESSION_CONFIG_PROP_INBOUND_QUANTITY
	} else {
		prop = SESSION_CONFIG_PROP_OUTBOUND_QUANTITY
	}

	value := session.config.properties[prop]
	if value == "" {
		return 0
	}

	// Parse string to int
	var quantity int
	fmt.Sscanf(value, "%d", &quantity)
	return quantity
}

// GetTunnelLength returns the hop count (length) for tunnels in this session.
// The inbound parameter determines which direction: true for inbound, false for outbound.
// Returns 0 if the session is not properly initialized or the property is not set.
//
// Tunnel length affects anonymity and latency:
//   - Higher values (3+): Stronger anonymity, higher latency
//   - Lower values (1-2): Lower latency, weaker anonymity
//   - Default (from client properties): 3 hops for strong anonymity
//
// I2CP Spec: Tunnel configuration is part of session properties mapping.
//
// Example:
//
//	inboundLength := session.GetTunnelLength(true)
//	outboundLength := session.GetTunnelLength(false)
//	fmt.Printf("Tunnel lengths: %d inbound hops, %d outbound hops\n",
//	    inboundLength, outboundLength)
func (session *Session) GetTunnelLength(inbound bool) int {
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.config == nil {
		return 0
	}

	var prop SessionConfigProperty
	if inbound {
		prop = SESSION_CONFIG_PROP_INBOUND_LENGTH
	} else {
		prop = SESSION_CONFIG_PROP_OUTBOUND_LENGTH
	}

	value := session.config.properties[prop]
	if value == "" {
		return 0
	}

	// Parse string to int
	var length int
	fmt.Sscanf(value, "%d", &length)
	return length
}

// GetProperty returns the value of a specific session configuration property.
// Returns an empty string if the session is not properly initialized or the property is not set.
//
// Available properties include tunnel configuration (quantity, length, variance),
// cryptographic options (tagsToSend, lowTagThreshold), and I2CP protocol settings
// (fastReceive, gzip, messageReliability).
//
// See SessionConfigProperty constants for the full list of available properties.
//
// I2CP Spec: Session properties are sent as a mapping in CreateSessionMessage (type 1).
//
// Example:
//
//	fastReceive := session.GetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE)
//	if fastReceive == "true" {
//	    fmt.Println("Fast receive mode enabled")
//	}
//
//	nickname := session.GetProperty(SESSION_CONFIG_PROP_INBOUND_NICKNAME)
//	fmt.Printf("Inbound tunnel nickname: %s\n", nickname)
func (session *Session) GetProperty(prop SessionConfigProperty) string {
	session.mu.RLock()
	defer session.mu.RUnlock()

	if session.config == nil {
		return ""
	}

	if prop < 0 || prop >= NR_OF_SESSION_CONFIG_PROPERTIES {
		return ""
	}

	return session.config.properties[prop]
}

// validateContextNotNilOrCancelled validates that the context is non-nil and not already cancelled.
func validateContextNotNilOrCancelled(ctx context.Context, operation string) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled before %s: %w", operation, ctx.Err())
	default:
		return nil
	}
}

// executeWithContext executes a function in a goroutine with context cancellation support.
func executeWithContext(ctx context.Context, fn func() error, cancelMsg string) error {
	errChan := make(chan error, 1)
	go func() {
		errChan <- fn()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", cancelMsg, ctx.Err())
	}
}
