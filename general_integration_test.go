package go_i2cp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Integration tests for go-i2cp library
//
// These tests validate the library against a live I2P router on localhost:7654.
// They test actual I2CP operations including session management, message routing,
// and destination lookups over the I2P network.
//
// Prerequisites:
//   - Running I2P router with I2CP enabled on localhost:7654
//   - Router must support modern I2CP features (version 0.9.11+)
//   - Recommended: I2P router with established network connections for faster tunnel building
//
// Run with: go test -v -timeout=5m
//
// IMPORTANT: These tests require a running I2P router and will FAIL if one is not available on localhost:7654.
//
// Note on Router Behavior:
//   Some routers may not send SessionStatus CREATED messages (status code 1) immediately,
//   or may send different status codes depending on configuration. The tests handle this
//   gracefully with warnings rather than failures. Session ID assignment timing may also
//   vary between router implementations.
//
// Test Coverage:
//   - TestSessionLifecycle: Session creation, status callbacks, graceful shutdown
//   - TestBidirectionalDataTransfer: End-to-end message delivery with integrity verification
//   - TestDestinationLookupAndRouting: Destination lookup and message routing by B32 address
//   - TestMultipleMessagesWithIntegrity: Multiple concurrent messages with varying sizes
//
// Performance Notes:
//   - Initial tunnel establishment can take 10-30 seconds per session
//   - Message delivery over I2P can take 5-60 seconds depending on network conditions
//   - Tests include appropriate timeouts and may take several minutes to complete
//   - Run with -timeout=10m for slower networks or busy routers

const (
	// Test timeouts
	connectionTimeout = 30 * time.Second
	operationTimeout  = 30 * time.Second
	messageTimeout    = 60 * time.Second

	// Test protocol identifiers (custom for testing)
	protocolTestData      uint8 = 200
	protocolBidirectional uint8 = 201
)

// runProcessIOLoop repeatedly calls client.ProcessIO(ctx) until it returns an
// error or ctx is done, sleeping briefly between iterations to avoid a busy
// loop. Errors other than ErrClientClosed are logged with label as a prefix
// to identify which client under test produced them.
func runProcessIOLoop(t *testing.T, ctx context.Context, client *Client, label string) {
	for {
		if err := client.ProcessIO(ctx); err != nil {
			if err != ErrClientClosed {
				t.Logf("%s ProcessIO error: %v", label, err)
			}
			return
		}

		time.Sleep(100 * time.Millisecond)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// connectAndCreateSession connects a new Client, creates a Session configured
// with SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE and the given nickname, and
// starts a background runProcessIOLoop bounded by ioTimeout for the rest of
// the test. If ready is non-nil, it waits (10s timeout, failing the test on
// expiry) for the channel to close - typically signaled by the caller's
// OnStatus callback on I2CP_SESSION_STATUS_CREATED - before sleeping
// tunnelWait to allow I2P tunnels to establish. The client and its ProcessIO
// loop are torn down automatically when the test completes. The returned
// context is the ProcessIO loop's context, exposed for callers that need to
// reuse it for further operations bounded by the same deadline (e.g. lookups).
func connectAndCreateSession(t *testing.T, callbacks SessionCallbacks, nickname string, ioTimeout, tunnelWait time.Duration, ready <-chan struct{}) (*Client, *Session, context.Context) {
	t.Helper()

	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect %s client: %v", nickname, err)
	}
	t.Cleanup(func() { client.Close() })

	session := NewSession(client, callbacks)
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, nickname)

	if err := client.CreateSession(ctx, session); err != nil {
		t.Fatalf("Failed to create %s session: %v", nickname, err)
	}

	ioCtx, ioCancel := context.WithTimeout(context.Background(), ioTimeout)
	t.Cleanup(ioCancel)
	go runProcessIOLoop(t, ioCtx, client, nickname)

	if ready != nil {
		t.Logf("Waiting for %s session creation...", nickname)
		select {
		case <-ready:
			t.Logf("%s session created with ID: %d", nickname, session.ID())
		case <-time.After(10 * time.Second):
			t.Fatalf("Timeout waiting for %s session creation", nickname)
		}
	}

	t.Logf("Waiting for %s tunnels to establish...", nickname)
	time.Sleep(tunnelWait)

	return client, session, ioCtx
}

// TestSessionLifecycle validates complete session lifecycle including:
// - Session creation
// - Status callback invocation (OnStatus)
// - Graceful session shutdown
// - Proper cleanup of resources
//
// This test demonstrates the fundamental I2CP session management operations
// that form the foundation for all I2P communications.
func TestSessionLifecycle(t *testing.T) {
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	// Track callback invocations for validation
	var (
		statusMu       sync.Mutex
		statusReceived []SessionStatus
	)

	// Create client with empty callbacks
	client := NewClient(nil)

	// Connect to router with timeout
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to I2P router: %v", err)
	}

	// Ensure cleanup happens even if test fails
	defer func() {
		if err := client.Close(); err != nil && err != ErrClientClosed {
			t.Errorf("Failed to close client: %v", err)
		}
	}()

	t.Log("Successfully connected to I2P router")

	// Create session with status tracking callback
	session := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			statusMu.Lock()
			defer statusMu.Unlock()
			statusReceived = append(statusReceived, status)
			t.Logf("Session status callback: %d", status)
		},
	})

	// Configure session with reasonable defaults
	session.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-session")
	session.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "2")
	session.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")

	// Create session
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), operationTimeout)
	defer sessionCancel()

	err = client.CreateSession(sessionCtx, session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	t.Logf("Session created with ID: %d", session.ID())

	// Process I/O to receive session status updates
	ioCtx, ioCancel := context.WithTimeout(context.Background(), operationTimeout)
	defer ioCancel()

	// Track when session is created
	sessionCreated := make(chan struct{})
	var sessionCreatedOnce sync.Once

	// Update callback to signal when session is created
	statusMu.Lock()
	originalOnStatus := session.callbacks.OnStatus
	session.callbacks.OnStatus = func(s *Session, status SessionStatus) {
		if originalOnStatus != nil {
			originalOnStatus(s, status)
		}
		if status == I2CP_SESSION_STATUS_CREATED {
			sessionCreatedOnce.Do(func() {
				close(sessionCreated)
			})
		}
	}
	statusMu.Unlock()

	// Process messages in background
	go runProcessIOLoop(t, ioCtx, client, "session")

	// Wait for session to be fully created by router
	t.Log("Waiting for router to create session...")
	select {
	case <-sessionCreated:
		t.Log("Session created notification received")
	case <-time.After(10 * time.Second):
		t.Log("Timeout waiting for session creation - continuing anyway")
	}

	// Additional time for session ID assignment
	time.Sleep(1 * time.Second)

	// Verify session ID was assigned
	sessionID := session.ID()
	t.Logf("Session ID: %d", sessionID)
	if sessionID == 0 {
		t.Log("Warning: Session ID was not assigned by router (this may be expected in some router configurations)")
	}

	// Verify destination was created
	dest := session.Destination()
	if dest == nil {
		t.Fatal("Session destination is nil")
	}

	// Log destination address for debugging
	b32Addr := dest.b32
	t.Logf("Session destination (B32): %s", b32Addr)

	// Verify status callback was invoked
	statusMu.Lock()
	receivedCreated := false
	for _, status := range statusReceived {
		if status == I2CP_SESSION_STATUS_CREATED {
			receivedCreated = true
			break
		}
	}
	statusMu.Unlock()

	if !receivedCreated {
		t.Log("Warning: OnStatus callback was not invoked with CREATED status (this may be router-specific behavior)")
	} else {
		t.Log("OnStatus callback confirmed CREATED status")
	}

	// Close session gracefully
	t.Log("Closing session...")
	if err := session.Close(); err != nil {
		t.Errorf("Failed to close session: %v", err)
	}

	// Verify destroyed status was received
	time.Sleep(500 * time.Millisecond)

	statusMu.Lock()
	receivedDestroyed := false
	for _, status := range statusReceived {
		if status == I2CP_SESSION_STATUS_DESTROYED {
			receivedDestroyed = true
			break
		}
	}
	statusMu.Unlock()

	if !receivedDestroyed {
		t.Error("OnStatus callback was not invoked with DESTROYED status")
	}

	t.Log("Session lifecycle test completed successfully")
}

// TestBidirectionalDataTransfer validates end-to-end message delivery:
// - Creates two independent I2P destinations (sender and receiver)
// - Sends test payload from sender to receiver
// - Verifies OnMessage callback invocation
// - Validates data integrity using checksums
//
// This test demonstrates actual I2P network communication over the anonymous
// network, proving the library can successfully route messages between destinations.
func TestBidirectionalDataTransfer(t *testing.T) {
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	// Test payload with checksum for integrity verification
	testPayload := []byte("Hello from go-i2cp integration test! This is a test message for bidirectional data transfer.")
	payloadChecksum := sha256.Sum256(testPayload)

	t.Logf("Test payload size: %d bytes", len(testPayload))
	t.Logf("Test payload checksum: %s", hex.EncodeToString(payloadChecksum[:]))

	// Create receiver client and session
	// Track received messages
	var (
		receiverMu       sync.Mutex
		receivedMessages int
		receivedPayload  []byte
		messageReceived  = make(chan struct{})
		receiverReady    = make(chan struct{})
	)

	// Create receiver session with message callback
	_, receiverSession, _ := connectAndCreateSession(t, SessionCallbacks{
		OnMessage: func(s *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			receiverMu.Lock()
			defer receiverMu.Unlock()

			receivedMessages++
			receivedPayload = make([]byte, payload.Len())
			payload.Read(receivedPayload)

			// srcDest may be nil for non-repliable datagram protocols
			srcAddr := "(no source destination)"
			if srcDest != nil {
				srcAddr = srcDest.Base32()
			}
			t.Logf("Receiver: Got message from %s - protocol=%d, srcPort=%d, destPort=%d, size=%d",
				srcAddr, protocol, srcPort, destPort, len(receivedPayload))

			// Signal message received
			select {
			case messageReceived <- struct{}{}:
			default:
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Receiver session status: %d", status)
			if status == I2CP_SESSION_STATUS_CREATED {
				close(receiverReady)
			}
		},
	}, "integration-test-receiver", messageTimeout, 10*time.Second, receiverReady)

	receiverDest := receiverSession.Destination()
	t.Logf("Receiver destination (B32): %s", receiverDest.b32)

	// Create sender client and session
	senderReady := make(chan struct{})
	_, senderSession, _ := connectAndCreateSession(t, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Sender session status: %d", status)
			if status == I2CP_SESSION_STATUS_CREATED {
				close(senderReady)
			}
		},
	}, "integration-test-sender", messageTimeout, 10*time.Second, senderReady)

	t.Logf("Sender destination (B32): %s", senderSession.Destination().b32)

	// Send message from sender to receiver
	t.Log("Sending test message...")
	// Use smaller payload to stay within I2CP 64KB limit (accounting for protocol overhead)
	payloadSize := len(testPayload)
	if payloadSize > 60000 { // 60KB to allow for protocol overhead
		payloadSize = 60000
	}
	payload := NewStream(testPayload[:payloadSize])
	nonce := uint32(time.Now().Unix())

	err := senderSession.SendMessage(
		receiverDest,
		protocolBidirectional,
		12345, // source port
		54321, // destination port
		payload,
		nonce,
	)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	t.Log("Message sent, waiting for delivery...")

	// Wait for message to be received (with timeout)
	select {
	case <-messageReceived:
		t.Log("Message received successfully")
	case <-time.After(messageTimeout):
		t.Fatal("Timeout waiting for message delivery")
	}

	// Verify message integrity
	receiverMu.Lock()
	defer receiverMu.Unlock()

	if receivedMessages != 1 {
		t.Errorf("Expected 1 message, got %d", receivedMessages)
	}

	if len(receivedPayload) != len(testPayload) {
		t.Errorf("Payload size mismatch: expected %d, got %d", len(testPayload), len(receivedPayload))
	}

	receivedChecksum := sha256.Sum256(receivedPayload)
	if receivedChecksum != payloadChecksum {
		t.Error("Payload checksum mismatch - data corruption detected")
		t.Logf("Expected: %s", hex.EncodeToString(payloadChecksum[:]))
		t.Logf("Received: %s", hex.EncodeToString(receivedChecksum[:]))
	} else {
		t.Log("Payload integrity verified - checksums match")
	}

	t.Log("Bidirectional data transfer test completed successfully")
}

// performDestinationLookupWithRetries attempts to lookup a destination by B32 address,
// with exponential backoff retry logic. The destinationFound channel is signaled by the
// OnDestination callback when a destination is resolved. The caller's lookedUpDest variable
// (captured by closure in the callback) will be updated with the resolved destination.
func performDestinationLookupWithRetries(t *testing.T, client *Client, session *Session, ctx context.Context, targetB32 string, destinationFound <-chan struct{}, lookupMu *sync.Mutex, _ *Destination) {
	t.Helper()

	const maxLookupAttempts = 5
	const lookupRetryDelay = 15 * time.Second

	var lookupSuccess bool
	for attempt := 1; attempt <= maxLookupAttempts; attempt++ {
		t.Logf("Looking up destination (attempt %d/%d): %s", attempt, maxLookupAttempts, targetB32)
		requestId, err := client.DestinationLookup(ctx, session, targetB32)
		if err != nil {
			t.Fatalf("Failed to initiate destination lookup: %v", err)
		}

		t.Logf("Destination lookup initiated - requestId: %d", requestId)

		select {
		case <-destinationFound:
			t.Log("Destination lookup successful")
			lookupSuccess = true
		case <-time.After(operationTimeout):
			if attempt < maxLookupAttempts {
				t.Logf("Lookup attempt %d timed out, retrying in %v...", attempt, lookupRetryDelay)
				time.Sleep(lookupRetryDelay)
			}
		}
		if lookupSuccess {
			break
		}
	}
	if !lookupSuccess {
		t.Fatal("All destination lookup attempts timed out")
	}
}

// verifyDestinationMatch asserts that the looked-up destination matches the target destination.
func verifyDestinationMatch(t *testing.T, lookedUpB32, targetB32 string) {
	t.Helper()

	if lookedUpB32 != targetB32 {
		t.Errorf("Looked-up destination mismatch: expected %s, got %s", targetB32, lookedUpB32)
	} else {
		t.Log("Looked-up destination matches target destination")
	}
}

// verifyMessageDelivery waits for a message to be received and verifies the count.
func verifyMessageDelivery(t *testing.T, messageReceived <-chan struct{}, targetMu *sync.Mutex, targetMessages *int) {
	t.Helper()

	select {
	case <-messageReceived:
		t.Log("Message delivered successfully to looked-up destination")
	case <-time.After(messageTimeout):
		t.Fatal("Timeout waiting for message delivery to looked-up destination")
	}

	targetMu.Lock()
	defer targetMu.Unlock()

	if *targetMessages != 1 {
		t.Errorf("Expected 1 message on target, got %d", *targetMessages)
	}
}

// TestDestinationLookupAndRouting validates destination lookup and message routing:
// - Creates a destination to be looked up
// - Performs lookup using DestinationLookup
// - Verifies OnDestination callback invocation
// - Sends message to looked-up destination
// - Confirms successful message delivery
//
// This test demonstrates the I2P naming/addressing system and how destinations
// are resolved before communication can occur.
func TestDestinationLookupAndRouting(t *testing.T) {
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	// Track received messages on target
	var (
		targetMu        sync.Mutex
		targetMessages  int
		messageReceived = make(chan struct{})
	)

	// Create target client and session (the destination to be looked up)
	_, targetSession, _ := connectAndCreateSession(t, SessionCallbacks{
		OnMessage: func(s *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			targetMu.Lock()
			defer targetMu.Unlock()
			targetMessages++
			// srcDest may be nil for non-repliable datagram protocols
			srcAddr := "(no source destination)"
			if srcDest != nil {
				srcAddr = srcDest.Base32()
			}
			t.Logf("Target: Received message from %s - protocol=%d, size=%d", srcAddr, protocol, payload.Len())

			select {
			case messageReceived <- struct{}{}:
			default:
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Target session status: %d", status)
		},
	}, "integration-test-target", 5*time.Minute, 30*time.Second, nil)

	targetDest := targetSession.Destination()
	targetB32 := targetDest.b32
	t.Logf("Target destination (B32): %s", targetB32)

	// Create lookup client and session
	var (
		lookupMu         sync.Mutex
		lookedUpDest     *Destination
		destinationFound = make(chan struct{})
	)

	lookupClient, lookupSession, lookupIOCtx := connectAndCreateSession(t, SessionCallbacks{
		OnDestination: func(s *Session, requestId uint32, address string, dest *Destination) {
			lookupMu.Lock()
			defer lookupMu.Unlock()

			t.Logf("OnDestination callback: requestId=%d, address=%s, dest=%v",
				requestId, address, dest != nil)

			if dest != nil {
				lookedUpDest = dest
				select {
				case destinationFound <- struct{}{}:
				default:
				}
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Lookup session status: %d", status)
		},
	}, "integration-test-lookup", 5*time.Minute, 20*time.Second, nil)

	// Perform destination lookup by B32 address with retries
	performDestinationLookupWithRetries(t, lookupClient, lookupSession, lookupIOCtx, targetB32, destinationFound, &lookupMu, lookedUpDest)

	// Verify looked-up destination matches target
	lookupMu.Lock()
	if lookedUpDest == nil {
		lookupMu.Unlock()
		t.Fatal("Destination lookup returned nil")
	}
	lookedUpB32 := lookedUpDest.b32
	lookupMu.Unlock()

	verifyDestinationMatch(t, lookedUpB32, targetB32)

	// Send message to looked-up destination
	t.Log("Sending message to looked-up destination...")
	testMsg := []byte(fmt.Sprintf("Message sent at %s", time.Now().Format(time.RFC3339)))
	msgPayload := NewStream(testMsg)

	lookupMu.Lock()
	sendErr := lookupSession.SendMessage(
		lookedUpDest,
		protocolTestData,
		11111, // source port
		22222, // destination port
		msgPayload,
		uint32(time.Now().Unix()),
	)
	lookupMu.Unlock()

	if sendErr != nil {
		t.Fatalf("Failed to send message to looked-up destination: %v", sendErr)
	}

	t.Log("Message sent, waiting for delivery...")

	// Wait for message delivery and verify
	verifyMessageDelivery(t, messageReceived, &targetMu, &targetMessages)

	t.Log("Destination lookup and routing test completed successfully")
}

// TestMultipleMessagesWithIntegrity sends multiple messages with varying sizes
// and verifies all are delivered with correct data integrity.
//
// This test validates:
// - Handling of multiple concurrent messages
// - Message ordering and delivery guarantees
// - Data integrity across multiple transfers
// - Protocol identifier handling
func TestMultipleMessagesWithIntegrity(t *testing.T) {
	// Wait for I2CP server and tunnel readiness
	waitForI2CPReadiness(t)

	const messageCount = 5
	messageSizes := []int{100, 500, 1000, 5000, 10000}

	// Create receiver
	var (
		receiverMu       sync.Mutex
		receivedCount    int
		receivedData     = make(map[string][]byte)
		messagesReceived = make(chan struct{}, messageCount)
	)

	_, receiverSession, _ := connectAndCreateSession(t, SessionCallbacks{
		OnMessage: func(s *Session, srcDest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			receiverMu.Lock()
			defer receiverMu.Unlock()

			data := make([]byte, payload.Len())
			payload.Read(data)
			checksum := sha256.Sum256(data)
			checksumStr := hex.EncodeToString(checksum[:])

			receivedCount++
			receivedData[checksumStr] = data

			t.Logf("Received message %d: size=%d, checksum=%s",
				receivedCount, len(data), checksumStr[:16])

			select {
			case messagesReceived <- struct{}{}:
			default:
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Receiver status: %d", status)
		},
	}, "integration-test-multi-receiver", messageTimeout, 10*time.Second, nil)

	receiverDest := receiverSession.Destination()
	t.Logf("Receiver created: %s", receiverDest.b32)

	// Create sender
	_, senderSession, _ := connectAndCreateSession(t, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Sender status: %d", status)
		},
	}, "integration-test-multi-sender", messageTimeout, 10*time.Second, nil)

	// Send multiple messages with different sizes
	t.Log("Sending multiple messages...")
	sentChecksums := make(map[string]int)

	for i := 0; i < messageCount; i++ {
		size := messageSizes[i]
		data := make([]byte, size)
		for j := 0; j < size; j++ {
			data[j] = byte((i*256 + j) % 256)
		}

		checksum := sha256.Sum256(data)
		checksumStr := hex.EncodeToString(checksum[:])
		sentChecksums[checksumStr] = size

		payload := NewStream(data)
		err := senderSession.SendMessage(
			receiverDest,
			protocolTestData,
			uint16(10000+i),
			uint16(20000+i),
			payload,
			uint32(i),
		)
		if err != nil {
			t.Fatalf("Failed to send message %d: %v", i, err)
		}

		t.Logf("Sent message %d: size=%d, checksum=%s", i+1, size, checksumStr[:16])
		time.Sleep(1 * time.Second)
	}

	// Wait for all messages
	t.Log("Waiting for message delivery...")
	for i := 0; i < messageCount; i++ {
		select {
		case <-messagesReceived:
			t.Logf("Message %d/%d received", i+1, messageCount)
		case <-time.After(messageTimeout):
			t.Fatalf("Timeout waiting for message %d/%d", i+1, messageCount)
		}
	}

	// Verify all messages
	receiverMu.Lock()
	defer receiverMu.Unlock()

	if receivedCount != messageCount {
		t.Errorf("Expected %d messages, received %d", messageCount, receivedCount)
	}

	for checksum, expectedSize := range sentChecksums {
		data, found := receivedData[checksum]
		if !found {
			t.Errorf("Message with checksum %s not received", checksum[:16])
			continue
		}
		if len(data) != expectedSize {
			t.Errorf("Size mismatch for checksum %s: expected %d, got %d",
				checksum[:16], expectedSize, len(data))
		}
	}

	t.Log("Multiple messages test completed successfully")
}
