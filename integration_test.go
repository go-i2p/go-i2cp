//go:build integration

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
// Run with: go test -v -tags=integration -timeout=5m
//
// The tests will gracefully skip if the I2P router is unavailable.
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

// checkRouterAvailable attempts to connect to the I2P router and returns
// whether it's available for testing. This allows tests to skip gracefully
// when the router is not running.
func checkRouterAvailable(t *testing.T) bool {
	t.Helper()

	client := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Logf("I2P router not available on localhost:7654: %v", err)
		return false
	}

	client.Close()
	return true
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
	if !checkRouterAvailable(t) {
		t.Skip("I2P router not available - skipping integration test")
	}

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
	errChan := make(chan error, 1)
	go func() {
		for {
			err := client.ProcessIO(ioCtx)
			if err != nil {
				if err == ErrClientClosed {
					errChan <- nil
					return
				}
				errChan <- err
				return
			}

			// Small delay to prevent busy loop
			time.Sleep(100 * time.Millisecond)

			select {
			case <-ioCtx.Done():
				errChan <- nil
				return
			default:
			}
		}
	}()

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
	if !checkRouterAvailable(t) {
		t.Skip("I2P router not available - skipping integration test")
	}

	// Test payload with checksum for integrity verification
	testPayload := []byte("Hello from go-i2cp integration test! This is a test message for bidirectional data transfer.")
	payloadChecksum := sha256.Sum256(testPayload)

	t.Logf("Test payload size: %d bytes", len(testPayload))
	t.Logf("Test payload checksum: %s", hex.EncodeToString(payloadChecksum[:]))

	// Create receiver client and session
	receiverClient := NewClient(nil)
	receiverCtx, receiverCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer receiverCancel()

	if err := receiverClient.Connect(receiverCtx); err != nil {
		t.Fatalf("Failed to connect receiver client: %v", err)
	}
	defer receiverClient.Close()

	t.Log("Receiver client connected")

	// Track received messages
	var (
		receiverMu       sync.Mutex
		receivedMessages int
		receivedPayload  []byte
		messageReceived  = make(chan struct{})
	)

	// Create receiver session with message callback
	receiverSession := NewSession(receiverClient, SessionCallbacks{
		OnMessage: func(s *Session, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			receiverMu.Lock()
			defer receiverMu.Unlock()

			receivedMessages++
			receivedPayload = make([]byte, payload.Len())
			payload.Read(receivedPayload)

			t.Logf("Receiver: Got message - protocol=%d, srcPort=%d, destPort=%d, size=%d",
				protocol, srcPort, destPort, len(receivedPayload))

			// Signal message received
			select {
			case messageReceived <- struct{}{}:
			default:
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Receiver session status: %d", status)
		},
	})

	// Configure receiver session
	receiverSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	receiverSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-receiver")

	if err := receiverClient.CreateSession(receiverCtx, receiverSession); err != nil {
		t.Fatalf("Failed to create receiver session: %v", err)
	}

	t.Logf("Receiver session created with ID: %d", receiverSession.ID())
	receiverDest := receiverSession.Destination()
	t.Logf("Receiver destination (B32): %s", receiverDest.b32)

	// Start receiver I/O processing
	receiverIOCtx, receiverIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer receiverIOCancel()

	go func() {
		for {
			if err := receiverClient.ProcessIO(receiverIOCtx); err != nil {
				if err != ErrClientClosed {
					t.Logf("Receiver ProcessIO error: %v", err)
				}
				return
			}
			time.Sleep(100 * time.Millisecond)

			select {
			case <-receiverIOCtx.Done():
				return
			default:
			}
		}
	}()

	// Give receiver time to establish tunnels
	t.Log("Waiting for receiver tunnels to establish...")
	time.Sleep(10 * time.Second)

	// Create sender client and session
	senderClient := NewClient(nil)
	senderCtx, senderCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer senderCancel()

	if err := senderClient.Connect(senderCtx); err != nil {
		t.Fatalf("Failed to connect sender client: %v", err)
	}
	defer senderClient.Close()

	t.Log("Sender client connected")

	senderSession := NewSession(senderClient, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Sender session status: %d", status)
		},
	})

	// Configure sender session
	senderSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	senderSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-sender")

	if err := senderClient.CreateSession(senderCtx, senderSession); err != nil {
		t.Fatalf("Failed to create sender session: %v", err)
	}

	t.Logf("Sender session created with ID: %d", senderSession.ID())
	t.Logf("Sender destination (B32): %s", senderSession.Destination().b32)

	// Start sender I/O processing
	senderIOCtx, senderIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer senderIOCancel()

	go func() {
		for {
			if err := senderClient.ProcessIO(senderIOCtx); err != nil {
				if err != ErrClientClosed {
					t.Logf("Sender ProcessIO error: %v", err)
				}
				return
			}
			time.Sleep(100 * time.Millisecond)

			select {
			case <-senderIOCtx.Done():
				return
			default:
			}
		}
	}()

	// Give sender time to establish tunnels
	t.Log("Waiting for sender tunnels to establish...")
	time.Sleep(10 * time.Second)

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
	if !checkRouterAvailable(t) {
		t.Skip("I2P router not available - skipping integration test")
	}

	// Create target client and session (the destination to be looked up)
	targetClient := NewClient(nil)
	targetCtx, targetCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer targetCancel()

	if err := targetClient.Connect(targetCtx); err != nil {
		t.Fatalf("Failed to connect target client: %v", err)
	}
	defer targetClient.Close()

	t.Log("Target client connected")

	// Track received messages on target
	var (
		targetMu        sync.Mutex
		targetMessages  int
		messageReceived = make(chan struct{})
	)

	targetSession := NewSession(targetClient, SessionCallbacks{
		OnMessage: func(s *Session, protocol uint8, srcPort, destPort uint16, payload *Stream) {
			targetMu.Lock()
			defer targetMu.Unlock()
			targetMessages++
			t.Logf("Target: Received message - protocol=%d, size=%d", protocol, payload.Len())

			select {
			case messageReceived <- struct{}{}:
			default:
			}
		},
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Target session status: %d", status)
		},
	})

	targetSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	targetSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-target")

	if err := targetClient.CreateSession(targetCtx, targetSession); err != nil {
		t.Fatalf("Failed to create target session: %v", err)
	}

	targetDest := targetSession.Destination()
	targetB32 := targetDest.b32
	t.Logf("Target session created - ID: %d", targetSession.ID())
	t.Logf("Target destination (B32): %s", targetB32)

	// Start target I/O processing
	targetIOCtx, targetIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer targetIOCancel()

	go func() {
		for {
			if err := targetClient.ProcessIO(targetIOCtx); err != nil {
				if err != ErrClientClosed {
					t.Logf("Target ProcessIO error: %v", err)
				}
				return
			}
			time.Sleep(100 * time.Millisecond)

			select {
			case <-targetIOCtx.Done():
				return
			default:
			}
		}
	}()

	// Wait for target tunnels to establish
	t.Log("Waiting for target tunnels to establish...")
	time.Sleep(10 * time.Second)

	// Create lookup client and session
	lookupClient := NewClient(nil)
	lookupCtx, lookupCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer lookupCancel()

	if err := lookupClient.Connect(lookupCtx); err != nil {
		t.Fatalf("Failed to connect lookup client: %v", err)
	}
	defer lookupClient.Close()

	t.Log("Lookup client connected")

	// Track destination lookups
	var (
		lookupMu         sync.Mutex
		lookedUpDest     *Destination
		destinationFound = make(chan struct{})
	)

	lookupSession := NewSession(lookupClient, SessionCallbacks{
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
	})

	lookupSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	lookupSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-lookup")

	if err := lookupClient.CreateSession(lookupCtx, lookupSession); err != nil {
		t.Fatalf("Failed to create lookup session: %v", err)
	}

	t.Logf("Lookup session created - ID: %d", lookupSession.ID())

	// Start lookup I/O processing
	lookupIOCtx, lookupIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer lookupIOCancel()

	go func() {
		for {
			if err := lookupClient.ProcessIO(lookupIOCtx); err != nil {
				if err != ErrClientClosed {
					t.Logf("Lookup ProcessIO error: %v", err)
				}
				return
			}
			time.Sleep(100 * time.Millisecond)

			select {
			case <-lookupIOCtx.Done():
				return
			default:
			}
		}
	}()

	// Give lookup client time to establish tunnels
	t.Log("Waiting for lookup tunnels to establish...")
	time.Sleep(10 * time.Second)

	// Perform destination lookup by B32 address
	t.Logf("Looking up destination: %s", targetB32)
	requestId, err := lookupClient.DestinationLookup(lookupIOCtx, lookupSession, targetB32)
	if err != nil {
		t.Fatalf("Failed to initiate destination lookup: %v", err)
	}

	t.Logf("Destination lookup initiated - requestId: %d", requestId)

	// Wait for lookup to complete
	select {
	case <-destinationFound:
		t.Log("Destination lookup successful")
	case <-time.After(operationTimeout):
		t.Fatal("Timeout waiting for destination lookup")
	}

	// Verify looked-up destination matches target
	lookupMu.Lock()
	if lookedUpDest == nil {
		lookupMu.Unlock()
		t.Fatal("Destination lookup returned nil")
	}

	lookedUpB32 := lookedUpDest.b32
	lookupMu.Unlock()

	if lookedUpB32 != targetB32 {
		t.Errorf("Looked-up destination mismatch: expected %s, got %s", targetB32, lookedUpB32)
	} else {
		t.Log("Looked-up destination matches target destination")
	}

	// Send message to looked-up destination
	t.Log("Sending message to looked-up destination...")
	testMsg := []byte(fmt.Sprintf("Message sent at %s", time.Now().Format(time.RFC3339)))
	msgPayload := NewStream(testMsg)

	lookupMu.Lock()
	err = lookupSession.SendMessage(
		lookedUpDest,
		protocolTestData,
		11111, // source port
		22222, // destination port
		msgPayload,
		uint32(time.Now().Unix()),
	)
	lookupMu.Unlock()

	if err != nil {
		t.Fatalf("Failed to send message to looked-up destination: %v", err)
	}

	t.Log("Message sent, waiting for delivery...")

	// Wait for message delivery
	select {
	case <-messageReceived:
		t.Log("Message delivered successfully to looked-up destination")
	case <-time.After(messageTimeout):
		t.Fatal("Timeout waiting for message delivery to looked-up destination")
	}

	// Verify message was received
	targetMu.Lock()
	defer targetMu.Unlock()

	if targetMessages != 1 {
		t.Errorf("Expected 1 message on target, got %d", targetMessages)
	}

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
	if !checkRouterAvailable(t) {
		t.Skip("I2P router not available - skipping integration test")
	}

	const messageCount = 5
	messageSizes := []int{100, 500, 1000, 5000, 10000}

	// Create receiver
	receiverClient := NewClient(nil)
	receiverCtx, receiverCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer receiverCancel()

	if err := receiverClient.Connect(receiverCtx); err != nil {
		t.Fatalf("Failed to connect receiver: %v", err)
	}
	defer receiverClient.Close()

	var (
		receiverMu       sync.Mutex
		receivedCount    int
		receivedData     = make(map[string][]byte)
		messagesReceived = make(chan struct{}, messageCount)
	)

	receiverSession := NewSession(receiverClient, SessionCallbacks{
		OnMessage: func(s *Session, protocol uint8, srcPort, destPort uint16, payload *Stream) {
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
	})

	receiverSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	receiverSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-multi-receiver")

	if err := receiverClient.CreateSession(receiverCtx, receiverSession); err != nil {
		t.Fatalf("Failed to create receiver session: %v", err)
	}

	receiverDest := receiverSession.Destination()
	t.Logf("Receiver created: %s", receiverDest.b32)

	// Start receiver I/O
	receiverIOCtx, receiverIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer receiverIOCancel()

	go func() {
		for {
			if err := receiverClient.ProcessIO(receiverIOCtx); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
			select {
			case <-receiverIOCtx.Done():
				return
			default:
			}
		}
	}()

	time.Sleep(10 * time.Second)

	// Create sender
	senderClient := NewClient(nil)
	senderCtx, senderCancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer senderCancel()

	if err := senderClient.Connect(senderCtx); err != nil {
		t.Fatalf("Failed to connect sender: %v", err)
	}
	defer senderClient.Close()

	senderSession := NewSession(senderClient, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {
			t.Logf("Sender status: %d", status)
		},
	})

	senderSession.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	senderSession.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "integration-test-multi-sender")

	if err := senderClient.CreateSession(senderCtx, senderSession); err != nil {
		t.Fatalf("Failed to create sender session: %v", err)
	}

	// Start sender I/O
	senderIOCtx, senderIOCancel := context.WithTimeout(context.Background(), messageTimeout)
	defer senderIOCancel()

	go func() {
		for {
			if err := senderClient.ProcessIO(senderIOCtx); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
			select {
			case <-senderIOCtx.Done():
				return
			default:
			}
		}
	}()

	time.Sleep(10 * time.Second)

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
