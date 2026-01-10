package go_i2cp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/common/base32"
)

type ClientProperty int

const (
	CLIENT_PROP_ROUTER_ADDRESS ClientProperty = iota
	CLIENT_PROP_ROUTER_PORT
	CLIENT_PROP_ROUTER_USE_TLS
	CLIENT_PROP_USERNAME
	CLIENT_PROP_PASSWORD
	CLIENT_PROP_TLS_CERT_FILE
	CLIENT_PROP_TLS_KEY_FILE
	CLIENT_PROP_TLS_CA_FILE
	CLIENT_PROP_TLS_INSECURE
	NR_OF_I2CP_CLIENT_PROPERTIES
)

var defaultProperties = map[string]string{
	"i2cp.password":                  "",
	"i2cp.username":                  "",
	"i2cp.closeIdleTime":             "",
	"i2cp.closeOnIdle":               "",
	"i2cp.encryptLeaseSet":           "",
	"i2cp.fastReceive":               "",
	"i2cp.gzip":                      "",
	"i2cp.leaseSetKey":               "",
	"i2cp.leaseSetPrivateKey":        "",
	"i2cp.leaseSetSigningPrivateKey": "",
	"i2cp.messageReliability":        "",
	"i2cp.reduceIdleTime":            "",
	"i2cp.reduceOnIdle":              "",
	"i2cp.reduceQuantity":            "",
	"i2cp.SSL":                       "false",
	"i2cp.SSL.certFile":              "",
	"i2cp.SSL.keyFile":               "",
	"i2cp.SSL.caFile":                "",
	"i2cp.SSL.insecure":              "false",
	"i2cp.tcp.host":                  "127.0.0.1",
	"i2cp.tcp.port":                  "7654",
	// Tunnel configuration (I2CP defaults for anonymity/performance balance)
	// Higher values = more anonymity but more overhead
	// 3 tunnels with 3 hops each provides strong anonymity
	"inbound.quantity":        "3", // Number of inbound tunnels
	"inbound.length":          "3", // Hops per inbound tunnel
	"outbound.quantity":       "3", // Number of outbound tunnels
	"outbound.length":         "3", // Hops per outbound tunnel
	"inbound.backupQuantity":  "0", // Number of backup inbound tunnels
	"outbound.backupQuantity": "0", // Number of backup outbound tunnels
}

type Client struct {
	callbacks       *ClientCallBacks
	properties      map[string]string
	tcp             Tcp
	outputStream    *Stream
	messageStream   *Stream
	receiveStream   *Stream // Dedicated buffer for receiving messages (prevents corruption from messageStream reuse)
	router          RouterInfo
	outputQueue     []*Stream
	sessions        map[uint16]*Session
	n_sessions      int
	lookup          map[string]uint32
	lookupReq       map[uint32]LookupEntry
	lock            sync.Mutex
	connected       bool
	currentSession  *Session // *opaque in the C lib
	lookupRequestId uint32
	crypto          *Crypto
	shutdown        chan struct{}  // Channel to signal shutdown
	wg              sync.WaitGroup // WaitGroup for goroutine tracking

	// Router time synchronization (CRITICAL FIX: I2CP spec requires ±30 sec accuracy)
	// Stores offset between router time and local time from SetDateMessage
	routerTimeDelta int64        // milliseconds offset: router_time - local_time
	routerTimeMu    sync.RWMutex // Protects router time delta access

	// Router version tracking (I2CP spec § Version Notes, since 0.8.7)
	// Stores I2CP protocol version string from SetDateMessage for feature detection
	routerVersion   string       // e.g. "0.9.67" - empty if router < 0.8.7
	routerVersionMu sync.RWMutex // Protects router version access

	// Multi-session support (MAJOR FIX: I2CP spec § Multi-Session as of 0.9.21)
	// Tracks primary session (first created) vs subsessions for proper lifecycle management
	primarySessionID *uint16 // ID of the first created session (nil if no sessions yet)

	// Reconnection support (I2CP enhancement for production reliability)
	reconnectEnabled    bool          // Whether auto-reconnect is enabled
	reconnectAttempts   int           // Current number of reconnection attempts
	reconnectMaxRetries int           // Maximum number of reconnection attempts (0 = infinite)
	reconnectBackoff    time.Duration // Initial backoff duration between reconnect attempts
	reconnectMu         sync.Mutex    // Protects reconnection state

	// Metrics collection (optional production monitoring)
	metrics MetricsCollector // nil = metrics disabled

	// Circuit breaker (I2CP enhancement for router failure protection)
	// Prevents cascading failures by failing fast when router is unreachable
	circuitBreaker *CircuitBreaker // nil = circuit breaking disabled

	// Message batching (performance optimization)
	batchEnabled       bool          // Whether message batching is enabled
	batchFlushTimer    time.Duration // Time to wait before flushing batch (default 10ms)
	batchSizeThreshold int           // Size threshold for immediate flush (default 16KB)
	batchTicker        *time.Ticker  // Ticker for periodic batch flushing
	batchMu            sync.Mutex    // Protects batch state

	// Message statistics (diagnostic tool for troubleshooting)
	messageStats *MessageStats // nil = stats disabled, use EnableMessageStats() to enable

	// Session state tracking (diagnostic tool for troubleshooting session lifecycle)
	stateTracker *SessionStateTracker // nil = tracking disabled, use EnableDebugging() to enable

	// Protocol debugging (enhanced diagnostic tool for protocol analysis)
	protocolDebugger *ProtocolDebugger // nil = debugging disabled, use EnableDebugging() to enable
}

var defaultConfigFile = "/.i2cp.conf"

// NewClient creates a new i2p client with the specified callbacks
func NewClient(callbacks *ClientCallBacks) (c *Client) {
	c = new(Client)
	c.callbacks = callbacks
	c.crypto = NewCrypto()
	LogInit(ERROR)
	c.outputStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
	c.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
	c.receiveStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))
	c.setDefaultProperties()
	c.lookup = make(map[string]uint32, 1000)
	c.lookupReq = make(map[uint32]LookupEntry, 1000)

	// Initialize message batching with defaults
	c.batchEnabled = false // Disabled by default for backward compatibility
	c.batchFlushTimer = 10 * time.Millisecond
	c.batchSizeThreshold = 16 * 1024 // 16KB

	// Initialize circuit breaker with production defaults
	// 5 failures = reasonable threshold for router issues
	// 30 seconds = enough time for router to recover
	c.circuitBreaker = NewCircuitBreaker(5, 30*time.Second)

	c.sessions = make(map[uint16]*Session)
	c.outputQueue = make([]*Stream, 0)
	c.shutdown = make(chan struct{})
	c.tcp.Init()
	return
}

func (c *Client) setDefaultProperties() {
	// Create a copy of defaultProperties to avoid shared map reference
	c.properties = make(map[string]string, len(defaultProperties))
	for k, v := range defaultProperties {
		c.properties[k] = v
	}
	home := os.Getenv("I2CP_HOME")
	if len(home) == 0 {
		home = ""
	}
	conf := os.Getenv("GO_I2CP_CONF")
	if len(conf) == 0 {
		conf = defaultConfigFile
	}
	config := home + conf
	Debug("Loading config file %s", config)
	ParseConfig(config, c.SetProperty)
}

// ensureInitialized checks if the Client has been properly initialized.
// Returns ErrClientNotInitialized if the client was created with zero-value (Client{})
// instead of using NewClient().
//
// This method checks critical fields that must be non-nil for the client to function:
// - crypto: Required for all cryptographic operations
// - properties: Required for configuration
// - sessions: Required for session management
//
// This is a defensive check to prevent nil pointer panics from zero-value Client usage.
func (c *Client) ensureInitialized() error {
	if c.crypto == nil {
		return ErrClientNotInitialized
	}
	if c.properties == nil {
		return ErrClientNotInitialized
	}
	if c.sessions == nil {
		return ErrClientNotInitialized
	}
	return nil
}

func (c *Client) sendMessage(typ uint8, stream *Stream, queue bool) (err error) {
	send := NewStream(make([]byte, 0, stream.Len()+4+1))
	err = send.WriteUint32(uint32(stream.Len()))
	err = send.WriteByte(typ)
	lenb := stream.Len()
	_ = lenb
	_, err = send.Write(stream.Bytes())
	lenc := send.Len()
	_ = lenc

	// Track message being sent (if stats enabled)
	if c.messageStats != nil && c.messageStats.IsEnabled() {
		c.messageStats.RecordSent(typ, uint64(lenc))
	}

	// Protocol debugging - log all sent messages
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		c.protocolDebugger.LogMessage("SEND", typ, uint32(stream.Len()), stream.Bytes(), 0)
	}

	if queue {
		Debug("Putting %d bytes message on the output queue.", send.Len())
		c.lock.Lock()
		c.outputQueue = append(c.outputQueue, send)

		// Check if batching is enabled and size threshold exceeded
		if c.batchEnabled && c.getTotalQueueSize() >= c.batchSizeThreshold {
			c.lock.Unlock()
			// Flush immediately when threshold exceeded
			Debug("Batch size threshold exceeded (%d bytes), flushing immediately", c.getTotalQueueSize())
			return c.flushOutputQueue()
		}
		c.lock.Unlock()
	} else {
		// Track bandwidth and message sent
		if c.metrics != nil {
			c.metrics.AddBytesSent(uint64(send.Len()))
			c.metrics.IncrementMessageSent(typ)
		}

		// Use circuit breaker if available to protect against router failures
		if c.circuitBreaker != nil {
			err = c.circuitBreaker.Execute(func() error {
				_, sendErr := c.tcp.Send(send)
				return sendErr
			})
		} else {
			_, err = c.tcp.Send(send)
		}
	}
	return
}

func (c *Client) recvMessage(typ uint8, stream *Stream, dispatch bool) (err error) {
	// Read and parse message header
	length, msgType, err := c.readMessageHeader()
	if err != nil {
		return err
	}

	// Validate message length and type
	if err := c.validateMessageHeader(msgType, length, typ); err != nil {
		return err
	}

	// Receive message body
	if err := c.receiveMessageBody(length, stream); err != nil {
		return err
	}

	Debug("Received message type %d with %d bytes", msgType, length)

	// Track metrics and dispatch message
	c.processReceivedMessage(msgType, length, stream, dispatch)
	return nil
}

// readMessageHeader reads the 5-byte message header from the TCP connection.
// Returns the message length, type, and any error encountered during reading.
func (c *Client) readMessageHeader() (uint32, uint8, error) {
	firstFive := NewStream(make([]byte, 5))
	i, err := c.tcp.Receive(firstFive)
	if i == 0 {
		c.trackError("network")
		if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
			c.callbacks.OnDisconnect(c, "Didn't receive anything", nil)
		}
		return 0, 0, fmt.Errorf("no data received from router")
	}
	if err != nil {
		c.trackError("network")
		Error("Failed to receive message header: %s", err.Error())
		return 0, 0, err
	}

	length, err := firstFive.ReadUint32()
	if err != nil {
		Error("Failed to read message length: %s", err.Error())
		return 0, 0, err
	}

	msgType, err := firstFive.ReadByte()
	if err != nil {
		Error("Failed to read message type: %s", err.Error())
		return 0, 0, err
	}

	return length, msgType, nil
}

// validateMessageHeader validates the message length against protocol limits and checks message type.
// It enforces the I2CP protocol maximum message size of 64KB and validates expected message types.
func (c *Client) validateMessageHeader(msgType uint8, length uint32, expectedType uint8) error {
	// Enhanced message length validation with type-specific handling
	if msgType == I2CP_MSG_SET_DATE && length > 0xffff {
		c.trackError("protocol")
		Fatal("Unexpected response for SetDate message, check that your router SSL settings match the ~/.i2cp.conf configuration")
		return fmt.Errorf("invalid SetDate message length: %d", length)
	}

	// Enforce I2CP protocol maximum message size limit
	// The I2CP specification defines a maximum message size of 65535 bytes (64KB)
	// for all message types to ensure consistent behavior across implementations
	const I2CP_MAX_MESSAGE_SIZE = 0xffff // 64KB - I2CP protocol limit

	if length > I2CP_MAX_MESSAGE_SIZE {
		c.trackError("protocol")
		Error("Message length %d exceeds I2CP protocol limit %d", length, I2CP_MAX_MESSAGE_SIZE)
		return fmt.Errorf("message exceeds I2CP limit: %d > %d bytes", length, I2CP_MAX_MESSAGE_SIZE)
	}

	// Validate expected message type if specified
	if (expectedType != I2CP_MSG_ANY) && (msgType != expectedType) {
		c.trackError("protocol")
		Error("Expected message type %d, received %d", expectedType, msgType)
		return fmt.Errorf("unexpected message type: expected %d, got %d", expectedType, msgType)
	}

	return nil
}

// receiveMessageBody receives the message body from the TCP connection, handling partial reads.
// It reads the specified length of bytes and writes them to the provided stream.
func (c *Client) receiveMessageBody(length uint32, stream *Stream) error {
	if length == 0 {
		stream.Reset()
		return nil
	}

	messageBody := NewStream(make([]byte, 0, length)) // Create empty buffer with capacity
	totalReceived := 0

	// Handle partial reads for large messages
	for totalReceived < int(length) {
		remaining := int(length) - totalReceived
		tempBuffer := NewStream(make([]byte, remaining))

		i, err := c.tcp.Receive(tempBuffer)
		if err != nil {
			Error("Failed to receive message body: %s", err.Error())
			return err
		}
		if i == 0 {
			Error("Connection closed while reading message body")
			return fmt.Errorf("connection closed during message receive")
		}

		// Copy received data to main message buffer
		tempBuffer.Seek(0, 0) // Reset to beginning
		receivedData := make([]byte, i)
		tempBuffer.Read(receivedData)
		messageBody.Write(receivedData)
		totalReceived += i

		Debug("Received %d/%d bytes of message body", totalReceived, length)
	}

	// Reset stream position for message processing
	messageBody.Seek(0, 0)
	stream.Reset()
	stream.Write(messageBody.Bytes())
	stream.Seek(0, 0)

	return nil
}

// processReceivedMessage tracks metrics and dispatches the received message to handlers.
// It updates bandwidth and message counters, then optionally dispatches to message handlers.
func (c *Client) processReceivedMessage(msgType uint8, length uint32, stream *Stream, dispatch bool) {
	// Track bandwidth and message received
	if c.metrics != nil {
		c.metrics.AddBytesReceived(uint64(length + 5)) // +5 for header
		c.metrics.IncrementMessageReceived(msgType)
	}

	// Track message statistics (if enabled)
	if c.messageStats != nil && c.messageStats.IsEnabled() {
		c.messageStats.RecordReceived(msgType, uint64(length+5))
	}

	// Protocol debugging - log all received messages
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		data := stream.Bytes()
		c.protocolDebugger.LogMessage("RECV", msgType, length, data, 0)
	}

	if dispatch {
		c.onMessage(msgType, stream)
	}
}

func (c *Client) onMessage(msgType uint8, stream *Stream) {
	Debug("Dispatching I2CP message type %d (%s) to handler", msgType, getMessageTypeName(msgType))
	switch msgType {
	case I2CP_MSG_SET_DATE:
		c.onMsgSetDate(stream)
	case I2CP_MSG_DISCONNECT:
		c.onMsgDisconnect(stream)
	case I2CP_MSG_RECEIVE_MESSAGE_BEGIN:
		// MINOR FIX: Warn about deprecated message type per I2CP spec 0.9.4+
		Warning("Received deprecated RECEIVE_MESSAGE_BEGIN (type 6) - not used in fastReceive mode (default since 0.9.4)")
		c.onMsgReceiveMessageBegin(stream)
	case I2CP_MSG_RECEIVE_MESSAGE_END:
		// MINOR FIX: Warn about deprecated message type per I2CP spec 0.9.4+
		Warning("Received deprecated RECEIVE_MESSAGE_END (type 7) - not used in fastReceive mode (default since 0.9.4)")
		c.onMsgReceiveMessageEnd(stream)
	case I2CP_MSG_PAYLOAD_MESSAGE:
		c.onMsgPayload(stream)
	case I2CP_MSG_MESSAGE_STATUS:
		c.onMsgStatus(stream)
	case I2CP_MSG_DEST_REPLY:
		c.onMsgDestReply(stream)
	case I2CP_MSG_REQUEST_LEASESET:
		// MINOR FIX: Warn about deprecated message type per I2CP spec 0.9.7+
		Warning("Received deprecated REQUEST_LEASESET (type 21) - router should send REQUEST_VARIABLE_LEASESET (type 37)")
		c.onMsgRequestLeaseSet(stream)
	case I2CP_MSG_BANDWIDTH_LIMITS:
		c.onMsgBandwithLimit(stream)
	case I2CP_MSG_SESSION_STATUS:
		c.onMsgSessionStatus(stream)
	case I2CP_MSG_REPORT_ABUSE:
		// MINOR FIX: Handle deprecated REPORT_ABUSE message per I2CP spec
		// This message type exists in the spec but was never fully implemented in Java I2P
		Warning("Received deprecated REPORT_ABUSE (type 29) - UNUSED, UNSUPPORTED, treating as no-op")
	case I2CP_MSG_REQUEST_VARIABLE_LEASESET:
		c.onMsgReqVariableLease(stream)
	case I2CP_MSG_HOST_REPLY:
		c.onMsgHostReply(stream)
	case I2CP_MSG_RECONFIGURE_SESSION:
		c.onMsgReconfigureSession(stream)
	// I2CP_MSG_CREATE_LEASE_SET2 (type 41) is CLIENT→ROUTER only per Java I2P reference.
	// Routers do NOT send this message to clients. The correct router→client message
	// for LeaseSet updates is RequestVariableLeaseSetMessage (type 37).
	// Handler preserved below for testing but not dispatched for protocol conformance.
	// See AUDIT.md Critical Issue #1 for details.
	case I2CP_MSG_BLINDING_INFO:
		c.onMsgBlindingInfo(stream)
	default:
		Info("%s", "recieved unhandled i2cp message.")
	}
}

func (c *Client) onMsgSetDate(stream *Stream) {
	Debug("Received SetDate message.")
	c.debugRawMessage(stream)

	routerDate, err := c.readRouterDate(stream)
	if err != nil {
		return
	}

	version, err := c.readRouterVersion(stream)
	if err != nil {
		return
	}

	c.updateRouterInfo(routerDate, version)
	c.synchronizeRouterTime(routerDate)
}

// debugRawMessage logs the raw bytes of the SetDate message for debugging.
func (c *Client) debugRawMessage(stream *Stream) {
	rawBytes := stream.Bytes()
	Debug("SetDate raw bytes (length=%d): %v", len(rawBytes), rawBytes)
}

// readRouterDate reads and validates the router date from the stream.
func (c *Client) readRouterDate(stream *Stream) (uint64, error) {
	routerDate, err := stream.ReadUint64()
	if err != nil {
		Error("Failed to read router date: %s", err.Error())
		c.router.date = uint64(time.Now().Unix() * 1000)
		return 0, err
	}
	Debug("Read router.date = %d", routerDate)
	return routerDate, nil
}

// readRouterVersion reads the router version string from the stream.
func (c *Client) readRouterVersion(stream *Stream) (string, error) {
	verLength, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read version length: %s", err.Error())
		return "", err
	}
	Debug("Read version length = %d", verLength)

	version := make([]byte, verLength)
	_, err = stream.Read(version)
	if err != nil {
		Error("Failed to read version string: %s", err.Error())
		return "", err
	}

	return string(version), nil
}

// updateRouterInfo updates the client's router date, version, and capabilities.
func (c *Client) updateRouterInfo(routerDate uint64, version string) {
	c.router.date = routerDate
	c.router.version = parseVersion(version)
	Debug("Router version %s, date %d", version, c.router.date)

	if c.router.version.compare(Version{major: 0, minor: 9, micro: 10, qualifier: 0}) >= 0 {
		c.router.capabilities |= ROUTER_CAN_HOST_LOOKUP
	}
}

// synchronizeRouterTime calculates and stores the time delta between local and router time.
func (c *Client) synchronizeRouterTime(routerDate uint64) {
	localTime := uint64(time.Now().Unix() * 1000)
	c.routerTimeMu.Lock()
	defer c.routerTimeMu.Unlock()

	if routerDate == 0 {
		Warning("Router sent zero/invalid date - falling back to unsynchronized local time")
		c.routerTimeDelta = 0
		return
	}

	c.routerTimeDelta = int64(routerDate) - int64(localTime)
	Debug("Router time delta: %d ms (local: %d, router: %d)", c.routerTimeDelta, localTime, routerDate)

	if c.routerTimeDelta > 30000 || c.routerTimeDelta < -30000 {
		Warning("Large clock skew detected: %d ms. Session creation may fail if not corrected.", c.routerTimeDelta)
	}
}

func (c *Client) onMsgDisconnect(stream *Stream) {
	var err error
	Debug("Received Disconnect message")
	// size, err = stream.ReadByte()
	strbuf := make([]byte, stream.Len())
	lens := stream.Len()
	_ = lens
	_, err = stream.Read(strbuf)

	reason := string(strbuf)
	Debug("Received Disconnect message with reason %s", reason)

	// Record disconnect for debugging
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		c.protocolDebugger.RecordDisconnect(reason, strbuf)
	}

	// Update session states
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.lock.Lock()
		for sessionID := range c.sessions {
			c.stateTracker.SetState(sessionID, SessionStateDisconnected, fmt.Sprintf("disconnect: %s", reason))
		}
		c.lock.Unlock()
	}

	if err != nil {
		Error("Could not read msgDisconnect correctly data")
	}

	// Invoke disconnect callback if registered
	if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
		c.callbacks.OnDisconnect(c, reason, nil)
	}

	// Mark as disconnected
	c.connected = false

	// Attempt auto-reconnect if enabled (don't block the message handler)
	c.reconnectMu.Lock()
	shouldReconnect := c.reconnectEnabled
	c.reconnectMu.Unlock()

	if shouldReconnect {
		go func() {
			Info("Connection lost, attempting auto-reconnect...")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			if err := c.autoReconnect(ctx); err != nil {
				Error("Auto-reconnect failed: %v", err)
			}
		}()
	}
}

// validateGzipHeader checks if the payload starts with valid gzip header bytes.
// Returns error if header validation fails.
func validateGzipHeader(stream *Stream) error {
	gzipHeader := [3]byte{0x1f, 0x8b, 0x08}
	var testHeader [3]byte

	_, err := stream.Read(testHeader[:])
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if testHeader != gzipHeader {
		return fmt.Errorf("invalid gzip header")
	}

	return nil
}

// decompressPayload decompresses a gzip-compressed payload from the stream.
// Returns the decompressed payload buffer or an error.
func decompressPayload(msgStream *bytes.Buffer) (*bytes.Buffer, error) {
	payload := bytes.NewBuffer(make([]byte, 0xffff))

	decompress, err := gzip.NewReader(msgStream)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}

	_, err = io.Copy(payload, decompress)
	if err != nil {
		decompress.Close()
		return nil, fmt.Errorf("failed to decompress payload: %w", err)
	}

	if err = decompress.Close(); err != nil {
		return nil, fmt.Errorf("failed to close decompressor: %w", err)
	}

	return payload, nil
}

// parsePayloadHeader reads protocol, port, and other header information from the payload stream.
// Returns protocol, source port, destination port, or an error.
func parsePayloadHeader(stream *Stream) (protocol uint8, srcPort, destPort uint16, err error) {
	// Skip gzip flags
	if _, err = stream.ReadByte(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read gzip flags: %w", err)
	}

	if srcPort, err = stream.ReadUint16(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read source port: %w", err)
	}

	if destPort, err = stream.ReadUint16(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read dest port: %w", err)
	}

	// Skip protocol byte
	if _, err = stream.ReadByte(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read protocol byte: %w", err)
	}

	if protocol, err = stream.ReadByte(); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read protocol: %w", err)
	}

	return protocol, srcPort, destPort, nil
}

func (c *Client) onMsgPayload(stream *Stream) {
	Debug("Received PayloadMessage message")

	// Step 1: Read MessagePayloadMessage header (session ID, message ID)
	session, err := c.readPayloadMessageHeader(stream)
	if err != nil {
		Error("Failed to read payload message header: %v", err)
		return
	}

	// Step 2: Read payload size and extract gzip header info (protocol, ports)
	protocol, srcPort, destPort, gzipData, err := c.readPayloadWithGzipHeader(stream)
	if err != nil {
		Error("Failed to read payload with gzip header: %v", err)
		return
	}

	// Step 3: Decompress the gzip payload
	payload, err := c.decompressGzipPayload(gzipData)
	if err != nil {
		Error("Failed to decompress payload: %v", err)
		return
	}

	// Step 4: For repliable datagrams (protocol 17), parse source Destination from decompressed payload
	// For other protocols (streaming=6, raw=18, etc.), source destination is not available at this layer
	var srcDest *Destination
	if protocol == 17 { // Repliable datagram - source destination is in payload
		srcDest, payload, err = c.parseRepliableDatagramPayload(payload)
		if err != nil {
			Error("Failed to parse repliable datagram: %v", err)
			return
		}
		Debug("Message from source: %s", srcDest.Base32())
	} else {
		// For streaming (6), raw datagrams (18), and custom protocols,
		// source destination is not embedded in payload at I2CP layer
		Debug("Received payload with protocol %d (no embedded source destination)", protocol)
	}

	// Step 5: Dispatch to session
	Debug("Dispatching message payload: protocol=%d, srcPort=%d, destPort=%d, size=%d", protocol, srcPort, destPort, payload.Len())
	session.dispatchMessage(srcDest, protocol, srcPort, destPort, &Stream{payload})
}

// readPayloadMessageHeader reads session ID and message ID from MessagePayloadMessage.
// Per I2CP spec: MessagePayloadMessage contains Session ID (2), Message ID (4), Payload.
func (c *Client) readPayloadMessageHeader(stream *Stream) (*Session, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read session ID: %w", err)
	}

	messageId, err := stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read message ID: %w", err)
	}
	_ = messageId // Message ID is router-generated, currently unused

	c.lock.Lock()
	session, ok := c.sessions[sessionId]
	c.lock.Unlock()

	if !ok {
		Fatal("Session id %d does not match any of our currently initiated sessions by %p", sessionId, c)
		return nil, fmt.Errorf("session %d not found", sessionId)
	}

	return session, nil
}

// readPayloadWithGzipHeader reads the payload and extracts protocol/port info from gzip header.
// Per I2CP spec: Payload = 4-byte length + gzip data (with ports in gzip mtime, protocol in gzip OS field)
func (c *Client) readPayloadWithGzipHeader(stream *Stream) (protocol uint8, srcPort, destPort uint16, gzipData []byte, err error) {
	payloadSize, err := stream.ReadUint32()
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("failed to read payload size: %w", err)
	}

	if payloadSize == 0 {
		return 0, 0, 0, nil, fmt.Errorf("empty payload")
	}

	// Read entire gzip payload
	gzipData = make([]byte, payloadSize)
	n, err := stream.Read(gzipData)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("failed to read gzip payload: %w", err)
	}
	if uint32(n) != payloadSize {
		return 0, 0, 0, nil, fmt.Errorf("incomplete payload read: got %d, expected %d", n, payloadSize)
	}

	// Validate gzip header (bytes 0-2: 0x1F 0x8B 0x08)
	if len(gzipData) < 10 {
		return 0, 0, 0, nil, fmt.Errorf("gzip data too short: %d bytes", len(gzipData))
	}
	if gzipData[0] != 0x1f || gzipData[1] != 0x8b || gzipData[2] != 0x08 {
		return 0, 0, 0, nil, fmt.Errorf("invalid gzip header: %x %x %x", gzipData[0], gzipData[1], gzipData[2])
	}

	// Extract I2CP fields from gzip header:
	// Bytes 4-5: Source port (little-endian, in gzip mtime field)
	// Bytes 6-7: Dest port (little-endian, in gzip mtime field)
	// Byte 9: Protocol (in gzip OS field)
	srcPort = binary.LittleEndian.Uint16(gzipData[4:6])
	destPort = binary.LittleEndian.Uint16(gzipData[6:8])
	protocol = gzipData[9]

	return protocol, srcPort, destPort, gzipData, nil
}

// decompressGzipPayload decompresses gzip data and returns the payload.
func (c *Client) decompressGzipPayload(gzipData []byte) (*bytes.Buffer, error) {
	reader, err := gzip.NewReader(bytes.NewReader(gzipData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	payload := bytes.NewBuffer(make([]byte, 0, 0xffff))
	if _, err := io.Copy(payload, reader); err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return payload, nil
}

// parseRepliableDatagramPayload parses source Destination from repliable datagram (protocol 17).
// Per datagram spec: Datagram1 = Destination (387+ bytes) + Signature (64 bytes for Ed25519) + payload
func (c *Client) parseRepliableDatagramPayload(payload *bytes.Buffer) (*Destination, *bytes.Buffer, error) {
	payloadStream := NewStream(payload.Bytes())

	// Parse source Destination from decompressed payload
	srcDest, err := NewDestinationFromMessage(payloadStream, c.crypto)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse source destination from datagram: %w", err)
	}

	// Skip Ed25519 signature (64 bytes)
	const ed25519SignatureSize = 64
	sig := make([]byte, ed25519SignatureSize)
	if _, err := payloadStream.Read(sig); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature: %w", err)
	}

	// Remaining bytes are the actual payload
	remainingPayload := bytes.NewBuffer(payloadStream.Bytes())

	return srcDest, remainingPayload, nil
}

// readMessageStatusFields reads all fields from a MessageStatus message.
// Returns sessionId, messageId, status, size, nonce, and any error encountered.
func readMessageStatusFields(stream *Stream) (uint16, uint32, uint8, uint32, uint32, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to read session ID from MessageStatus: %w", err)
	}

	messageId, err := stream.ReadUint32()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to read message ID from MessageStatus: %w", err)
	}

	status, err := stream.ReadByte()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to read status from MessageStatus: %w", err)
	}

	size, err := stream.ReadUint32()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to read size from MessageStatus: %w", err)
	}

	nonce, err := stream.ReadUint32()
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("failed to read nonce from MessageStatus: %w", err)
	}

	return sessionId, messageId, status, size, nonce, nil
}

// dispatchStatusToSession finds the session and dispatches message status to it.
func (c *Client) dispatchStatusToSession(sessionId uint16, messageId uint32, status uint8, size, nonce uint32) {
	c.lock.Lock()
	sess := c.sessions[sessionId]
	c.lock.Unlock()

	if sess != nil {
		sess.dispatchMessageStatus(messageId, SessionMessageStatus(status), size, nonce)
	} else {
		Warning("MessageStatus received for unknown session %d", sessionId)
	}
}

func (c *Client) onMsgStatus(stream *Stream) {
	Debug("Received MessageStatus message")

	sessionId, messageId, status, size, nonce, err := readMessageStatusFields(stream)
	if err != nil {
		Error("%v", err)
		return
	}

	Debug("Message status; session id %d, message id %d, status %d, size %d, nonce %d", sessionId, messageId, status, size, nonce)

	c.dispatchStatusToSession(sessionId, messageId, status, size, nonce)
}

func (c *Client) onMsgDestReply(stream *Stream) {
	var b32 string
	var destination *Destination
	var lup LookupEntry
	var err error
	var requestId uint32
	Debug("Received DestReply message.")
	if stream.Len() != 32 {
		destination, err = NewDestinationFromMessage(stream, c.crypto)
		if err != nil {
			Fatal("Failed to construct destination from stream")
		}
		b32 = destination.b32
	} else {
		// Use common/base32 for I2P-specific base32 encoding
		b32Encoded := base32.EncodeToString(stream.Bytes())
		b32 = b32Encoded + ".b32.i2p"
		Debug("Could not resolve destination")
	}

	// Use two-value map access to verify lookup exists before using result
	requestId, found := c.lookup[b32]
	if !found {
		Warning("No pending lookup found for address '%s'", b32)
		return
	}
	delete(c.lookup, b32)

	lup, lupFound := c.lookupReq[requestId]
	if !lupFound {
		Warning("No lookup entry found for request ID %d (address '%s')", requestId, b32)
		return
	}
	delete(c.lookupReq, requestId)

	if lup.session == nil {
		Warning("Lookup entry for '%s' has nil session", b32)
		return
	}

	lup.session.dispatchDestination(requestId, b32, destination)
}

// onMsgReceiveMessageBegin handles deprecated ReceiveMessageBeginMessage (type 6)
// DEPRECATED: Not used in fastReceive mode (default since 0.9.4)
// per I2CP specification 0.6.x - 0.9.3 - legacy slow-receive mode
func (c *Client) onMsgReceiveMessageBegin(stream *Stream) {
	Warning("Received deprecated ReceiveMessageBeginMessage - fastReceive mode should be used")

	// Read session ID
	sessionID, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from ReceiveMessageBegin: %v", err)
		return
	}

	// Read message ID
	messageID, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read message ID from ReceiveMessageBegin: %v", err)
		return
	}

	Debug("ReceiveMessageBegin for session %d, message %d (legacy mode)",
		sessionID, messageID)

	// In legacy slow-receive mode, the client would need to send an acknowledgment
	// However, since fastReceive is default since 0.9.4, we just log this
	// Modern clients should use MessagePayloadMessage (type 31) instead
}

// onMsgReceiveMessageEnd handles deprecated ReceiveMessageEndMessage (type 7)
// DEPRECATED: Not used in fastReceive mode (default since 0.9.4)
// per I2CP specification 0.6.x - 0.9.3 - legacy slow-receive mode
func (c *Client) onMsgReceiveMessageEnd(stream *Stream) {
	Warning("Received deprecated ReceiveMessageEndMessage - fastReceive mode should be used")

	// Read session ID
	sessionID, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from ReceiveMessageEnd: %v", err)
		return
	}

	// Read message ID
	messageID, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read message ID from ReceiveMessageEnd: %v", err)
		return
	}

	Debug("ReceiveMessageEnd for session %d, message %d (legacy mode)",
		sessionID, messageID)

	// In legacy mode, this signals the end of a message transfer
	// Modern clients receive complete messages via MessagePayloadMessage
}

// onMsgRequestLeaseSet handles deprecated RequestLeaseSetMessage (type 21)
// DEPRECATED: Use RequestVariableLeaseSetMessage (type 37) for clients 0.9.7+
// per I2CP specification 0.6.x - 0.9.6 - fixed-expiration lease sets
func (c *Client) onMsgRequestLeaseSet(stream *Stream) {
	Warning("Received deprecated RequestLeaseSetMessage - converting to variable lease set format")

	// Read session ID
	sessionID, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from RequestLeaseSet: %v", err)
		return
	}

	// Legacy RequestLeaseSet uses fixed expiration time
	// Read lease count
	leaseCount, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read lease count from RequestLeaseSet: %v", err)
		return
	}

	Debug("RequestLeaseSet for session %d with %d leases (converting to variable format)",
		sessionID, leaseCount)

	// Convert to variable lease set format by calling the modern handler
	// In legacy format, expiration was fixed; modern format allows variable expiration
	// We delegate to onMsgReqVariableLease which handles the actual lease set creation
	c.onMsgReqVariableLease(stream)
}

// onMsgReportAbuse handles deprecated ReportAbuseMessage (type 29)
// DEPRECATED: Never fully implemented in I2P, unsupported
// per I2CP specification - reserved for abuse reporting (unused)
// onMsgReportAbuse is NOT dispatched from onMessage() - reserved but never implemented.
// This handler exists for protocol documentation but should never be called.
// I2CP message type 29 was reserved in the spec but never implemented in Java I2P router.
// If a router sends this message, it will be handled by the default case (unknown message).
// See AUDIT.md for details on protocol conformance.
func (c *Client) onMsgReportAbuse(stream *Stream) {
	Warning("Received unsupported ReportAbuseMessage (type 29) - reserved but never implemented")
	Error("Protocol violation: Router sent unsupported message type 29 (ReportAbuse)")
	// This should never be called since the dispatcher doesn't route this message type
}

// onMsgBandwithLimit handles BandwidthLimitsMessage (type 23) from router
// per I2CP specification - reports bandwidth limits and burst parameters
// Note: 9 fields are undefined in the spec and reserved for future use
func (c *Client) onMsgBandwithLimit(stream *Stream) {
	Debug("Received BandwidthLimits message.")

	clientInbound, clientOutbound, err := readClientBandwidthLimits(stream)
	if err != nil {
		return
	}

	routerInbound, routerInboundBurst, routerOutbound, routerOutboundBurst, burstTime, err := readRouterBandwidthLimits(stream)
	if err != nil {
		return
	}

	undefined, err := readUndefinedBandwidthFields(stream)
	if err != nil {
		return
	}

	Debug("BandwidthLimits - Client: in=%d out=%d, Router: in=%d(%d) out=%d(%d) burst=%d",
		clientInbound, clientOutbound,
		routerInbound, routerInboundBurst,
		routerOutbound, routerOutboundBurst,
		burstTime)

	dispatchBandwidthLimits(c, clientInbound, clientOutbound, routerInbound, routerInboundBurst,
		routerOutbound, routerOutboundBurst, burstTime, undefined)
}

// readClientBandwidthLimits reads client bandwidth limits from the stream.
// Returns inbound and outbound limits in bytes/second, or an error.
func readClientBandwidthLimits(stream *Stream) (uint32, uint32, error) {
	clientInbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read client inbound limit: %v", err)
		return 0, 0, err
	}

	clientOutbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read client outbound limit: %v", err)
		return 0, 0, err
	}

	return clientInbound, clientOutbound, nil
}

// readRouterBandwidthLimits reads router bandwidth limits and burst parameters from the stream.
// Returns inbound, inbound burst, outbound, outbound burst, burst time, or an error.
func readRouterBandwidthLimits(stream *Stream) (uint32, uint32, uint32, uint32, uint32, error) {
	routerInbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router inbound limit: %v", err)
		return 0, 0, 0, 0, 0, err
	}

	routerInboundBurst, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router inbound burst: %v", err)
		return 0, 0, 0, 0, 0, err
	}

	routerOutbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router outbound limit: %v", err)
		return 0, 0, 0, 0, 0, err
	}

	routerOutboundBurst, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router outbound burst: %v", err)
		return 0, 0, 0, 0, 0, err
	}

	burstTime, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read burst time: %v", err)
		return 0, 0, 0, 0, 0, err
	}

	return routerInbound, routerInboundBurst, routerOutbound, routerOutboundBurst, burstTime, nil
}

// readUndefinedBandwidthFields reads the 9 reserved/undefined uint32 fields from the stream.
// These fields are reserved for future protocol extensions.
func readUndefinedBandwidthFields(stream *Stream) ([]uint32, error) {
	undefined := make([]uint32, 9)
	for i := 0; i < 9; i++ {
		val, err := stream.ReadUint32()
		if err != nil {
			Error("Failed to read undefined field %d: %v", i, err)
			return nil, err
		}
		undefined[i] = val
	}
	return undefined, nil
}

// dispatchBandwidthLimits creates a BandwidthLimits structure and dispatches it to the callback.
// This notifies the application of bandwidth limits received from the router.
func dispatchBandwidthLimits(c *Client, clientInbound, clientOutbound, routerInbound,
	routerInboundBurst, routerOutbound, routerOutboundBurst, burstTime uint32, undefined []uint32,
) {
	limits := &BandwidthLimits{
		ClientInbound:       clientInbound,
		ClientOutbound:      clientOutbound,
		RouterInbound:       routerInbound,
		RouterInboundBurst:  routerInboundBurst,
		RouterOutbound:      routerOutbound,
		RouterOutboundBurst: routerOutboundBurst,
		BurstTime:           burstTime,
	}
	copy(limits.Undefined[:], undefined)

	Debug("Parsed bandwidth limits: %s", limits.String())

	// Dispatch callback if configured
	if c.callbacks != nil && c.callbacks.OnBandwidthLimits != nil {
		c.callbacks.OnBandwidthLimits(c, limits)
	}
}

// readSessionStatusMessage reads and validates session ID and status from the I2CP SessionStatus message.
// Returns sessionID, sessionStatus, and any error encountered during reading.
func readSessionStatusMessage(stream *Stream) (sessionID uint16, sessionStatus uint8, err error) {
	// DEBUG: Dump raw message bytes
	rawBytes := stream.Bytes()
	Debug("SessionStatus raw bytes (length=%d): %v", len(rawBytes), rawBytes)

	// CRITICAL FIX: I2CP SessionStatus message format is [sessionID: uint16][status: uint8]
	sessionID, err = stream.ReadUint16()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read session ID: %w", err)
	}

	sessionStatus, err = stream.ReadByte()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read session status: %w", err)
	}

	Debug("SessionStatus for session %d: status %d", sessionID, sessionStatus)
	return sessionID, sessionStatus, nil
}

// handleSessionCreated processes the SESSION_STATUS_CREATED message and registers the session.
// This includes primary/subsession tracking and session map registration.
func (c *Client) handleSessionCreated(sessionID uint16, sessionStatus uint8) {
	if c.currentSession == nil {
		Error("Received session status created without waiting for it %p", c)
		return
	}

	// CRITICAL FIX: I2CP spec § Session ID - Validate session ID is not 0xFFFF
	if sessionID == I2CP_SESSION_ID_NONE {
		Error("Router assigned reserved session ID 0xFFFF - spec violation")
		return
	}

	c.currentSession.id = sessionID
	Debug("Assigned session ID %d to session %p", sessionID, c.currentSession)

	// CRITICAL FIX: Register session in map BEFORE dispatching callback
	c.lock.Lock()

	// MAJOR FIX: Multi-session tracking per I2CP spec § Multi-Session (as of 0.9.21)
	if c.primarySessionID == nil {
		// This is the first session - mark as primary
		id := sessionID
		c.primarySessionID = &id
		c.currentSession.isPrimary = true
		c.currentSession.primarySession = nil
		Debug("Session %d is primary session", sessionID)
	} else {
		// This is a subsession - link to primary
		c.currentSession.isPrimary = false
		if primarySess, exists := c.sessions[*c.primarySessionID]; exists {
			c.currentSession.primarySession = primarySess
			Debug("Session %d is subsession of primary %d", sessionID, *c.primarySessionID)
		} else {
			Warning("Primary session %d not found for subsession %d", *c.primarySessionID, sessionID)
		}
	}

	// Register the session
	c.sessions[sessionID] = c.currentSession
	sess := c.currentSession
	c.currentSession = nil
	c.lock.Unlock()

	// Track session state - now awaiting RequestVariableLeaseSet
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.SetState(sessionID, SessionStateCreated, "SessionStatus CREATED received")
		c.stateTracker.SetState(sessionID, SessionStateAwaitingLeaseSet, "waiting for RequestVariableLeaseSet")
		// Start tracking how long we wait for RequestVariableLeaseSet
		c.stateTracker.StartLeaseSetWait(sessionID, 120*time.Second) // 2 minute timeout
	}

	Info(">>> Session %d CREATED - now waiting for RequestVariableLeaseSet (type 37) from router...", sessionID)
	Debug(">>> Session %d created successfully, invoking OnStatus callback with SESSION_STATUS_CREATED", sessionID)
	// Now dispatch status callback - session is already registered
	sess.dispatchStatus(SessionStatus(sessionStatus))
}

// handleNonCreatedStatus processes status updates for existing sessions or rejected session creation.
// Handles DESTROYED status and other session state changes.
func (c *Client) handleNonCreatedStatus(sessionID uint16, sessionStatus uint8) {
	c.lock.Lock()
	sess := c.sessions[sessionID]

	if sess == nil {
		// CRITICAL FIX: Handle router rejecting session creation
		if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED && c.currentSession != nil {
			Debug("Router rejected session creation for sessionID %d (received DESTROYED without CREATED)", sessionID)
			// Track rejection state
			if c.stateTracker != nil && c.stateTracker.IsEnabled() {
				c.stateTracker.SetState(sessionID, SessionStateRejected, "session rejected by router")
			}
			Error("❌ Session %d REJECTED by router (SessionStatus=DESTROYED without CREATED)", sessionID)
			sess = c.currentSession
			sess.id = sessionID
			c.currentSession = nil
			c.lock.Unlock()
			sess.dispatchStatus(SessionStatus(sessionStatus))
		} else {
			c.lock.Unlock()
			Fatal("Session with id %d doesn't exists in client instance %p.", sessionID, c)
		}
	} else {
		// I2CP SPEC COMPLIANCE: Signal destroyConfirmed when DESTROYED status received
		if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED {
			if c.stateTracker != nil && c.stateTracker.IsEnabled() {
				c.stateTracker.SetState(sessionID, SessionStateDestroyed, "SessionStatus DESTROYED received")
			}
			if sess.destroyConfirmed != nil {
				close(sess.destroyConfirmed)
				sess.destroyConfirmed = nil
			}
		}
		c.lock.Unlock()
		sess.dispatchStatus(SessionStatus(sessionStatus))
	}
}

func (c *Client) onMsgSessionStatus(stream *Stream) {
	Debug("<<< RECEIVED SessionStatus message from router")

	// Read session ID and status from message
	sessionID, sessionStatus, err := readSessionStatusMessage(stream)
	if err != nil {
		Error("Failed to read SessionStatus message: %v", err)
		return
	}

	if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_CREATED {
		c.handleSessionCreated(sessionID, sessionStatus)
	} else {
		c.handleNonCreatedStatus(sessionID, sessionStatus)
	}
}

func (c *Client) onMsgReqVariableLease(stream *Stream) {
	var sessionId uint16
	var tunnels uint8
	var sess *Session
	var leases []*Lease
	var err error

	// This is the critical message we're debugging - log prominently
	Info(">>> RECEIVED RequestVariableLeaseSet (type 37) - router is requesting LeaseSet publication!")

	Debug("Received RequestVariableLeaseSet message.")
	sessionId, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from RequestVariableLeaseSet: %v", err)
		return
	}
	tunnels, err = stream.ReadByte()
	if err != nil {
		Error("Failed to read tunnel count from RequestVariableLeaseSet: %v", err)
		return
	}

	// Record that we received the LeaseSet request
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.RecordLeaseSetReceived(sessionId, tunnels)
		c.stateTracker.SetState(sessionId, SessionStateLeaseSetRequested, fmt.Sprintf("tunnels=%d", tunnels))
	}

	c.lock.Lock()
	sess = c.sessions[sessionId]
	c.lock.Unlock()
	if sess == nil {
		Error("Session with id %d doesn't exist for RequestVariableLeaseSet", sessionId)
		return
	}
	leases = make([]*Lease, tunnels)
	for i := uint8(0); i < tunnels; i++ {
		leases[i], err = NewLeaseFromStream(stream)
		if err != nil {
			Error("Failed to parse lease %d/%d for session %d: %v", i+1, tunnels, sessionId, err)
			return
		}
	}
	Debug("Parsed %d leases for session %d", tunnels, sessionId)

	// Store leases in session for use in CreateLeaseSet2
	sess.mu.Lock()
	sess.leases = leases
	sess.mu.Unlock()

	// Use CreateLeaseSet2 (type 41) for modern crypto instead of legacy CreateLeaseSet (type 4)
	if err := c.msgCreateLeaseSet2(sess, int(tunnels), true); err != nil {
		Error("Failed to send CreateLeaseSet2 for session %d: %v", sessionId, err)
		return
	}

	// Update state after sending LeaseSet
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.SetState(sessionId, SessionStateLeaseSetSent, "CreateLeaseSet2 sent")
	}
}

func (c *Client) onMsgHostReply(stream *Stream) {
	Debug("Received HostReply message.")

	// Parse message header
	sessionId, requestId, result, err := c.parseHostReplyHeader(stream)
	if err != nil {
		return
	}

	// Process lookup result
	dest, options, lup := c.processHostReplyResult(stream, result, requestId)

	// Find session and dispatch result
	c.dispatchHostReplyResult(sessionId, requestId, dest, options, lup)
}

// parseHostReplyHeader reads the session ID, request ID, and result code from a HostReply message.
// Returns the parsed values or an error if any field cannot be read.
func (c *Client) parseHostReplyHeader(stream *Stream) (uint16, uint32, uint8, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from HostReply: %v", err)
		return 0, 0, 0, err
	}

	requestId, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read request ID from HostReply: %v", err)
		return 0, 0, 0, err
	}

	result, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read result code from HostReply: %v", err)
		return 0, 0, 0, err
	}

	return sessionId, requestId, result, nil
}

// processHostReplyResult processes the result of a host lookup, parsing the destination on success
// or logging error details on failure. Returns destination, options map, and lookup entry.
func (c *Client) processHostReplyResult(stream *Stream, result uint8, requestId uint32) (*Destination, map[string]string, LookupEntry) {
	var dest *Destination
	var options map[string]string
	var lup LookupEntry

	if result == HOST_REPLY_SUCCESS {
		dest, options, lup = c.parseSuccessfulLookup(stream, requestId)
		Debug("HostReply lookup succeeded for request %d", requestId)
	} else {
		c.logLookupFailure(result, requestId)
	}

	return dest, options, lup
}

// parseSuccessfulLookup parses the destination and optional service record options from a successful lookup.
// Returns the destination, options map, and lookup entry retrieved for type checking.
func (c *Client) parseSuccessfulLookup(stream *Stream, requestId uint32) (*Destination, map[string]string, LookupEntry) {
	dest, err := NewDestinationFromMessage(stream, c.crypto)
	if err != nil {
		Error("Failed to parse destination from HostReply: %v", err)
		return nil, nil, LookupEntry{}
	}

	// Get lookup entry to check if service record options are expected
	c.lock.Lock()
	lup := c.lookupReq[requestId]
	c.lock.Unlock()

	// Parse optional Mapping for service record lookups (I2CP 0.9.66+ Proposal 167)
	var options map[string]string
	if (lup.lookupType >= HOST_LOOKUP_TYPE_HASH_WITH_OPTIONS && lup.lookupType <= HOST_LOOKUP_TYPE_DEST_WITH_OPTIONS) && stream.Len() > 0 {
		Debug("Parsing optional Mapping for service record lookup type %d (request %d)", lup.lookupType, requestId)
		options, err = stream.ReadMapping()
		if err != nil {
			Warning("Failed to parse service record Mapping for request %d: %v", requestId, err)
			options = nil
		} else {
			Debug("Parsed %d service record options for request %d", len(options), requestId)
		}
	}

	return dest, options, lup
}

// logLookupFailure logs detailed error information for failed host lookups based on the result code.
// Provides specific error messages for each I2CP 0.9.43+ HostReply error code.
func (c *Client) logLookupFailure(result uint8, requestId uint32) {
	var errorDetail string
	switch result {
	case HOST_REPLY_FAILURE:
		errorDetail = "General lookup failure"
	case HOST_REPLY_PASSWORD_REQUIRED:
		errorDetail = "Encrypted LeaseSet requires lookup password"
	case HOST_REPLY_PRIVATE_KEY_REQUIRED:
		errorDetail = "Per-client authentication requires private key"
	case HOST_REPLY_PASSWORD_AND_KEY_REQUIRED:
		errorDetail = "Both password and private key required"
	case HOST_REPLY_DECRYPTION_FAILURE:
		errorDetail = "Failed to decrypt LeaseSet with provided credentials"
	case HOST_REPLY_LEASESET_LOOKUP_FAILURE:
		errorDetail = "LeaseSet not found in network database"
	case HOST_REPLY_LOOKUP_TYPE_UNSUPPORTED:
		errorDetail = "Lookup type not supported by router"
	default:
		errorDetail = fmt.Sprintf("Unknown error code %d", result)
	}
	Warning("HostReply lookup failed for request %d: %s (code %d)", requestId, errorDetail, result)
}

// dispatchHostReplyResult dispatches the lookup result to the appropriate session.
// It retrieves the session, updates the lookup entry with options, and dispatches the destination.
func (c *Client) dispatchHostReplyResult(sessionId uint16, requestId uint32, dest *Destination, options map[string]string, lup LookupEntry) {
	// Find session
	c.lock.Lock()
	sess := c.sessions[sessionId]
	c.lock.Unlock()
	if sess == nil {
		Error("Session with id %d doesn't exist for HostReply", sessionId)
		return
	}

	// Get and remove lookup entry
	c.lock.Lock()
	if lup.address == "" {
		lup = c.lookupReq[requestId]
	}
	delete(c.lookupReq, requestId)

	// Store parsed service record options in lookup entry
	if options != nil {
		lup.options = options
	}
	c.lock.Unlock()

	if lup.address == "" {
		Warning("No lookup entry found for request ID %d", requestId)
		return
	}

	// Dispatch destination with options (options may be nil for basic lookups)
	sess.dispatchDestinationWithOptions(requestId, lup.address, dest, lup.options)
}

// validateReconfigureProperties validates reconfiguration property values per I2CP specification.
// This prevents invalid values (negative counts, excessive tunnel quantities) from being applied
// to session configuration, matching Java router validation behavior.
func validateReconfigureProperties(properties map[string]string) error {
	for key, value := range properties {
		if err := validatePropertyBySuffix(key, value); err != nil {
			return err
		}
	}
	return nil
}

// validatePropertyBySuffix validates a single property based on its key suffix.
// Returns an error if the property value is invalid for its type.
func validatePropertyBySuffix(key, value string) error {
	// Validate tunnel quantities (must be 0-16 per I2CP spec)
	if strings.HasSuffix(key, ".quantity") {
		return validateIntegerProperty(key, value, 0, 16, "tunnel quantity")
	}

	// Validate tunnel lengths (must be 0-7 per I2CP spec)
	if strings.HasSuffix(key, ".length") {
		return validateIntegerProperty(key, value, 0, 7, "tunnel length")
	}

	// Validate length variance (must be 0-3 per I2CP spec)
	if strings.HasSuffix(key, ".lengthVariance") {
		return validateIntegerProperty(key, value, 0, 3, "length variance")
	}

	return nil
}

// validateIntegerProperty validates that a property value is an integer within the specified range.
// Returns an error if the value is not a valid integer or is outside the allowed range.
func validateIntegerProperty(key, value string, min, max int, propertyType string) error {
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid %s value '%s' for %s: %w", propertyType, value, key, err)
	}
	if intValue < min || intValue > max {
		return fmt.Errorf("%s %d out of range [%d, %d] for %s", propertyType, intValue, min, max, key)
	}
	return nil
}

// onMsgReconfigureSession handles ReconfigureSessionMessage (type 2) for dynamic session updates
// per I2CP specification section 7.1 - supports runtime tunnel and crypto parameter changes
func (c *Client) onMsgReconfigureSession(stream *Stream) {
	Debug("Received ReconfigureSessionMessage")

	sess, properties, err := c.readReconfigureSessionData(stream)
	if err != nil {
		return
	}

	if err := c.applyReconfigurationProperties(sess, properties); err != nil {
		return
	}

	sess.dispatchStatus(I2CP_SESSION_STATUS_UPDATED)
}

// readReconfigureSessionData reads and validates the session ID and properties from the stream.
// Returns the session, properties map, and any error encountered.
func (c *Client) readReconfigureSessionData(stream *Stream) (*Session, map[string]string, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from ReconfigureSessionMessage: %v", err)
		return nil, nil, err
	}

	c.lock.Lock()
	sess := c.sessions[sessionId]
	c.lock.Unlock()

	if sess == nil {
		Error("ReconfigureSessionMessage received for unknown session ID %d", sessionId)
		return nil, nil, fmt.Errorf("unknown session ID %d", sessionId)
	}

	properties, err := stream.ReadMapping()
	if err != nil {
		Error("Failed to read properties mapping from ReconfigureSessionMessage: %v", err)
		return nil, nil, err
	}

	Debug("Reconfiguring session %d with %d properties", sessionId, len(properties))
	return sess, properties, nil
}

// applyReconfigurationProperties validates and applies configuration properties to a session.
// Returns an error if validation fails or properties cannot be applied.
func (c *Client) applyReconfigurationProperties(sess *Session, properties map[string]string) error {
	if err := validateReconfigureProperties(properties); err != nil {
		Error("Invalid reconfiguration properties for session %d: %v", sess.ID(), err)
		return err
	}

	if sess.config == nil {
		return nil
	}

	for key, value := range properties {
		prop := sess.config.propFromString(key)
		if prop >= 0 && prop < NR_OF_SESSION_CONFIG_PROPERTIES {
			sess.config.SetProperty(prop, value)
			Debug("Updated session %d property %s = %s", sess.ID(), key, value)
		} else {
			Warning("Unknown session property in reconfigure: %s", key)
		}
	}

	return nil
}

// onMsgBlindingInfo handles BlindingInfoMessage (type 42) received from router.
//
// IMPORTANT: Per I2CP specification, BlindingInfoMessage is CLIENT→ROUTER ONLY.
// The router NEVER sends this message to clients. This handler exists only for:
//  1. Testing purposes (simulating message parsing)
//  2. Future-proofing if spec changes
//  3. Graceful handling of unexpected messages
//
// In production, receiving this message indicates either:
//   - A router bug
//   - Protocol version mismatch
//   - Test/development environment
//
// The handler logs a warning but processes the message to avoid disconnection.
func (c *Client) onMsgBlindingInfo(stream *Stream) {
	// SPEC NOTE: Router should NEVER send this message - log warning
	Warning("Received BlindingInfoMessage (type 42) from router - this is unexpected per I2CP spec")
	Warning("BlindingInfoMessage is CLIENT→ROUTER only; router should not send this")
	Debug("Processing unexpected BlindingInfoMessage for diagnostic purposes")

	sessionId, authScheme, flags, blindingParams, err := c.readBlindingInfoFields(stream)
	if err != nil {
		return
	}

	Debug("BlindingInfo for session %d: scheme %d, flags 0x%04x, params %d bytes",
		sessionId, authScheme, flags, len(blindingParams))

	session, ok := c.findSession(sessionId)
	if !ok {
		Error("Session with id %d doesn't exist for BlindingInfoMessage", sessionId)
		return
	}

	c.storeBlindingInfo(session, authScheme, flags, blindingParams)
	session.dispatchBlindingInfo(uint16(authScheme), flags, blindingParams)

	Debug("BlindingInfo callback not yet implemented")
}

// readBlindingInfoFields reads all fields from a BlindingInfoMessage stream.
func (c *Client) readBlindingInfoFields(stream *Stream) (sessionId uint16, authScheme uint8, flags uint16, blindingParams []byte, err error) {
	if sessionId, err = c.readBlindingSessionID(stream); err != nil {
		return
	}

	if authScheme, err = c.readBlindingAuthScheme(stream); err != nil {
		return
	}

	if flags, err = c.readBlindingFlags(stream); err != nil {
		return
	}

	if blindingParams, err = c.readBlindingParams(stream); err != nil {
		return
	}

	return
}

// readBlindingSessionID reads the session ID from a BlindingInfoMessage stream.
func (c *Client) readBlindingSessionID(stream *Stream) (uint16, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from BlindingInfoMessage: %v", err)
		return 0, err
	}
	return sessionId, nil
}

// readBlindingAuthScheme reads the authentication scheme from a BlindingInfoMessage stream.
func (c *Client) readBlindingAuthScheme(stream *Stream) (uint8, error) {
	authScheme, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read auth scheme from BlindingInfoMessage: %v", err)
		return 0, err
	}
	return authScheme, nil
}

// readBlindingFlags reads the flags from a BlindingInfoMessage stream.
func (c *Client) readBlindingFlags(stream *Stream) (uint16, error) {
	flags, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read flags from BlindingInfoMessage: %v", err)
		return 0, err
	}
	return flags, nil
}

// readBlindingParams reads the blinding parameters from a BlindingInfoMessage stream.
func (c *Client) readBlindingParams(stream *Stream) ([]byte, error) {
	paramLen, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read param length from BlindingInfoMessage: %v", err)
		return nil, err
	}

	blindingParams := make([]byte, paramLen)
	n, err := stream.Read(blindingParams)
	if err != nil {
		Error("Failed to read blinding params from BlindingInfoMessage: %v", err)
		return nil, err
	}

	if n != int(paramLen) {
		err = fmt.Errorf("expected %d bytes, got %d", paramLen, n)
		Error("Failed to read blinding params from BlindingInfoMessage: %v", err)
		return nil, err
	}

	return blindingParams, nil
}

// findSession retrieves a session by ID with proper locking.
func (c *Client) findSession(sessionId uint16) (*Session, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	session, ok := c.sessions[sessionId]
	return session, ok
}

// storeBlindingInfo stores blinding parameters in the session.
func (c *Client) storeBlindingInfo(session *Session, authScheme uint8, flags uint16, blindingParams []byte) {
	session.SetBlindingScheme(uint16(authScheme))
	session.SetBlindingFlags(flags)
	session.SetBlindingParams(blindingParams)
	Debug("Blinding info stored for session %d: enabled=%v", session.id, session.IsBlindingEnabled())
}

// initializeLeaseSetStream creates and initializes the lease set stream with null bytes.
func initializeLeaseSetStream(c *Client, sessionId uint16) *Stream {
	var nullbytes [256]byte
	for i := 0; i < len(nullbytes); i++ {
		nullbytes[i] = 0
	}

	// Reset the message stream before writing to ensure clean state
	c.messageStream.Reset()
	c.messageStream.WriteUint16(sessionId)
	c.messageStream.Write(nullbytes[:20])
	c.messageStream.Write(nullbytes[:256])

	return NewStream(make([]byte, 4096))
}

// buildLeaseSetData writes destination and lease data to the lease set stream.
func buildLeaseSetData(leaseSet *Stream, dest *Destination, sgk *SignatureKeyPair, tunnels uint8, leases []*Lease) error {
	var nullbytes [256]byte

	dest.WriteToMessage(leaseSet)
	leaseSet.Write(nullbytes[:256])

	if sgk.ed25519KeyPair == nil {
		return fmt.Errorf("Ed25519 keypair is nil for CreateLeaseSet")
	}

	paddedPubKey := make([]byte, 128)
	ed25519PubKey := sgk.ed25519KeyPair.PublicKey()
	copy(paddedPubKey[96:], ed25519PubKey[:])
	leaseSet.Write(paddedPubKey)

	leaseSet.WriteByte(tunnels)
	for i := uint8(0); i < tunnels; i++ {
		leases[i].WriteToMessage(leaseSet)
	}

	return nil
}

func (c *Client) msgCreateLeaseSet(sessionId uint16, session *Session, tunnels uint8, leases []*Lease, queue bool) {
	Debug("Sending CreateLeaseSetMessage")

	leaseSet := initializeLeaseSetStream(c, sessionId)

	config := session.config
	dest := config.destination
	sgk := &dest.sgk

	if err := buildLeaseSetData(leaseSet, dest, sgk, tunnels, leases); err != nil {
		Error("%v", err)
		return
	}

	if err := sgk.ed25519KeyPair.SignStream(leaseSet); err != nil {
		Error("Failed to sign CreateLeaseSet: %v", err)
		return
	}

	c.messageStream.Write(leaseSet.Bytes())
	if err := c.sendMessage(I2CP_MSG_CREATE_LEASE_SET, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet")
	}
}

// msgCreateLeaseSet2 sends CreateLeaseSet2Message (type 41) for modern LeaseSet creation
// per I2CP specification 0.9.39+ - supports LS2/EncryptedLS/MetaLS with modern crypto
func (c *Client) msgCreateLeaseSet2(session *Session, leaseCount int, queue bool) error {
	Debug("Sending CreateLeaseSet2Message for session %d with %d leases", session.id, leaseCount)

	// Generate X25519 encryption key pair for this session if not already present
	if session.encryptionKeyPair == nil {
		keyPair, err := NewX25519KeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate X25519 encryption key pair: %w", err)
		}
		session.encryptionKeyPair = keyPair
		Debug("Generated X25519 encryption key pair for session %d", session.id)
	}

	leaseSet := NewStream(make([]byte, 0, 4096))
	dest := session.config.destination

	c.messageStream.Reset()
	c.messageStream.WriteUint16(session.id)

	// Write LeaseSet type byte to message stream (per I2CP spec, router reads this BEFORE the LeaseSet)
	var leaseSetType uint8
	if session.IsBlindingEnabled() {
		leaseSetType = LEASESET_TYPE_ENCRYPTED
		Debug("Creating encrypted LeaseSet2 with blinding for session %d", session.id)
	} else {
		leaseSetType = LEASESET_TYPE_STANDARD
		Debug("Creating standard LeaseSet2 for session %d", session.id)
	}
	c.messageStream.WriteByte(leaseSetType)

	if err := c.buildLeaseSet2Content(session, leaseSet, dest, leaseCount); err != nil {
		return err
	}

	if err := c.signAndSendLeaseSet2(session, leaseSet, dest, queue); err != nil {
		return err
	}

	Debug("Successfully sent CreateLeaseSet2Message for session %d", session.id)
	return nil
}

// buildLeaseSet2Content constructs the complete LeaseSet2 content including header, timestamps, flags, properties, encryption keys, leases, and blinding parameters.
func (c *Client) buildLeaseSet2Content(session *Session, leaseSet *Stream, dest *Destination, leaseCount int) error {
	if err := c.writeLeaseSet2Header(session, leaseSet, dest); err != nil {
		return err
	}
	Debug("LeaseSet2 after destination: %d bytes", leaseSet.Len())

	if err := c.writeLeaseSet2Timestamps(leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after timestamps: %d bytes", leaseSet.Len())

	if err := c.writeLeaseSet2Flags(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after flags: %d bytes", leaseSet.Len())

	if err := c.writeLeaseSet2Properties(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after properties: %d bytes", leaseSet.Len())
	Debug("LeaseSet2 bytes 391-401: %x", leaseSet.Bytes()[391:401])

	// Write encryption public keys (after properties, before leases)
	if err := c.writeLeaseSet2EncryptionKeys(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after enc keys: %d bytes", leaseSet.Len())
	Debug("LeaseSet2 bytes 401-436: %x", leaseSet.Bytes()[401:436])

	if err := c.writeLeaseSet2Leases(session, leaseSet, leaseCount); err != nil {
		return err
	}

	return c.writeLeaseSet2BlindingParams(session, leaseSet)
}

// writeLeaseSet2Header writes the destination to the LeaseSet stream.
// Note: The LeaseSet type byte is written to messageStream in msgCreateLeaseSet2,
// NOT here, per the I2CP CreateLeaseSet2Message format specification.
func (c *Client) writeLeaseSet2Header(session *Session, leaseSet *Stream, dest *Destination) error {
	dest.WriteToMessage(leaseSet)
	return nil
}

// writeLeaseSet2Timestamps writes the published and expires timestamps to the stream.
// Per LeaseSet2 format:
//
//	Published: 4 bytes, seconds since epoch
//	Expires: 2 bytes, offset in seconds from published time
func (c *Client) writeLeaseSet2Timestamps(leaseSet *Stream) error {
	publishedSeconds := uint32(c.router.date / 1000) // Convert ms to seconds
	leaseSet.WriteUint32(publishedSeconds)

	// Expires is an offset in seconds from the published time
	// 600 seconds = 10 minutes lease validity
	expiresOffset := uint16(600)
	leaseSet.WriteUint16(expiresOffset)
	return nil
}

// writeLeaseSet2Flags writes the flags field to the stream, including blinding flags if enabled.
func (c *Client) writeLeaseSet2Flags(session *Session, leaseSet *Stream) error {
	var flags uint16 = 0
	if session.IsBlindingEnabled() {
		flags |= session.BlindingFlags()
	}
	leaseSet.WriteUint16(flags)
	return nil
}

// writeLeaseSet2Properties writes the properties mapping to the stream, including blinding scheme if enabled.
func (c *Client) writeLeaseSet2Properties(session *Session, leaseSet *Stream) error {
	properties := make(map[string]string)
	if session.IsBlindingEnabled() {
		properties["blinding.scheme"] = fmt.Sprintf("%d", session.BlindingScheme())
		Debug("Added blinding scheme %d to LeaseSet2 properties", session.BlindingScheme())
	}
	if err := leaseSet.WriteMapping(properties); err != nil {
		Error("Failed to write properties to LeaseSet2: %v", err)
		return fmt.Errorf("failed to write properties: %w", err)
	}
	return nil
}

// writeLeaseSet2EncryptionKeys writes the encryption public keys to the LeaseSet2 stream.
// Per LeaseSet2 format: [numKeys:1][encType:2][pubKey:keyLen]...
// For X25519 (encType=4): pubKey is 32 bytes
// LeaseSet2 format: [numk:1][keytype:2][keylen:2][key:keylen]...
func (c *Client) writeLeaseSet2EncryptionKeys(session *Session, leaseSet *Stream) error {
	if session.encryptionKeyPair == nil {
		return fmt.Errorf("no encryption key pair available for LeaseSet2")
	}

	// Write number of encryption keys (1 for now - just X25519)
	leaseSet.WriteByte(1)

	// Write encryption key per LeaseSet2 spec:
	// [keytype:2][keylen:2][key:keylen]
	encType := uint16(X25519) // X25519 = 4
	keyLen := uint16(32)      // X25519 keys are 32 bytes

	leaseSet.WriteUint16(encType)
	leaseSet.WriteUint16(keyLen)

	pubKey := session.encryptionKeyPair.PublicKey()
	leaseSet.Write(pubKey[:])

	Debug("Wrote X25519 encryption public key to LeaseSet2 (type=%d, len=%d)", encType, keyLen)
	return nil
}

// writeLeaseSet2Leases writes the lease count and actual lease data from the session to the stream.
// Uses the leases received from RequestVariableLeaseSet.
// Writes in Lease2 format (40 bytes per lease) for LeaseSet2 compatibility.
func (c *Client) writeLeaseSet2Leases(session *Session, leaseSet *Stream, leaseCount int) error {
	leaseSet.WriteByte(uint8(leaseCount))

	session.mu.RLock()
	leases := session.leases
	session.mu.RUnlock()

	// Use actual leases if available, otherwise fall back to placeholder
	if len(leases) >= leaseCount {
		for i := 0; i < leaseCount; i++ {
			// Use WriteToLeaseSet2 for Lease2 format (40 bytes with 4-byte timestamp)
			if err := leases[i].WriteToLeaseSet2(leaseSet); err != nil {
				return fmt.Errorf("failed to write lease %d: %w", i, err)
			}
		}
		Debug("Wrote %d actual leases to LeaseSet2 (Lease2 format, 40 bytes each)", leaseCount)
	} else {
		// Fallback to placeholder data in Lease2 format (40 bytes per lease)
		Debug("Warning: No actual leases available, using placeholder data for %d leases", leaseCount)
		for i := 0; i < leaseCount; i++ {
			nullGateway := make([]byte, 32)
			leaseSet.Write(nullGateway)
			leaseSet.WriteUint32(uint32(i + 1))
			// End date in seconds (not milliseconds) for Lease2 format
			leaseEndDateSeconds := uint32(c.router.date/1000) + 300 // 5 minutes
			leaseSet.WriteUint32(leaseEndDateSeconds)
		}
	}
	return nil
}

// writeLeaseSet2BlindingParams writes blinding parameters to the stream if blinding is enabled.
func (c *Client) writeLeaseSet2BlindingParams(session *Session, leaseSet *Stream) error {
	if !session.IsBlindingEnabled() {
		return nil
	}

	blindingParams := session.BlindingParams()
	if len(blindingParams) > 0 {
		leaseSet.WriteUint16(uint16(len(blindingParams)))
		leaseSet.Write(blindingParams)
		Debug("Added %d bytes of blinding parameters to LeaseSet2", len(blindingParams))
	} else {
		leaseSet.WriteUint16(0)
		Debug("Blinding enabled but no parameters present, wrote zero-length")
	}
	return nil
}

// signAndSendLeaseSet2 signs the LeaseSet2 stream and sends the message to the router.
// Per I2CP CreateLeaseSet2Message format:
// [SessionID:2][LeaseSetType:1][LeaseSet2Content:var][Signature:64][NumPrivKeys:1][PrivKeyData...]
//
// Per LeaseSet2 spec, the signature covers [LeaseSetType:1][LeaseSet2Content:var]
// The type byte is NOT part of the LeaseSet2 data structure itself, but IS included in signature
func (c *Client) signAndSendLeaseSet2(session *Session, leaseSet *Stream, dest *Destination, queue bool) error {
	sgk := &dest.sgk

	// Create data to sign: [type:1][leaseSet content]
	// The type byte must be included in the signature per LeaseSet2 spec
	var leaseSetType uint8
	if session.IsBlindingEnabled() {
		leaseSetType = LEASESET_TYPE_ENCRYPTED
	} else {
		leaseSetType = LEASESET_TYPE_STANDARD
	}

	// Build the signable data: type byte + LeaseSet2 content
	dataToSign := NewStream(make([]byte, 0, leaseSet.Len()+1))
	dataToSign.WriteByte(leaseSetType)
	dataToSign.Write(leaseSet.Bytes())

	// Sign the combined data
	if err := sgk.ed25519KeyPair.SignStream(dataToSign); err != nil {
		Error("Failed to sign CreateLeaseSet2: %v", err)
		return err
	}

	// Get the signature from the end of dataToSign (SignStream appends it)
	signedData := dataToSign.Bytes()
	// The signature is the last 64 bytes (Ed25519 signature size)
	signature := signedData[len(signedData)-64:]

	// Write LeaseSet2 content (without type) + signature to message stream
	c.messageStream.Write(leaseSet.Bytes())
	c.messageStream.Write(signature)

	// Write private keys after the signed LeaseSet2
	// I2CP CreateLeaseSet2Message format: [numKeys:1][encType:2][keyLen:2][privKey:keyLen]...
	if session.encryptionKeyPair != nil {
		c.messageStream.WriteByte(1) // Number of private keys

		// Write per I2CP spec: [encType:2][keyLen:2][privKey:keyLen]
		encType := uint16(X25519) // X25519 = 4
		keyLen := uint16(32)      // X25519 private keys are 32 bytes

		c.messageStream.WriteUint16(encType)
		c.messageStream.WriteUint16(keyLen)

		privKey := session.encryptionKeyPair.PrivateKey()
		c.messageStream.Write(privKey[:])

		Debug("Wrote X25519 encryption private key to CreateLeaseSet2Message (type=%d, len=%d), total: %d bytes",
			encType, keyLen, c.messageStream.Len())
	} else {
		c.messageStream.WriteByte(0) // No private keys
	}

	if err := c.sendMessage(I2CP_MSG_CREATE_LEASE_SET2, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet2Message: %v", err)
		return fmt.Errorf("failed to send CreateLeaseSet2Message: %w", err)
	}
	return nil
}

// getAuthenticationMethod determines which authentication method is being used
// based on the client's configuration properties.
// Returns one of: AUTH_METHOD_NONE, AUTH_METHOD_USERNAME_PWD, or AUTH_METHOD_SSL_TLS
// Returns error code for unsupported authentication methods (AUTH_METHOD_PER_CLIENT_DH, AUTH_METHOD_PER_CLIENT_PSK)
func (c *Client) getAuthenticationMethod() uint8 {
	// Check for unsupported per-client authentication methods (3-4)
	// SPEC COMPLIANCE: I2CP § BlindingInfoMessage defines DH (3) and PSK (4) auth
	// These are not yet implemented in go-i2cp
	if c.properties["i2cp.auth.method"] == "3" {
		Warning("Per-client DH authentication (method 3) requested but not implemented")
		return AUTH_METHOD_PER_CLIENT_DH
	}
	if c.properties["i2cp.auth.method"] == "4" {
		Warning("Per-client PSK authentication (method 4) requested but not implemented")
		return AUTH_METHOD_PER_CLIENT_PSK
	}

	// Check TLS authentication first (method 2)
	if c.properties["i2cp.SSL"] == "true" {
		return AUTH_METHOD_SSL_TLS
	}

	// Check username/password authentication (method 1)
	if len(c.properties["i2cp.username"]) > 0 {
		return AUTH_METHOD_USERNAME_PWD
	}

	// No authentication (method 0)
	return AUTH_METHOD_NONE
}

// msgGetDate sends GetDateMessage (type 32) to initialize the I2CP protocol connection.
// This message includes the client version and authentication information.
// Per I2CP specification, authentication method is communicated via the properties mapping.
//
// Supported authentication methods:
//   - Method 0 (none): No authentication
//   - Method 1 (username/password): I2CP 0.9.11+ username/password auth
//   - Method 2 (TLS): I2CP 0.8.3+ TLS certificate auth
func (c *Client) msgGetDate(queue bool) {
	var err error
	Debug("Sending GetDateMessage")
	c.messageStream.Reset()
	c.messageStream.WriteLenPrefixedString(I2CP_CLIENT_VERSION)

	// Determine authentication method
	authMethod := c.getAuthenticationMethod()

	// SPEC COMPLIANCE: Validate authentication method is supported
	if authMethod >= AUTH_METHOD_PER_CLIENT_DH {
		Error("Authentication method %d (per-client DH/PSK) not yet implemented in go-i2cp", authMethod)
		Warning("Router requires unsupported authentication - connection will likely fail")
		Warning("Supported methods: 0 (none), 1 (username/password), 2 (TLS)")
		// Continue anyway to let router reject with proper error message
	}

	// Build authentication info mapping based on method
	switch authMethod {
	case AUTH_METHOD_USERNAME_PWD:
		// Method 1: Username/password authentication (I2CP 0.9.11+)
		authInfo := map[string]string{
			"i2cp.username": c.properties["i2cp.username"],
			"i2cp.password": c.properties["i2cp.password"],
		}
		c.messageStream.WriteMapping(authInfo)
		Debug("Using username/password authentication (method 1)")

	case AUTH_METHOD_SSL_TLS:
		// Method 2: TLS certificate authentication (I2CP 0.8.3+)
		// The TLS handshake has already occurred in Connect()
		// Just indicate the authentication method to the router
		authInfo := map[string]string{
			"i2cp.auth.method": "2", // TLS certificate authentication
		}
		c.messageStream.WriteMapping(authInfo)
		Debug("Using TLS certificate authentication (method 2)")

	case AUTH_METHOD_NONE:
		// Method 0: No authentication required
		// Send empty mapping (no authentication info)
		Debug("Using no authentication (method 0)")

	default:
		// Should never happen, but handle gracefully
		Warning("Unknown authentication method %d, using no authentication", authMethod)
	}

	if err = c.sendMessage(I2CP_MSG_GET_DATE, c.messageStream, queue); err != nil {
		Error("Error while sending GetDateMessage")
	}
}

func (c *Client) msgCreateSession(config *SessionConfig, queue bool) error {
	var err error
	Info(">>> SENDING CreateSessionMessage to router")

	// Track state - session pending
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		// Use 0 as placeholder until we get the real session ID
		c.stateTracker.SetState(0, SessionStatePending, "CreateSession being sent")
	}

	// Build the session config message first (this sets config.date)
	c.messageStream.Reset()
	config.writeToMessage(c.messageStream, c.crypto, c)

	// Dump CreateSession message for debugging
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		msgBytes := c.messageStream.Bytes()
		// Calculate component sizes from the message
		// Format: Destination(391) + Mapping(variable) + Date(8) + Signature(64 for Ed25519)
		destSize := 391 // Fixed size for Destination with certificate
		sigSize := 64   // Ed25519 signature size
		mappingSize := len(msgBytes) - destSize - 8 - sigSize
		if mappingSize < 0 {
			mappingSize = 0
		}
		c.protocolDebugger.DumpCreateSessionMessage(msgBytes, destSize, mappingSize, config.date, sigSize)
	}

	// SPEC COMPLIANCE: Validate session config date per I2CP § CreateSessionMessage
	// "If the Date in the Session Config is too far (more than +/- 30 seconds) from the
	// router's current time, the session will be rejected."
	c.routerTimeMu.RLock()
	routerTimeDelta := c.routerTimeDelta
	c.routerTimeMu.RUnlock()

	configDate := config.date // milliseconds since epoch (set by writeToMessage)
	localNow := uint64(time.Now().UnixMilli())
	routerNow := uint64(int64(localNow) + routerTimeDelta)

	// Calculate skew between config date and router time
	var skew int64
	if configDate > routerNow {
		skew = int64(configDate - routerNow)
	} else {
		skew = int64(routerNow - configDate)
	}

	// Warn if approaching 30-second limit (use 25s threshold to leave margin)
	if skew > 25000 {
		Warning("SessionConfig timestamp skew is %d ms (limit 30000 ms) - session may be rejected", skew)
		Warning("Local time: %d, Router time: %d, Config date: %d", localNow, routerNow, configDate)
		if skew > 30000 {
			return fmt.Errorf("SessionConfig date %d is %d ms from router time (max 30000 ms allowed)",
				configDate, skew)
		}
	}

	// Log detailed message info
	Info("CreateSession message: %d bytes, timestamp: %d (%v)",
		c.messageStream.Len(), config.date, time.UnixMilli(int64(config.date)).Format(time.RFC3339))

	if err = c.sendMessage(I2CP_MSG_CREATE_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending CreateSessionMessage.")
		return err
	}
	Info("<<< CreateSessionMessage sent successfully, awaiting SessionStatus response")
	Debug("<<< CreateSessionMessage sent successfully, awaiting SessionCreated response")
	return err
}

func (c *Client) msgDestLookup(hash []byte, queue bool) {
	Debug("Sending DestLookupMessage.")
	c.messageStream.Reset()
	c.messageStream.Write(hash)
	if err := c.sendMessage(I2CP_MSG_DEST_LOOKUP, c.messageStream, queue); err != nil {
		Error("Error while sending DestLookupMessage.")
	}
}

func (c *Client) msgHostLookup(sess *Session, requestId, timeout uint32, typ uint8, data []byte, queue bool) error {
	var sessionId uint16
	Debug("Sending HostLookupMessage.")
	c.messageStream.Reset()

	// CRITICAL FIX: Handle session ID 0xFFFF special case per I2CP spec
	// Per I2CP § Session ID: "Session ID 0xffff is used to indicate 'no session',
	// for example for hostname lookups."
	if sess == nil {
		sessionId = I2CP_SESSION_ID_NONE
		Debug("Using I2CP_SESSION_ID_NONE (0xFFFF) for lookup without session")
	} else {
		sessionId = sess.id
		// Validate session ID is not the reserved value
		if sessionId == I2CP_SESSION_ID_NONE {
			return fmt.Errorf("session ID cannot be 0xFFFF (reserved for no-session operations)")
		}
	}
	c.messageStream.WriteUint16(sessionId)
	c.messageStream.WriteUint32(requestId)
	c.messageStream.WriteUint32(timeout)
	c.messageStream.WriteByte(typ)
	if typ == HOST_LOOKUP_TYPE_HASH {
		c.messageStream.Write(data)
	}
	if err := c.sendMessage(I2CP_MSG_HOST_LOOKUP, c.messageStream, queue); err != nil {
		Error("Error while sending HostLookupMessage: %v", err)
		return fmt.Errorf("failed to send HostLookupMessage: %w", err)
	}
	return nil
}

// msgReconfigureSession sends ReconfigureSessionMessage (type 2) for dynamic session updates
// per I2CP specification section 7.1 - implements runtime tunnel and crypto parameter changes
func (c *Client) msgReconfigureSession(session *Session, properties map[string]string, queue bool) error {
	Debug("Sending ReconfigureSessionMessage for session %d with %d properties", session.id, len(properties))

	c.messageStream.Reset()
	c.messageStream.WriteUint16(session.id)

	// Write properties mapping to message
	if err := c.messageStream.WriteMapping(properties); err != nil {
		Error("Failed to write properties mapping to ReconfigureSessionMessage: %v", err)
		return fmt.Errorf("failed to write properties mapping: %w", err)
	}

	if err := c.sendMessage(I2CP_MSG_RECONFIGURE_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending ReconfigureSessionMessage: %v", err)
		return fmt.Errorf("failed to send ReconfigureSessionMessage: %w", err)
	}

	Debug("Successfully sent ReconfigureSessionMessage for session %d", session.id)
	return nil
}

// BlindingInfo represents the parameters for a BlindingInfoMessage.
// This structure encapsulates all the fields needed to advise the router
// about a blinded destination per I2CP specification 0.9.43+.
type BlindingInfo struct {
	// EndpointType specifies how the destination is identified (0-3)
	// Use BLINDING_ENDPOINT_* constants
	EndpointType uint8

	// Endpoint is the destination identifier, format depends on EndpointType:
	//   Type 0: 32-byte hash
	//   Type 1: hostname string (will be length-prefixed)
	//   Type 2: full Destination bytes
	//   Type 3: 2-byte sig type + SigningPublicKey bytes
	Endpoint []byte

	// BlindedSigType is the signature type used for blinding (2 bytes)
	BlindedSigType uint16

	// Expiration is the expiration time in seconds since epoch
	Expiration uint32

	// PerClientAuth indicates if per-client authentication is required
	// When true, DecryptionKey must be provided
	PerClientAuth bool

	// AuthScheme specifies the authentication scheme when PerClientAuth is true
	// Use BLINDING_AUTH_SCHEME_DH (0) or BLINDING_AUTH_SCHEME_PSK (1)
	AuthScheme uint8

	// DecryptionKey is the 32-byte ECIES_X25519 private key (little-endian)
	// Only required when PerClientAuth is true
	DecryptionKey []byte

	// LookupPassword is the optional password for encrypted LeaseSet lookup
	// Only include if the destination requires a secret
	LookupPassword string
}

// msgBlindingInfo sends BlindingInfoMessage (type 42) to advise the router about a blinded destination.
// per I2CP specification 0.9.43+ - used before messaging blinded destinations (b33 addresses)
//
// The router does not send a reply to this message.
//
// Per SPEC.md § BlindingInfoMessage:
// "Before a client sends a message to a blinded destination, it must either lookup
// the 'b33' in a Host Lookup message, or send a Blinding Info message."
//
// Parameters:
//   - sess: The session to associate this blinding info with
//   - info: BlindingInfo struct containing all blinding parameters
//   - queue: If true, queue the message; if false, send immediately
//
// Returns error if validation fails or message cannot be sent.
func (c *Client) msgBlindingInfo(sess *Session, info *BlindingInfo, queue bool) error {
	if err := c.validateBlindingInfo(sess, info); err != nil {
		return err
	}

	Debug("Sending BlindingInfoMessage for session %d, endpoint type %d", sess.id, info.EndpointType)

	c.messageStream.Reset()

	// Write Session ID (2 bytes)
	c.messageStream.WriteUint16(sess.id)

	// Build and write flags byte
	flags := c.buildBlindingFlags(info)
	c.messageStream.WriteByte(flags)

	// Write endpoint type (1 byte)
	c.messageStream.WriteByte(info.EndpointType)

	// Write blinded signature type (2 bytes)
	c.messageStream.WriteUint16(info.BlindedSigType)

	// Write expiration (4 bytes, seconds since epoch)
	c.messageStream.WriteUint32(info.Expiration)

	// Write endpoint data based on type
	if err := c.writeBlindingEndpoint(info); err != nil {
		return fmt.Errorf("failed to write endpoint: %w", err)
	}

	// Write optional decryption key (only if per-client auth)
	if info.PerClientAuth {
		c.messageStream.Write(info.DecryptionKey)
	}

	// Write optional lookup password (only if provided)
	if info.LookupPassword != "" {
		if err := c.messageStream.WriteLenPrefixedString(info.LookupPassword); err != nil {
			return fmt.Errorf("failed to write lookup password: %w", err)
		}
	}

	if err := c.sendMessage(I2CP_MSG_BLINDING_INFO, c.messageStream, queue); err != nil {
		Error("Error while sending BlindingInfoMessage: %v", err)
		return fmt.Errorf("failed to send BlindingInfoMessage: %w", err)
	}

	Debug("Successfully sent BlindingInfoMessage for session %d", sess.id)
	return nil
}

// validateBlindingInfo validates the BlindingInfo parameters before sending.
func (c *Client) validateBlindingInfo(sess *Session, info *BlindingInfo) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if info == nil {
		return fmt.Errorf("blinding info cannot be nil")
	}

	// Validate endpoint type
	if info.EndpointType > BLINDING_ENDPOINT_SIGKEY {
		return fmt.Errorf("invalid endpoint type %d (must be 0-3)", info.EndpointType)
	}

	// Validate endpoint data based on type
	switch info.EndpointType {
	case BLINDING_ENDPOINT_HASH:
		if len(info.Endpoint) != 32 {
			return fmt.Errorf("hash endpoint must be exactly 32 bytes, got %d", len(info.Endpoint))
		}
	case BLINDING_ENDPOINT_HOSTNAME:
		if len(info.Endpoint) == 0 {
			return fmt.Errorf("hostname endpoint cannot be empty")
		}
		if len(info.Endpoint) > 255 {
			return fmt.Errorf("hostname too long: %d bytes (max 255)", len(info.Endpoint))
		}
	case BLINDING_ENDPOINT_DESTINATION:
		if len(info.Endpoint) < 387 { // Minimum destination size
			return fmt.Errorf("destination endpoint too short: %d bytes", len(info.Endpoint))
		}
	case BLINDING_ENDPOINT_SIGKEY:
		if len(info.Endpoint) < 3 { // At minimum: 2-byte sig type + 1 byte key
			return fmt.Errorf("sigkey endpoint too short: %d bytes", len(info.Endpoint))
		}
	}

	// Validate auth scheme
	if info.AuthScheme > BLINDING_AUTH_SCHEME_PSK {
		return fmt.Errorf("invalid auth scheme %d (must be 0 or 1)", info.AuthScheme)
	}

	// Validate decryption key when per-client auth is enabled
	if info.PerClientAuth {
		if len(info.DecryptionKey) != 32 {
			return fmt.Errorf("decryption key must be exactly 32 bytes for per-client auth, got %d", len(info.DecryptionKey))
		}
	}

	return nil
}

// buildBlindingFlags constructs the flags byte for BlindingInfoMessage.
// Bit layout: 76543210
//   - Bit 0: 0=everybody, 1=per-client
//   - Bits 3-1: Auth scheme (if bit 0 is 1)
//   - Bit 4: 1=secret required
//   - Bits 7-5: Reserved (0)
func (c *Client) buildBlindingFlags(info *BlindingInfo) uint8 {
	var flags uint8 = 0

	if info.PerClientAuth {
		flags |= BLINDING_FLAG_PER_CLIENT
		// Set auth scheme in bits 3-1 (shift left by 1)
		flags |= (info.AuthScheme & 0x07) << 1
	}

	if info.LookupPassword != "" {
		flags |= BLINDING_FLAG_SECRET
	}

	return flags
}

// writeBlindingEndpoint writes the endpoint data to the message stream.
func (c *Client) writeBlindingEndpoint(info *BlindingInfo) error {
	switch info.EndpointType {
	case BLINDING_ENDPOINT_HASH:
		// Type 0: 32-byte hash
		c.messageStream.Write(info.Endpoint)

	case BLINDING_ENDPOINT_HOSTNAME:
		// Type 1: length-prefixed hostname string
		if err := c.messageStream.WriteLenPrefixedString(string(info.Endpoint)); err != nil {
			return err
		}

	case BLINDING_ENDPOINT_DESTINATION:
		// Type 2: full destination bytes
		c.messageStream.Write(info.Endpoint)

	case BLINDING_ENDPOINT_SIGKEY:
		// Type 3: sig type (2 bytes) + SigningPublicKey
		c.messageStream.Write(info.Endpoint)

	default:
		return fmt.Errorf("unknown endpoint type: %d", info.EndpointType)
	}

	return nil
}

// SendBlindingInfo is a convenience method on Session to send blinding info for a destination.
// This is the primary API for applications to use when messaging blinded destinations.
//
// Example usage:
//
//	info := &go_i2cp.BlindingInfo{
//	    EndpointType:   go_i2cp.BLINDING_ENDPOINT_HASH,
//	    Endpoint:       destHash[:],
//	    BlindedSigType: 11, // Ed25519-SHA512
//	    Expiration:     uint32(time.Now().Add(24*time.Hour).Unix()),
//	    LookupPassword: "optional-secret",
//	}
//	err := session.SendBlindingInfo(info)
func (session *Session) SendBlindingInfo(info *BlindingInfo) error {
	if err := session.ensureInitialized(); err != nil {
		return err
	}
	return session.client.msgBlindingInfo(session, info, false)
}

func (c *Client) msgGetBandwidthLimits(queue bool) {
	Debug("Sending GetBandwidthLimitsMessage.")
	c.messageStream.Reset()
	if err := c.sendMessage(I2CP_MSG_GET_BANDWIDTH_LIMITS, c.messageStream, queue); err != nil {
		Error("Error while sending GetBandwidthLimitsMessage")
	}
}

func (c *Client) msgDestroySession(sess *Session, queue bool) error {
	// I2CP SPEC COMPLIANCE: Handle both spec-compliant and Java I2P router behaviors
	// Per I2CP spec § DestroySessionMessage: "The router should respond with a SessionStatusMessage (Destroyed)"
	// Per I2CP 0.9.67 § DestroySessionMessage Notes (Java I2P deviation):
	// "Through API 0.9.66, the Java I2P router and client libraries deviate substantially.
	// The router never sends SessionStatus(Destroyed). If no sessions are left, it sends
	// DisconnectMessage. If there are subsessions or primary remains, it does not reply."

	wasPrimary := sess.isPrimary
	cascadeDestroySubsessions(c, sess)

	if err := sendDestroySessionMessage(c, sess, queue); err != nil {
		return err
	}

	waitForDestroyConfirmation(sess, wasPrimary)

	// CRITICAL FIX: Per I2CP § DestroySessionMessage Notes (0.9.67):
	// "Destroying the primary session will, however, destroy all subsessions and stop the I2CP connection."
	if wasPrimary {
		Debug("Primary session destroyed - closing I2CP connection per spec requirement")
		return c.Close()
	}

	return nil
}

// cascadeDestroySubsessions destroys all subsessions when a primary session is destroyed.
// Per I2CP § Multisession Notes, destroying the primary cascades to all subsessions.
func cascadeDestroySubsessions(c *Client, sess *Session) {
	// COMPLIANCE FIX: Cascade destroy subsessions when primary is destroyed (I2CP § Multisession Notes)
	c.lock.Lock()
	defer c.lock.Unlock()

	if !sess.isPrimary {
		return
	}

	Debug("Destroying primary session %d - cascading to all subsessions per I2CP spec", sess.id)
	// Destroy all subsessions first
	for id, s := range c.sessions {
		if id != sess.id && !s.isPrimary {
			Debug("Auto-destroying subsession %d (primary %d being destroyed)", id, sess.id)
			// Recursive call for subsessions
			c.lock.Unlock()
			c.msgDestroySession(s, false)
			c.lock.Lock()
			delete(c.sessions, id)
		}
	}
	c.primarySessionID = nil
}

// sendDestroySessionMessage sends the DestroySessionMessage to the router.
// Returns an error if the message cannot be sent.
func sendDestroySessionMessage(c *Client, sess *Session, queue bool) error {
	Debug("Sending DestroySessionMessage for session %d (primary: %v)", sess.id, sess.isPrimary)
	c.messageStream.Reset()
	c.messageStream.WriteUint16(sess.id)

	if err := c.sendMessage(I2CP_MSG_DESTROY_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending DestroySessionMessage: %v", err)
		return err
	}
	return nil
}

// waitForDestroyConfirmation waits for session destruction confirmation or timeout.
// Handles both spec-compliant routers (send SessionStatus(Destroyed)) and Java I2P (may not respond).
func waitForDestroyConfirmation(sess *Session, wasPrimary bool) {
	// SPEC COMPLIANCE: Wait for SessionStatus(Destroyed) OR timeout for non-compliant routers
	// Dual-path handling supports both spec-compliant routers and Java I2P's deviant behavior
	// Per I2CP § DestroySessionMessage: Spec-compliant routers send SessionStatus(Destroyed)
	// Per Java I2P (API ≤0.9.66): Router never sends SessionStatus(Destroyed), may send DisconnectMessage
	// Timeout set to 5 seconds to accommodate network latency and Java I2P's DisconnectMessage timing
	if sess.destroyConfirmed == nil {
		return
	}

	select {
	case <-sess.destroyConfirmed:
		Debug("Session %d destruction confirmed via SessionStatus(Destroyed)", sess.id)
	case <-time.After(5 * time.Second):
		// Timeout - router did not send SessionStatus(Destroyed) (expected for Java I2P ≤0.9.66)
		if wasPrimary {
			Debug("DestroySession timeout for primary session %d - router may send DisconnectMessage (Java I2P behavior)", sess.id)
		} else {
			Debug("DestroySession timeout for subsession %d - router did not respond (expected for Java I2P)", sess.id)
		}
	}
}

func (c *Client) msgSendMessage(sess *Session, dest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32, queue bool) error {
	Debug("Sending SendMessageMessage")
	out := &bytes.Buffer{}
	c.messageStream.Reset()
	c.messageStream.WriteUint16(sess.id)
	dest.WriteToMessage(c.messageStream)
	compress := gzip.NewWriter(out)
	compress.Write(payload.Bytes())
	compress.Close()
	header := out.Bytes()[:10]
	binary.LittleEndian.PutUint16(header[4:6], srcPort)
	binary.LittleEndian.PutUint16(header[6:8], destPort)
	header[9] = protocol
	c.messageStream.WriteUint32(uint32(out.Len()))
	c.messageStream.Write(out.Bytes())
	c.messageStream.WriteUint32(nonce)

	// Validate total message size per I2CP specification (max 64KB)
	totalMessageSize := c.messageStream.Len()
	if totalMessageSize > I2CP_MAX_MESSAGE_PAYLOAD_SIZE {
		return fmt.Errorf("total I2CP message size %d exceeds maximum %d bytes (compressed payload size: %d bytes)",
			totalMessageSize, I2CP_MAX_MESSAGE_PAYLOAD_SIZE, out.Len())
	}
	// MINOR FIX: Warn if exceeding conservative size - spec says "about 64KB" (router-dependent)
	if totalMessageSize > I2CP_SAFE_MESSAGE_SIZE {
		Warning("Message size %d exceeds conservative limit %d bytes (max %d), some routers may reject",
			totalMessageSize, I2CP_SAFE_MESSAGE_SIZE, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
	}

	if err := c.sendMessage(I2CP_MSG_SEND_MESSAGE, c.messageStream, queue); err != nil {
		Error("Error while sending SendMessageMessage: %v", err)
		return fmt.Errorf("failed to send SendMessageMessage: %w", err)
	}
	return nil
}

// msgSendMessageExpires sends SendMessageExpiresMessage (type 36) for enhanced delivery control
// per I2CP specification 0.7.1+ - implements expiring message delivery with flags and timeout
func (c *Client) msgSendMessageExpires(sess *Session, dest *Destination, protocol uint8, srcPort, destPort uint16, payload *Stream, nonce uint32, flags uint16, expirationSeconds uint64, queue bool) error {
	Debug("Sending SendMessageExpiresMessage")

	if err := c.validateSendMessageFlags(flags); err != nil {
		return err
	}

	compressedPayload, err := c.compressPayload(payload, protocol, srcPort, destPort)
	if err != nil {
		return err
	}

	c.buildSendMessageStream(sess, dest, compressedPayload, nonce, flags, expirationSeconds)

	if err := c.validateMessageSize(compressedPayload.Len()); err != nil {
		return err
	}

	if err := c.sendMessage(I2CP_MSG_SEND_MESSAGE_EXPIRES, c.messageStream, queue); err != nil {
		Error("Error while sending SendMessageExpiresMessage: %v", err)
		return fmt.Errorf("failed to send SendMessageExpiresMessage: %w", err)
	}
	return nil
}

// validateSendMessageFlags validates SendMessageExpires flags per I2CP specification.
func (c *Client) validateSendMessageFlags(flags uint16) error {
	const SEND_MSG_FLAGS_RESERVED_MASK uint16 = 0xF800
	if flags&SEND_MSG_FLAGS_RESERVED_MASK != 0 {
		return fmt.Errorf("invalid SendMessageExpires flags: reserved bits set (0x%04x)", flags)
	}

	const SEND_MSG_FLAGS_RELIABILITY_MASK uint16 = 0x0600
	if flags&SEND_MSG_FLAGS_RELIABILITY_MASK != 0 {
		return fmt.Errorf("deprecated reliability override flags (bits 10-9) no longer supported per I2CP spec")
	}

	tagThreshold := (flags >> 4) & 0x0F
	if tagThreshold > 15 {
		return fmt.Errorf("invalid tag threshold: %d (max 15)", tagThreshold)
	}

	tagCount := flags & 0x0F
	if tagCount > 15 {
		return fmt.Errorf("invalid tag count: %d (max 15)", tagCount)
	}

	noLeaseSet := (flags & 0x0100) != 0
	Debug("SendMessageExpires flags: noLeaseSet=%v, tagThreshold=%d, tagCount=%d",
		noLeaseSet, tagThreshold, tagCount)

	return nil
}

// compressPayload compresses the payload and adds protocol header information.
func (c *Client) compressPayload(payload *Stream, protocol uint8, srcPort, destPort uint16) (*bytes.Buffer, error) {
	out := &bytes.Buffer{}
	compress := gzip.NewWriter(out)
	compress.Write(payload.Bytes())
	compress.Close()
	header := out.Bytes()[:10]
	binary.LittleEndian.PutUint16(header[4:6], srcPort)
	binary.LittleEndian.PutUint16(header[6:8], destPort)
	header[9] = protocol
	return out, nil
}

// buildSendMessageStream constructs the message stream for SendMessageExpires.
func (c *Client) buildSendMessageStream(sess *Session, dest *Destination, compressedPayload *bytes.Buffer, nonce uint32, flags uint16, expirationSeconds uint64) {
	c.messageStream.Reset()
	c.messageStream.WriteUint16(sess.id)
	dest.WriteToMessage(c.messageStream)
	c.messageStream.WriteUint32(uint32(compressedPayload.Len()))
	c.messageStream.Write(compressedPayload.Bytes())
	c.messageStream.WriteUint32(nonce)
	c.messageStream.WriteUint16(flags)
	c.messageStream.WriteUint64(expirationSeconds)
}

// validateMessageSize validates the total message size against I2CP limits.
func (c *Client) validateMessageSize(compressedSize int) error {
	totalMessageSize := c.messageStream.Len()
	if totalMessageSize > I2CP_MAX_MESSAGE_PAYLOAD_SIZE {
		return fmt.Errorf("total I2CP message size %d exceeds maximum %d bytes (compressed payload size: %d bytes)",
			totalMessageSize, I2CP_MAX_MESSAGE_PAYLOAD_SIZE, compressedSize)
	}
	if totalMessageSize > I2CP_SAFE_MESSAGE_SIZE {
		Warning("SendMessageExpires size %d exceeds conservative limit %d bytes (max %d), some routers may reject",
			totalMessageSize, I2CP_SAFE_MESSAGE_SIZE, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
	}
	return nil
}

// Connect establishes a connection to the I2P router with context support.
// The context can be used to cancel the connection attempt or set a timeout.
// Implements proper error path cleanup with defer pattern per PLAN.md section 1.3.
// Supports TLS connections per I2CP 0.8.3+ specification (authentication method 2).
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	err := client.Connect(ctx)
func (c *Client) Connect(ctx context.Context) error {
	if err := c.validateConnectionPreconditions(ctx); err != nil {
		return err
	}

	Info("Client connecting to i2cp at %s:%s", c.properties["i2cp.tcp.host"], c.properties["i2cp.tcp.port"])

	if err := c.establishConnection(ctx); err != nil {
		return err
	}

	c.updateConnectionMetrics()
	return nil
}

// validateConnectionPreconditions checks if client is initialized and context is valid.
func (c *Client) validateConnectionPreconditions(ctx context.Context) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before connect: %w", err)
	}

	return nil
}

// establishConnection sets up TLS, connects TCP, and performs protocol handshake.
func (c *Client) establishConnection(ctx context.Context) error {
	if err := c.setupTLSIfEnabled(); err != nil {
		return err
	}

	if err := c.connectTCP(); err != nil {
		return err
	}

	success := false
	defer func() {
		if !success {
			Debug("Connect failed - cleaning up TCP connection")
			c.tcp.Disconnect()
			c.connected = false
		}
	}()

	if err := c.performProtocolHandshake(ctx); err != nil {
		return err
	}

	c.connected = true
	success = true

	// Invoke OnConnect callback after successful handshake
	if c.callbacks != nil && c.callbacks.OnConnect != nil {
		c.callbacks.OnConnect(c)
	}

	return nil
}

// connectTCP establishes the TCP/TLS connection to the router.
func (c *Client) connectTCP() error {
	err := c.tcp.Connect()
	if err != nil {
		c.trackError("network")
		return fmt.Errorf("failed to connect TCP: %w", err)
	}
	return nil
}

// updateConnectionMetrics updates metrics to reflect connected state.
func (c *Client) updateConnectionMetrics() {
	if c.metrics != nil {
		c.metrics.SetConnectionState("connected")
	}
}

// setupTLSIfEnabled configures TLS for the TCP connection if enabled in client properties.
// It reads TLS configuration from client properties and applies them to the TCP layer.
func (c *Client) setupTLSIfEnabled() error {
	if c.properties["i2cp.SSL"] != "true" {
		return nil
	}

	certFile := c.properties["i2cp.SSL.certFile"]
	keyFile := c.properties["i2cp.SSL.keyFile"]
	caFile := c.properties["i2cp.SSL.caFile"]
	insecure := c.properties["i2cp.SSL.insecure"] == "true"

	Debug("Configuring TLS: certFile=%s, keyFile=%s, caFile=%s, insecure=%v",
		certFile, keyFile, caFile, insecure)

	err := c.tcp.SetupTLS(certFile, keyFile, caFile, insecure)
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	Info("TLS configured successfully")
	return nil
}

// performProtocolHandshake executes the I2CP protocol initialization sequence.
// It sends the protocol init byte, GetDate message, and waits for SetDate response.
func (c *Client) performProtocolHandshake(ctx context.Context) error {
	// Check context after TCP connect
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled after TCP connect: %w", err)
	}

	// Send protocol initialization byte
	if err := c.sendProtocolInit(); err != nil {
		return err
	}

	Debug("Sending protocol byte message")

	// Send GetDate message
	c.msgGetDate(false)

	// Receive SetDate response with context checking
	return c.receiveSetDateWithContext(ctx)
}

// sendProtocolInit sends the I2CP protocol initialization byte to the router.
// It uses circuit breaker if available to protect against connection issues.
func (c *Client) sendProtocolInit() error {
	c.outputStream.Reset()
	c.outputStream.WriteByte(I2CP_PROTOCOL_INIT)

	var err error
	if c.circuitBreaker != nil {
		err = c.circuitBreaker.Execute(func() error {
			_, sendErr := c.tcp.Send(c.outputStream)
			return sendErr
		})
	} else {
		_, err = c.tcp.Send(c.outputStream)
	}

	if err != nil {
		return fmt.Errorf("failed to send protocol init: %w", err)
	}

	return nil
}

// receiveSetDateWithContext receives the SetDate response message with context cancellation support.
// It runs the receive operation in a goroutine to allow context cancellation.
func (c *Client) receiveSetDateWithContext(ctx context.Context) error {
	type result struct {
		err error
	}
	resultChan := make(chan result, 1)

	go func() {
		err := c.recvMessage(I2CP_MSG_SET_DATE, c.receiveStream, true)
		resultChan <- result{err: err}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled during SetDate receive: %w", ctx.Err())
	case res := <-resultChan:
		if res.err != nil {
			return fmt.Errorf("failed to receive SetDate: %w", res.err)
		}
	}

	return nil
}

// CreateSession creates a new I2P session with context support.
// The context can be used to cancel the session creation or set a timeout.
//
// IMPORTANT: You must run ProcessIO() in a background goroutine BEFORE calling CreateSession.
// The session creation response (SessionStatusMessage) will be received and processed by ProcessIO.
// The session status callback will be invoked when the router confirms session creation.
//
// Example:
//
//	// Start ProcessIO in background
//	go func() {
//	    for {
//	        if err := client.ProcessIO(ctx); err != nil {
//	            // Handle error
//	            return
//	        }
//	        time.Sleep(100 * time.Millisecond)
//	    }
//	}()
//
//	// Create session
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	err := client.CreateSession(ctx, session)
//
// The session will be confirmed via the OnStatus callback in SessionCallbacks.
// validateAndConfigureSubsession validates subsession requirements and inherits configuration from the primary session.
// It checks router version compatibility and copies all configuration properties from the primary session.
// Returns error if subsession is invalid or router version is insufficient.
func (c *Client) validateAndConfigureSubsession(sess *Session) error {
	primary := sess.PrimarySession()
	if primary == nil {
		return fmt.Errorf("subsession requires a primary session reference")
	}

	// Check router version supports multi-session (I2CP 0.9.21+)
	if c.router.version.compare(Version{major: 0, minor: 9, micro: 21, qualifier: 0}) < 0 {
		return fmt.Errorf("router version %v does not support multi-session (requires >= 0.9.21)", c.router.version)
	}

	// Inherit all configuration from primary session
	// Per Java I2P reference: ClientMessageEventListener.java:280-388
	// "all the primary options, then the overrides from the alias"
	if primary.config != nil {
		for i := SessionConfigProperty(0); i < NR_OF_SESSION_CONFIG_PROPERTIES; i++ {
			value := primary.config.GetProperty(i)
			if value != "" {
				sess.config.SetProperty(i, value)
			}
		}
		Debug("Subsession inherited configuration from primary session %d", primary.ID())
	}

	return nil
}

// disableSubsessionTunnels overrides tunnel settings for subsessions to prevent tunnel creation.
// Per I2CP 0.9.21+ spec, subsessions share the primary session's tunnels and do not create their own.
func disableSubsessionTunnels(sess *Session) {
	sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "0")
	sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "0")
	Debug("Subsession tunnel creation disabled (sharing primary's tunnels)")
}

// configureFastReceiveMode enables or disables fast receive mode based on router version.
// Modern routers (I2CP 0.9.4+) send PayloadMessage (type 31) instead of deprecated
// ReceiveMessageBegin/End (types 6/7) messages.
func (c *Client) configureFastReceiveMode(sess *Session) {
	if c.router.version.compare(Version{major: 0, minor: 9, micro: 4, qualifier: 0}) >= 0 {
		sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		Debug("Router %v supports fastReceive mode", c.router.version)
	} else {
		// Legacy router - do not set fastReceive, expecting ReceiveMessageBegin/End
		Warning("Router version %v does not support fastReceive mode (requires >= 0.9.4)", c.router.version)
	}
}

// CreateSession creates a new I2CP session with the router.
// This initiates session establishment which completes asynchronously via ProcessIO.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sess: Session configuration and callbacks
//
// Returns error if validation fails or message cannot be sent.
// Success is confirmed via OnStatus callback with I2CP_SESSION_STATUS_CREATED.
//
// I2CP Spec: CreateSessionMessage (type 1), I2CP 0.9.21+ for multi-session support
func (c *Client) CreateSession(ctx context.Context, sess *Session) error {
	if err := c.validateSessionCreationPrerequisites(ctx, sess); err != nil {
		return err
	}

	if err := c.configureSessionProperties(sess); err != nil {
		return err
	}

	if err := c.sendSessionCreationRequest(sess); err != nil {
		return err
	}

	return nil
}

// validateSessionCreationPrerequisites checks all preconditions required to create a session.
// Returns an error if client is not initialized, session is nil, context is cancelled,
// or maximum sessions limit is reached.
func (c *Client) validateSessionCreationPrerequisites(ctx context.Context, sess *Session) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	if sess == nil {
		return fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before session creation: %w", err)
	}

	if c.n_sessions == I2CP_MAX_SESSIONS_PER_CLIENT {
		Warning("Maximum number of session per client connection reached.")
		return ErrMaxSessionsReached
	}

	return nil
}

// configureSessionProperties applies session configuration based on type and router capabilities.
// Handles subsession configuration, fast receive mode, and message reliability settings.
func (c *Client) configureSessionProperties(sess *Session) error {
	if !sess.IsPrimary() {
		if err := c.validateAndConfigureSubsession(sess); err != nil {
			return err
		}
		disableSubsessionTunnels(sess)
	}

	c.configureFastReceiveMode(sess)
	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	return nil
}

// sendSessionCreationRequest sends the CreateSession message to the router and updates metrics.
// The session status response will be processed asynchronously by ProcessIO.
func (c *Client) sendSessionCreationRequest(sess *Session) error {
	if err := c.msgCreateSession(sess.config, false); err != nil {
		return fmt.Errorf("failed to send CreateSession message: %w", err)
	}

	c.currentSession = sess

	Debug("CreateSession message sent, waiting for SessionCreated response...")
	Debug("IMPORTANT: Ensure ProcessIO() is running in background to receive response")

	if c.metrics != nil {
		c.lock.Lock()
		c.metrics.SetActiveSessions(len(c.sessions))
		c.lock.Unlock()
	}

	return nil
}

// ProcessIO processes pending I/O operations with context support.
// This method processes the output queue and receives messages from the router.
// It respects context cancellation and shutdown signals.
//
// Example:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	err := client.ProcessIO(ctx)
func (c *Client) ProcessIO(ctx context.Context) error {
	if err := c.validateProcessIOContext(ctx); err != nil {
		return err
	}

	if err := c.processOutputQueue(ctx); err != nil {
		return err
	}

	return c.processIncomingMessages(ctx)
}

// validateProcessIOContext validates the client state and context before processing IO.
func (c *Client) validateProcessIOContext(ctx context.Context) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before ProcessIO: %w", err)
	}

	select {
	case <-c.shutdown:
		return ErrClientClosed
	default:
		return nil
	}
}

// processOutputQueue sends all queued messages to the router.
func (c *Client) processOutputQueue(ctx context.Context) error {
	c.lock.Lock()
	defer func() {
		c.outputQueue = make([]*Stream, 0)
		c.lock.Unlock()
	}()

	for _, stream := range c.outputQueue {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled during output queue processing: %w", err)
		}

		Debug("Sending %d bytes message", stream.Len())

		ret, sendErr := c.sendQueuedMessage(stream)
		if ret < 0 {
			return fmt.Errorf("failed to send queued message: %w", sendErr)
		}
		if ret == 0 {
			break
		}
	}

	return nil
}

// sendQueuedMessage sends a single message using the circuit breaker if available.
func (c *Client) sendQueuedMessage(stream *Stream) (int, error) {
	var ret int
	var sendErr error

	if c.circuitBreaker != nil {
		sendErr = c.circuitBreaker.Execute(func() error {
			var err error
			ret, err = c.tcp.Send(stream)
			return err
		})
	} else {
		ret, sendErr = c.tcp.Send(stream)
	}

	return ret, sendErr
}

// checkContextCancellation verifies if the context has been cancelled during message processing.
// Returns an error if the context is cancelled, nil otherwise.
func (c *Client) checkContextCancellation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled during message receive: %w", err)
	}
	return nil
}

// checkShutdownSignal verifies if the client shutdown signal has been triggered.
// Returns ErrClientClosed if shutdown is in progress, nil otherwise.
func (c *Client) checkShutdownSignal() error {
	select {
	case <-c.shutdown:
		return ErrClientClosed
	default:
		return nil
	}
}

// processIncomingMessages receives and processes all available messages from the router.
func (c *Client) processIncomingMessages(ctx context.Context) error {
	var err error
	for c.tcp.CanRead() {
		if err = c.checkContextCancellation(ctx); err != nil {
			return err
		}

		if err = c.checkShutdownSignal(); err != nil {
			return err
		}

		Debug("ProcessIO: Waiting for message from router...")
		if err = c.recvMessage(I2CP_MSG_ANY, c.receiveStream, true); err != nil {
			return fmt.Errorf("failed to receive message: %w", err)
		}
	}

	return err
}

// DestinationLookup performs a destination lookup with context support.
// The context can be used to cancel the lookup or set a timeout.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	requestId, err := client.DestinationLookup(ctx, session, "example.i2p")
//
// validateLookupParameters validates the session, address, and context for a destination lookup.
// Returns error if any parameter is invalid or context is cancelled.
func validateLookupParameters(ctx context.Context, session *Session, address string) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}
	if address == "" {
		return fmt.Errorf("address cannot be empty: %w", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before lookup: %w", err)
	}
	return nil
}

// decodeB32Address attempts to decode a b32 address and returns the hash bytes.
// Returns nil stream if address is not b32 format or decoding fails.
func decodeB32Address(address string) (*Stream, error) {
	b32Len := 56 + 8 // base32-encoded 32-byte hash + ".b32.i2p"

	if len(address) != b32Len {
		return nil, nil // Not a b32 address
	}

	Debug("Lookup of b32 address detected, decode and use hash for faster lookup.")
	host := address[:strings.Index(address, ".")]

	decodedBytes, err := base32.DecodeString(host)
	if err != nil || len(decodedBytes) == 0 {
		Warning("Failed to decode hash of address '%s'", address)
		return nil, fmt.Errorf("failed to decode b32 address: %w", err)
	}

	return NewStream(decodedBytes), nil
}

// registerLookupRequest registers a new lookup request in a thread-safe manner.
// Returns the assigned request ID.
func (c *Client) registerLookupRequest(session *Session, address string) uint32 {
	lup := LookupEntry{address: address, session: session}

	c.lock.Lock()
	c.lookupRequestId += 1
	requestId := c.lookupRequestId
	c.lookupReq[requestId] = lup
	c.lock.Unlock()

	return requestId
}

// executeLookupRequest sends the appropriate lookup message based on router capabilities.
// Uses HostLookup for modern routers or falls back to deprecated DestLookup for legacy routers.
func (c *Client) executeLookupRequest(session *Session, requestId uint32, address string, hashStream *Stream) error {
	defaultTimeout := uint32(30000)
	routerCanHostLookup := (c.router.capabilities & ROUTER_CAN_HOST_LOOKUP) == ROUTER_CAN_HOST_LOOKUP

	if routerCanHostLookup {
		if hashStream == nil || hashStream.Len() == 0 {
			return c.msgHostLookup(session, requestId, defaultTimeout, HOST_LOOKUP_TYPE_HOSTNAME, []byte(address), true)
		}
		return c.msgHostLookup(session, requestId, defaultTimeout, HOST_LOOKUP_TYPE_HASH, hashStream.Bytes(), true)
	}

	// Legacy router - use deprecated DestLookup
	Warning("Router version %v < 0.9.11 detected, using deprecated DestLookup (HostLookup unavailable)", c.router.version)
	c.lock.Lock()
	c.lookup[address] = requestId
	c.lock.Unlock()
	c.msgDestLookup(hashStream.Bytes(), true)
	return nil
}

// validateLookupAddress checks if router supports the address format.
// Returns error if validation fails.
func (c *Client) validateLookupAddress(address string) error {
	routerCanHostLookup := (c.router.capabilities & ROUTER_CAN_HOST_LOOKUP) == ROUTER_CAN_HOST_LOOKUP
	b32Len := 56 + 8

	if !routerCanHostLookup && len(address) != b32Len {
		Warning("Address '%s' is not a b32 address %d.", address, len(address))
		return ErrInvalidDestination
	}

	return nil
}

// cleanupLookupRequest removes a lookup request from the registry.
func (c *Client) cleanupLookupRequest(requestId uint32) {
	c.lock.Lock()
	delete(c.lookupReq, requestId)
	c.lock.Unlock()
}

func (c *Client) DestinationLookup(ctx context.Context, session *Session, address string) (uint32, error) {
	if err := c.ensureInitialized(); err != nil {
		return 0, err
	}

	if err := validateLookupParameters(ctx, session, address); err != nil {
		return 0, err
	}

	if err := c.validateLookupAddress(address); err != nil {
		return 0, err
	}

	hashStream, err := decodeB32Address(address)
	if err != nil {
		return 0, err
	}

	requestId := c.registerLookupRequest(session, address)

	if err := ctx.Err(); err != nil {
		c.cleanupLookupRequest(requestId)
		return 0, fmt.Errorf("context cancelled before sending lookup: %w", err)
	}

	if err := c.executeLookupRequest(session, requestId, address, hashStream); err != nil {
		c.cleanupLookupRequest(requestId)
		return 0, fmt.Errorf("failed to send host lookup: %w", err)
	}

	return requestId, nil
}

// Close performs a graceful shutdown of the client.
// It destroys all sessions, waits for pending operations to complete,
// and closes the TCP connection. The shutdown has a 5 second timeout.
//
// Example:
//
//	defer client.Close()
//
// signalShutdown closes the shutdown channel if not already closed.
// Returns error if client is already closed.
func (c *Client) signalShutdown() error {
	select {
	case <-c.shutdown:
		// Already closed
		return ErrClientClosed
	default:
		close(c.shutdown)
		return nil
	}
}

// destroyAllSessions destroys all active sessions if the client is connected.
// Logs warnings for any session destruction failures but continues with others.
func (c *Client) destroyAllSessions() {
	if !c.tcp.IsConnected() {
		return
	}

	// Collect sessions to destroy while holding lock
	c.lock.Lock()
	sessionsToDestroy := make([]*Session, 0, len(c.sessions))
	for _, sess := range c.sessions {
		sessionsToDestroy = append(sessionsToDestroy, sess)
	}
	c.lock.Unlock()

	// Destroy sessions without holding lock to avoid deadlock with cascadeDestroySubsessions
	for _, sess := range sessionsToDestroy {
		Debug("Destroying session %d during shutdown", sess.id)
		if err := c.msgDestroySession(sess, false); err != nil {
			Warning("Failed to destroy session %d during shutdown: %v", sess.id, err)
		}
	}
}

// waitForPendingOperations waits for all pending operations to complete with a timeout.
// Returns after all operations finish or after 5 seconds, whichever comes first.
func (c *Client) waitForPendingOperations() {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		Debug("All pending operations completed")
	case <-time.After(5 * time.Second):
		Warning("Shutdown timeout - forcing close")
	}
}

// cleanupConnection performs final cleanup including disconnecting TCP and updating metrics.
func (c *Client) cleanupConnection() {
	c.tcp.Disconnect()
	c.connected = false

	if c.metrics != nil {
		c.metrics.SetConnectionState("disconnected")
		c.metrics.SetActiveSessions(0)
	}
}

func (c *Client) Close() error {
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	Info("Closing client %p", c)

	// Signal shutdown to all operations
	if err := c.signalShutdown(); err != nil {
		return err
	}

	// Destroy all sessions
	c.destroyAllSessions()

	// Wait for pending operations with timeout
	c.waitForPendingOperations()

	// Close connection and update metrics
	c.cleanupConnection()

	Info("Client %p closed successfully", c)
	return nil
}

// Disconnect is deprecated. Use Close() instead.
// Kept for backward compatibility.
func (c *Client) Disconnect() {
	Info("Disconnection client %p (deprecated - use Close instead)", c)
	if err := c.Close(); err != nil && err != ErrClientClosed {
		Error("Error during disconnect: %v", err)
	}
}

// EnableAutoReconnect enables automatic reconnection with exponential backoff.
// When enabled, the client will automatically attempt to reconnect if the connection
// is lost unexpectedly (not via explicit Close()).
//
// Parameters:
//   - maxRetries: Maximum reconnection attempts (0 = infinite retries)
//   - initialBackoff: Starting delay between reconnect attempts (doubles each time)
//
// The backoff strategy uses exponential backoff capped at 5 minutes.
// Set maxRetries to 0 for infinite retry attempts.
//
// Example:
//
//	// Retry indefinitely with 1 second initial backoff
//	client.EnableAutoReconnect(0, time.Second)
//
//	// Retry up to 5 times with 2 second initial backoff
//	client.EnableAutoReconnect(5, 2*time.Second)
func (c *Client) EnableAutoReconnect(maxRetries int, initialBackoff time.Duration) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.reconnectEnabled = true
	c.reconnectMaxRetries = maxRetries
	c.reconnectBackoff = initialBackoff
	c.reconnectAttempts = 0

	Debug("Auto-reconnect enabled: maxRetries=%d, initialBackoff=%v", maxRetries, initialBackoff)
}

// DisableAutoReconnect disables automatic reconnection.
func (c *Client) DisableAutoReconnect() {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.reconnectEnabled = false
	Debug("Auto-reconnect disabled")
}

// IsAutoReconnectEnabled returns whether auto-reconnect is currently enabled.
func (c *Client) IsAutoReconnectEnabled() bool {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	return c.reconnectEnabled
}

// ReconnectAttempts returns the current number of reconnection attempts.
func (c *Client) ReconnectAttempts() int {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	return c.reconnectAttempts
}

// autoReconnect attempts to reconnect to the I2P router with exponential backoff.
// This is called internally when a disconnect is detected and auto-reconnect is enabled.
// It returns nil if reconnection succeeds, or an error if all retries are exhausted.
func (c *Client) autoReconnect(ctx context.Context) error {
	c.reconnectMu.Lock()
	if !c.reconnectEnabled {
		c.reconnectMu.Unlock()
		return fmt.Errorf("auto-reconnect is not enabled")
	}
	maxRetries := c.reconnectMaxRetries
	initialBackoff := c.reconnectBackoff
	c.reconnectMu.Unlock()

	Info("Starting auto-reconnect (maxRetries=%d, initialBackoff=%v)", maxRetries, initialBackoff)

	// Use RetryWithBackoff for the reconnection logic
	err := RetryWithBackoff(ctx, maxRetries, initialBackoff, func() error {
		c.reconnectMu.Lock()
		c.reconnectAttempts++
		attempt := c.reconnectAttempts
		c.reconnectMu.Unlock()

		Info("Reconnection attempt %d", attempt)

		// Attempt to connect
		connectErr := c.Connect(ctx)
		if connectErr != nil {
			Warning("Reconnection attempt %d failed: %v", attempt, connectErr)
			return connectErr
		}

		Info("Reconnection attempt %d succeeded!", attempt)

		// Reset attempt counter on success
		c.reconnectMu.Lock()
		c.reconnectAttempts = 0
		c.reconnectMu.Unlock()

		return nil
	})
	if err != nil {
		Error("Auto-reconnect failed after all retries: %v", err)
		return fmt.Errorf("auto-reconnect failed: %w", err)
	}

	return nil
}

func (c *Client) SetProperty(name, value string) {
	// Silently return if not initialized (properties map is nil)
	if c.properties == nil {
		return
	}

	if _, ok := c.properties[name]; ok {
		c.properties[name] = value
		switch name {
		case "i2cp.tcp.host":
			c.tcp.SetProperty(TCP_PROP_ADDRESS, c.properties[name])
		case "i2cp.tcp.port":
			c.tcp.SetProperty(TCP_PROP_PORT, c.properties[name])
		case "i2cp.SSL":
			c.tcp.SetProperty(TCP_PROP_USE_TLS, c.properties[name])
		case "i2cp.SSL.certFile":
			c.tcp.SetProperty(TCP_PROP_TLS_CLIENT_CERTIFICATE, c.properties[name])
			// Note: keyFile, caFile, and insecure will be handled by tcp.SetupTLS()
			// These properties are read directly from client.properties during Connect()
		}
	}
}

func (c *Client) IsConnected() bool {
	return c.tcp.IsConnected()
}

// SetMetrics enables metrics collection with the provided collector.
// Pass nil to disable metrics collection.
// This method is safe to call on a running client.
func (c *Client) SetMetrics(metrics MetricsCollector) {
	// Silently return if not initialized
	if err := c.ensureInitialized(); err != nil {
		return
	}

	c.lock.Lock()
	c.metrics = metrics
	c.lock.Unlock()

	// Update active sessions count if metrics enabled
	if metrics != nil {
		metrics.SetActiveSessions(len(c.sessions))
		if c.connected {
			metrics.SetConnectionState("connected")
		} else {
			metrics.SetConnectionState("disconnected")
		}
	}
}

// GetMetrics returns the current metrics collector, or nil if disabled.
func (c *Client) GetMetrics() MetricsCollector {
	// Return nil if not initialized
	if err := c.ensureInitialized(); err != nil {
		return nil
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return c.metrics
}

// GetCircuitBreakerState returns the current state of the circuit breaker.
// Returns CircuitClosed if circuit breaker is disabled (nil).
//
// This allows applications to monitor circuit breaker state and implement
// custom behavior based on router connectivity health.
//
// Example:
//
//	if client.GetCircuitBreakerState() == CircuitOpen {
//	    // Router is unreachable, wait before retrying
//	    time.Sleep(30 * time.Second)
//	}
func (c *Client) GetCircuitBreakerState() CircuitState {
	// Return closed state if not initialized or circuit breaker disabled
	if err := c.ensureInitialized(); err != nil {
		return CircuitClosed
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.circuitBreaker == nil {
		return CircuitClosed
	}

	return c.circuitBreaker.State()
}

// ResetCircuitBreaker manually resets the circuit breaker to closed state.
// This is useful for manual recovery after fixing router connectivity issues.
//
// Returns ErrClientNotInitialized if the client was not properly initialized.
//
// Example:
//
//	// After fixing router configuration
//	if err := client.ResetCircuitBreaker(); err != nil {
//	    log.Printf("Failed to reset circuit breaker: %v", err)
//	}
func (c *Client) ResetCircuitBreaker() error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.circuitBreaker != nil {
		c.circuitBreaker.Reset()
	}

	return nil
}

// RouterVersion returns the I2P router's version information.
// Returns a zero-value Version struct if the client is not initialized or not connected.
//
// This method is safe to call before connecting to the router, but will return
// meaningful data only after a successful connection (after Connect() completes).
//
// I2CP Spec: Router version is exchanged during GetDateMessage (type 32) response.
//
// Example:
//
//	version := client.RouterVersion()
//	fmt.Printf("Router version: %d.%d.%d\n", version.major, version.minor, version.micro)
func (c *Client) RouterVersion() Version {
	// Return zero-value if not initialized
	if err := c.ensureInitialized(); err != nil {
		return Version{}
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return c.router.version
}

// RouterCapabilities returns the router's capability flags as a bitmask.
// Returns 0 if the client is not initialized or not connected.
//
// Known capability flags:
//   - ROUTER_CAN_HOST_LOOKUP (1): Router supports hostname resolution (I2CP 0.9.10+)
//
// This method is safe to call before connecting to the router, but will return
// meaningful data only after a successful connection.
//
// I2CP Spec: Capabilities are determined from router version during connection.
//
// Example:
//
//	caps := client.RouterCapabilities()
//	if (caps & ROUTER_CAN_HOST_LOOKUP) != 0 {
//	    fmt.Println("Router supports hostname lookups")
//	}
func (c *Client) RouterCapabilities() uint32 {
	// Return 0 if not initialized
	if err := c.ensureInitialized(); err != nil {
		return 0
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return c.router.capabilities
}

// RouterDate returns the router's timestamp in I2P time format (milliseconds since epoch).
// Returns 0 if the client is not initialized or not connected.
//
// This timestamp is used for time synchronization and lease expiration calculations.
// The router date is typically close to the current system time but may differ
// if the router's clock is skewed.
//
// I2CP Spec: Router date is exchanged during GetDateMessage (type 32) response.
//
// Example:
//
//	date := client.RouterDate()
//	routerTime := time.Unix(int64(date/1000), int64((date%1000)*1000000))
//	fmt.Printf("Router time: %v\n", routerTime)
func (c *Client) RouterDate() uint64 {
	// Return 0 if not initialized
	if err := c.ensureInitialized(); err != nil {
		return 0
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return c.router.date
}

// SupportsHostLookup returns whether the router supports hostname resolution.
// Returns false if the client is not initialized or not connected.
//
// Hostname lookup capability was added in I2CP protocol version 0.9.10.
// Applications should check this capability before calling DestinationLookup
// with hostname strings (non-base64 destinations).
//
// I2CP Spec: HostLookupMessage (type 38) requires router version >= 0.9.10.
//
// Example:
//
//	if !client.SupportsHostLookup() {
//	    return fmt.Errorf("router does not support hostname lookups")
//	}
//	client.DestinationLookup(ctx, session, "example.i2p")
func (c *Client) SupportsHostLookup() bool {
	// Return false if not initialized
	if err := c.ensureInitialized(); err != nil {
		return false
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return (c.router.capabilities & ROUTER_CAN_HOST_LOOKUP) == ROUTER_CAN_HOST_LOOKUP
}

// SupportsMultiSession returns whether the router supports multi-session contexts.
// Returns false if the client is not initialized or not connected.
//
// Multi-session support (primary sessions with subsessions) was added in
// I2CP protocol version 0.9.21. Subsessions share the tunnel pool of their
// primary session, enabling efficient resource usage for related services.
//
// Applications should check this capability before creating subsessions.
// Attempting to create subsessions on routers that don't support this
// feature will result in ErrMultiSessionUnsupported errors.
//
// I2CP Spec: Multi-session support requires router version >= 0.9.21.
//
// Example:
//
//	if !client.SupportsMultiSession() {
//	    return fmt.Errorf("router does not support multi-session contexts")
//	}
//	// Safe to create subsessions
func (c *Client) SupportsMultiSession() bool {
	// Return false if not initialized
	if err := c.ensureInitialized(); err != nil {
		return false
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	// Multi-session support added in I2CP 0.9.21
	requiredVersion := Version{major: 0, minor: 9, micro: 21, qualifier: 0}
	return c.router.version.compare(requiredVersion) >= 0
}

// trackError records an error in metrics if enabled.
// This is a helper method for internal use.
func (c *Client) trackError(errorType string) {
	if c.metrics != nil {
		c.metrics.IncrementError(errorType)
	}
}
