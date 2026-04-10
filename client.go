package go_i2cp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
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
	messageStreamMu sync.Mutex // Protects messageStream access (CRITICAL: prevents race conditions in concurrent message sending)
	receiveStream   *Stream    // Dedicated buffer for receiving messages (prevents corruption from messageStream reuse)
	router          RouterInfo
	outputQueue     []*Stream
	sessions        map[uint16]*Session
	n_sessions      int
	lookup          map[string]uint32
	lookupReq       map[uint32]LookupEntry
	lock            sync.Mutex
	connected       bool
	currentSession  *Session     // *opaque in the C lib
	sessionMu       sync.RWMutex // Protects currentSession pointer access (CRITICAL: prevents race conditions during session creation)
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

// sendMessage sends an I2CP message either immediately or queued for batching.
func (c *Client) sendMessage(typ uint8, stream *Stream, queue bool) (err error) {
	send := c.buildMessageFrame(typ, stream)
	c.recordSentMessageStats(typ, send.Len())

	if queue {
		return c.queueMessage(send)
	}
	return c.sendMessageDirect(typ, send)
}

// buildMessageFrame constructs the wire-format message frame with length prefix and type.
func (c *Client) buildMessageFrame(typ uint8, stream *Stream) *Stream {
	send := NewStream(make([]byte, 0, stream.Len()+4+1))
	send.WriteUint32(uint32(stream.Len()))
	send.WriteByte(typ)
	send.Write(stream.Bytes())
	return send
}

// recordSentMessageStats records message statistics for debugging and monitoring.
func (c *Client) recordSentMessageStats(typ uint8, frameLen int) {
	if c.messageStats != nil && c.messageStats.IsEnabled() {
		c.messageStats.RecordSent(typ, uint64(frameLen))
	}
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		c.protocolDebugger.LogMessage("SEND", typ, uint32(frameLen), nil, 0)
	}
}

// queueMessage adds a message to the output queue for batched sending.
func (c *Client) queueMessage(send *Stream) error {
	Debug("Putting %d bytes message on the output queue.", send.Len())
	c.lock.Lock()
	c.outputQueue = append(c.outputQueue, send)

	if c.batchEnabled && c.getTotalQueueSize() >= c.batchSizeThreshold {
		c.lock.Unlock()
		Debug("Batch size threshold exceeded (%d bytes), flushing immediately", c.getTotalQueueSize())
		return c.flushOutputQueue()
	}
	c.lock.Unlock()
	return nil
}

// sendMessageDirect sends a message immediately without queuing.
func (c *Client) sendMessageDirect(typ uint8, send *Stream) error {
	if c.metrics != nil {
		c.metrics.AddBytesSent(uint64(send.Len()))
		c.metrics.IncrementMessageSent(typ)
	}

	if c.circuitBreaker != nil {
		return c.circuitBreaker.Execute(func() error {
			_, sendErr := c.tcp.Send(send)
			return sendErr
		})
	}
	_, err := c.tcp.Send(send)
	return err
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
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordFailure()
		}
		if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
			c.callbacks.OnDisconnect(c, "Didn't receive anything", nil)
		}
		return 0, 0, fmt.Errorf("no data received from router")
	}
	if err != nil {
		c.trackError("network")
		if c.circuitBreaker != nil {
			c.circuitBreaker.RecordFailure()
		}
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
		c.onMsgBandwidthLimit(stream)
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

// initializeLeaseSetStream creates and initializes the lease set stream with null bytes.
func (c *Client) getAuthenticationMethod() uint8 {
	// Note: AUTH_METHOD_PER_CLIENT_DH (3) and AUTH_METHOD_PER_CLIENT_PSK (4) are NOT
	// I2CP session authentication methods. They are for encrypted LeaseSet access
	// via BlindingInfoMessage. If someone tries to use them here, it's a misconfiguration.
	if c.properties["i2cp.auth.method"] == "3" {
		Warning("i2cp.auth.method=3 is invalid: DH is for BlindingInfo, not session auth. Using no auth.")
		Debug("Use SendBlindingInfo() with NewPerClientAuthDH() for DH encrypted LeaseSet access")
		return AUTH_METHOD_NONE
	}
	if c.properties["i2cp.auth.method"] == "4" {
		Warning("i2cp.auth.method=4 is invalid: PSK is for BlindingInfo, not session auth. Using no auth.")
		Debug("Use SendBlindingInfo() with NewPerClientAuthPSK() for PSK encrypted LeaseSet access")
		return AUTH_METHOD_NONE
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
// Supported I2CP session authentication methods:
//   - Method 0 (none): No authentication
//   - Method 1 (username/password): I2CP 0.9.11+ username/password auth
//   - Method 2 (TLS): I2CP 0.8.3+ TLS certificate auth
//
// NOTE: Per-client DH/PSK (methods 3-4) are NOT session auth methods.
// They are for encrypted LeaseSet access via BlindingInfoMessage.
func (c *Client) msgGetDate(queue bool) {
	Debug("Sending GetDateMessage")

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.messageStream.Reset()
	c.messageStream.WriteLenPrefixedString(I2CP_CLIENT_VERSION)

	c.writeAuthenticationMapping()

	if err := c.sendMessage(I2CP_MSG_GET_DATE, c.messageStream, queue); err != nil {
		Error("Error while sending GetDateMessage")
	}
}

// writeAuthenticationMapping writes the authentication mapping to the message stream.
func (c *Client) writeAuthenticationMapping() {
	authMethod := c.getAuthenticationMethod()

	switch authMethod {
	case AUTH_METHOD_USERNAME_PWD:
		authInfo := map[string]string{
			"i2cp.username": c.properties["i2cp.username"],
			"i2cp.password": c.properties["i2cp.password"],
		}
		c.messageStream.WriteMapping(authInfo)
		Debug("Using username/password authentication (method 1)")

	case AUTH_METHOD_SSL_TLS:
		authInfo := map[string]string{
			"i2cp.auth.method": "2",
		}
		c.messageStream.WriteMapping(authInfo)
		Debug("Using TLS certificate authentication (method 2)")

	case AUTH_METHOD_NONE:
		c.messageStream.WriteMapping(map[string]string{})
		Debug("Using no authentication (method 0) - sending empty mapping for 0.9.11+ compliance")

	default:
		Warning("Unknown authentication method %d, using no authentication with empty mapping", authMethod)
		c.messageStream.WriteMapping(map[string]string{})
	}
}

func (c *Client) msgCreateSession(config *SessionConfig, queue bool) error {
	Info(">>> SENDING CreateSessionMessage to router")

	recordCreateSessionState(c)

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	// Build the session config message first (this sets config.date)
	c.messageStream.Reset()
	config.writeToMessage(c.messageStream, c.crypto, c)

	dumpCreateSessionMessage(c, c.messageStream, config)

	// Validate timestamp skew
	if err := validateCreateSessionTimestamp(c, config); err != nil {
		return err
	}

	// Log detailed message info
	Info("CreateSession message: %d bytes, timestamp: %d (%v)",
		c.messageStream.Len(), config.date, time.UnixMilli(int64(config.date)).Format(time.RFC3339))

	if err := c.sendMessage(I2CP_MSG_CREATE_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending CreateSessionMessage.")
		return err
	}
	Info("<<< CreateSessionMessage sent successfully, awaiting SessionStatus response")
	Debug("<<< CreateSessionMessage sent successfully, awaiting SessionCreated response")
	return nil
}

// recordCreateSessionState records the pending session state in the state tracker.
func recordCreateSessionState(c *Client) {
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		// Use 0 as placeholder until we get the real session ID
		c.stateTracker.SetState(0, SessionStatePending, "CreateSession being sent")
	}
}

// dumpCreateSessionMessage dumps the CreateSession message for debugging if enabled.
func dumpCreateSessionMessage(c *Client, messageStream *Stream, config *SessionConfig) {
	if c.protocolDebugger == nil || !c.protocolDebugger.IsEnabled() {
		return
	}

	msgBytes := messageStream.Bytes()
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

// validateCreateSessionTimestamp validates the session config timestamp against router time.
func validateCreateSessionTimestamp(c *Client, config *SessionConfig) error {
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
	return nil
}

// per I2CP specification section 7.1 - implements runtime tunnel and crypto parameter changes
func (c *Client) msgReconfigureSession(session *Session, properties map[string]string, queue bool) error {
	Debug("Sending ReconfigureSessionMessage for session %d with %d properties", session.id, len(properties))

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

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
	if err := c.checkBlindingInfoSupport(); err != nil {
		return err
	}

	if err := c.validateBlindingInfo(sess, info); err != nil {
		return err
	}

	Debug("Sending BlindingInfoMessage for session %d, endpoint type %d", sess.id, info.EndpointType)

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	if err := c.buildBlindingInfoMessage(sess, info); err != nil {
		return err
	}

	return c.sendBlindingInfoMessage(sess.id, queue)
}

// checkBlindingInfoSupport verifies the router supports BlindingInfo messages.
func (c *Client) checkBlindingInfoSupport() error {
	if !c.SupportsVersion(VersionBlindingInfo) {
		return fmt.Errorf("router version %s does not support BlindingInfo (requires %s+)",
			c.router.version.String(), VersionBlindingInfo.String())
	}
	return nil
}

// buildBlindingInfoMessage constructs the BlindingInfoMessage in the message stream.
func (c *Client) buildBlindingInfoMessage(sess *Session, info *BlindingInfo) error {
	c.messageStream.Reset()

	c.messageStream.WriteUint16(sess.id)
	c.messageStream.WriteByte(c.buildBlindingFlags(info))
	c.messageStream.WriteByte(info.EndpointType)
	c.messageStream.WriteUint16(info.BlindedSigType)
	c.messageStream.WriteUint32(info.Expiration)

	if err := c.writeBlindingEndpoint(info); err != nil {
		return fmt.Errorf("failed to write endpoint: %w", err)
	}

	return c.writeBlindingOptionalFields(info)
}

// writeBlindingOptionalFields writes optional decryption key and lookup password.
func (c *Client) writeBlindingOptionalFields(info *BlindingInfo) error {
	if info.PerClientAuth {
		c.messageStream.Write(info.DecryptionKey)
	}

	if info.LookupPassword != "" {
		if err := c.messageStream.WriteLenPrefixedString(info.LookupPassword); err != nil {
			return fmt.Errorf("failed to write lookup password: %w", err)
		}
	}
	return nil
}

// sendBlindingInfoMessage sends the constructed BlindingInfoMessage.
func (c *Client) sendBlindingInfoMessage(sessionID uint16, queue bool) error {
	if err := c.sendMessage(I2CP_MSG_BLINDING_INFO, c.messageStream, queue); err != nil {
		Error("Error while sending BlindingInfoMessage: %v", err)
		return fmt.Errorf("failed to send BlindingInfoMessage: %w", err)
	}

	Debug("Successfully sent BlindingInfoMessage for session %d", sessionID)
	return nil
}

// validateBlindingInfo validates the BlindingInfo parameters before sending.
func (c *Client) validateBlindingInfo(sess *Session, info *BlindingInfo) error {
	if err := validateBlindingInfoParams(sess, info); err != nil {
		return err
	}

	if err := validateBlindingEndpoint(info); err != nil {
		return err
	}

	if err := validateBlindingAuthScheme(info); err != nil {
		return err
	}

	if err := validateBlindingDecryptionKey(info); err != nil {
		return err
	}

	return nil
}

// validateBlindingInfoParams checks if session and blinding info parameters are not nil.
func validateBlindingInfoParams(sess *Session, info *BlindingInfo) error {
	if sess == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if info == nil {
		return fmt.Errorf("blinding info cannot be nil")
	}
	return nil
}

// validateBlindingEndpoint validates endpoint type and endpoint data for all supported types.
func validateBlindingEndpoint(info *BlindingInfo) error {
	if info.EndpointType > BLINDING_ENDPOINT_SIGKEY {
		return fmt.Errorf("invalid endpoint type %d (must be 0-3)", info.EndpointType)
	}

	return validateEndpointData(info)
}

// validateEndpointData validates the endpoint data based on the endpoint type.
func validateEndpointData(info *BlindingInfo) error {
	switch info.EndpointType {
	case BLINDING_ENDPOINT_HASH:
		return validateHashEndpoint(info.Endpoint)
	case BLINDING_ENDPOINT_HOSTNAME:
		return validateHostnameEndpoint(info.Endpoint)
	case BLINDING_ENDPOINT_DESTINATION:
		return validateDestinationEndpoint(info.Endpoint)
	case BLINDING_ENDPOINT_SIGKEY:
		return validateSigkeyEndpoint(info.Endpoint)
	}
	return nil
}

// validateHashEndpoint checks if hash endpoint is exactly 32 bytes.
func validateHashEndpoint(endpoint []byte) error {
	if len(endpoint) != 32 {
		return fmt.Errorf("hash endpoint must be exactly 32 bytes, got %d", len(endpoint))
	}
	return nil
}

// validateHostnameEndpoint checks if hostname endpoint is non-empty and within 255 bytes.
func validateHostnameEndpoint(endpoint []byte) error {
	if len(endpoint) == 0 {
		return fmt.Errorf("hostname endpoint cannot be empty")
	}
	if len(endpoint) > 255 {
		return fmt.Errorf("hostname too long: %d bytes (max 255)", len(endpoint))
	}
	return nil
}

// validateDestinationEndpoint checks if destination endpoint meets minimum size requirement.
func validateDestinationEndpoint(endpoint []byte) error {
	if len(endpoint) < 387 { // Minimum destination size
		return fmt.Errorf("destination endpoint too short: %d bytes", len(endpoint))
	}
	return nil
}

// validateSigkeyEndpoint checks if sigkey endpoint meets minimum size requirement.
func validateSigkeyEndpoint(endpoint []byte) error {
	if len(endpoint) < 3 { // At minimum: 2-byte sig type + 1 byte key
		return fmt.Errorf("sigkey endpoint too short: %d bytes", len(endpoint))
	}
	return nil
}

// validateBlindingAuthScheme checks if the auth scheme is within valid bounds.
func validateBlindingAuthScheme(info *BlindingInfo) error {
	if info.AuthScheme > BLINDING_AUTH_SCHEME_PSK {
		return fmt.Errorf("invalid auth scheme %d (must be 0 or 1)", info.AuthScheme)
	}
	return nil
}

// validateBlindingDecryptionKey validates the decryption key when per-client auth is enabled.
func validateBlindingDecryptionKey(info *BlindingInfo) error {
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

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.messageStream.Reset()
	if err := c.sendMessage(I2CP_MSG_GET_BANDWIDTH_LIMITS, c.messageStream, queue); err != nil {
		Error("Error while sending GetBandwidthLimitsMessage")
	}
}

func (c *Client) msgDestroySession(sess *Session, sessionID uint16, isPrimary bool, queue bool, callerHoldsLock bool) error {
	// I2CP SPEC COMPLIANCE: Handle both spec-compliant and Java I2P router behaviors
	// Per I2CP spec § DestroySessionMessage: "The router should respond with a SessionStatusMessage (Destroyed)"
	// Per I2CP 0.9.67 § DestroySessionMessage Notes (Java I2P deviation):
	// "Through API 0.9.66, the Java I2P router and client libraries deviate substantially.
	// The router never sends SessionStatus(Destroyed). If no sessions are left, it sends
	// DisconnectMessage. If there are subsessions or primary remains, it does not reply."

	// NOTE: sessionID and isPrimary are passed as parameters to avoid mutex re-entry deadlock
	// when called from Session.Close() which already holds session.mu
	// callerHoldsLock indicates if the caller already holds sess.mu
	wasPrimary := isPrimary
	Debug("msgDestroySession called for session %d (isPrimary: %v, callerHoldsLock: %v)", sessionID, wasPrimary, callerHoldsLock)
	cascadeDestroySubsessions(c, sess, sessionID, wasPrimary)

	if err := sendDestroySessionMessage(c, sessionID, wasPrimary, queue); err != nil {
		return err
	}

	waitForDestroyConfirmation(sess, wasPrimary)

	// CRITICAL FIX: Per I2CP § DestroySessionMessage Notes (0.9.67):
	// "Destroying the primary session will, however, destroy all subsessions and stop the I2CP connection."
	if wasPrimary {
		Debug("Primary session destroyed - closing I2CP connection per spec requirement")
		return c.Close()
	}

	// MAJOR-2 FIX: Proper subsession cleanup when destroying individual subsessions
	// Per I2CP § Destroying Subsessions: "A subsession may be destroyed with the DestroySession
	// message as usual. This will not destroy the primary session or stop the I2CP connection."
	// We must clean up the subsession's local state and remove it from the sessions map.
	Debug("Calling cleanupDestroyedSubsession for session %d", sessionID)
	cleanupDestroyedSubsession(c, sess, sessionID, isPrimary, callerHoldsLock)

	return nil
}

// cascadeDestroySubsessions destroys all subsessions when a primary session is destroyed.
// Per I2CP § Multisession Notes, destroying the primary cascades to all subsessions.
// NOTE: sessionID and isPrimary are passed as parameters to avoid mutex re-entry deadlock
func cascadeDestroySubsessions(c *Client, sess *Session, sessionID uint16, isPrimary bool) {
	// COMPLIANCE FIX: Cascade destroy subsessions when primary is destroyed (I2CP § Multisession Notes)
	c.lock.Lock()
	defer c.lock.Unlock()

	// NOTE: isPrimary is passed as parameter to avoid mutex re-entry deadlock
	if !isPrimary {
		return
	}

	Debug("Destroying primary session %d - cascading to all subsessions per I2CP spec", sessionID)
	// Destroy all subsessions first
	for id, s := range c.sessions {
		if id != sessionID && !s.IsPrimary() { // Thread-safe getter (different session, safe to call)
			Debug("Auto-destroying subsession %d (primary %d being destroyed)", id, sessionID)
			// Recursive call for subsessions - subsession's isPrimary is false, use s.ID() which is safe
			// callerHoldsLock=false because we don't hold the subsession's lock
			c.lock.Unlock()
			c.msgDestroySession(s, s.ID(), false, false, false)
			c.lock.Lock()
			delete(c.sessions, id)
		}
	}
	c.primarySessionID = nil
}

// cleanupDestroyedSubsession performs complete cleanup of a destroyed subsession.
// Per I2CP § Destroying Subsessions: Individual subsession destruction should not
// destroy the primary session or stop the I2CP connection, but must properly clean
// up the subsession's local state to prevent resource leaks.
//
// This function handles:
// - Removing the session from the client's sessions map
// - Clearing pending messages to prevent memory leaks
// - Cancelling the session's context
// - Removing the reference to the primary session
// - Clearing encryption key pairs and blinding parameters
//
// NOTE: sessionID and isPrimary are passed as parameters to avoid mutex re-entry.
// The callerHoldsLock parameter indicates if the caller already holds sess.mu.
func cleanupDestroyedSubsession(c *Client, sess *Session, sessionID uint16, isPrimary bool, callerHoldsLock bool) {
	if isPrimary {
		// Primary sessions are cleaned up via Close(), not here
		Debug("cleanupDestroyedSubsession: session %d is primary, skipping", sessionID)
		return
	}

	Debug("cleanupDestroyedSubsession: Cleaning up destroyed subsession %d", sessionID)

	// Remove from client's sessions map
	c.lock.Lock()
	Debug("cleanupDestroyedSubsession: Deleting session %d from sessions map", sessionID)
	delete(c.sessions, sessionID)
	c.lock.Unlock()

	// Clean up the session's internal state
	// Only acquire lock if caller doesn't already hold it
	if !callerHoldsLock {
		sess.mu.Lock()
		defer sess.mu.Unlock()
	}

	cleanupSessionPendingMessages(sess)
	cleanupSessionContext(sess)
	cleanupSessionReferences(sess)
	cleanupSessionLeases(sess)
	markSessionClosed(sess)
	closeSessionDestroyConfirmedChannel(sess)

	Debug("Subsession %d cleanup complete", sess.id)
}

// cleanupSessionPendingMessages clears pending messages from a session.
func cleanupSessionPendingMessages(sess *Session) {
	if sess.pendingMessages != nil {
		pendingCount := len(sess.pendingMessages)
		if pendingCount > 0 {
			Debug("Clearing %d pending messages from destroyed subsession %d", pendingCount, sess.id)
		}
		sess.pendingMessages = nil
	}
}

// cleanupSessionContext cancels the session's context if it exists.
func cleanupSessionContext(sess *Session) {
	if sess.cancel != nil {
		sess.cancel()
	}
}

// cleanupSessionReferences clears references to other sessions and keys.
func cleanupSessionReferences(sess *Session) {
	// Clear the reference to primary session to allow GC
	sess.primarySession = nil

	// Clear encryption key pair (subsessions share with primary, but clear reference)
	sess.encryptionKeyPair = nil

	// Clear blinding parameters
	sess.blindingScheme = 0
	sess.blindingFlags = 0
	sess.blindingParams = nil
}

// cleanupSessionLeases clears the session's lease set.
func cleanupSessionLeases(sess *Session) {
	sess.leases = nil
}

// markSessionClosed marks the session as closed and records the time.
func markSessionClosed(sess *Session) {
	sess.closed = true
	sess.closedAt = time.Now()
}

// closeSessionDestroyConfirmedChannel closes the destroyConfirmed channel if open.
func closeSessionDestroyConfirmedChannel(sess *Session) {
	if sess.destroyConfirmed != nil {
		select {
		case <-sess.destroyConfirmed:
			// Already closed
		default:
			close(sess.destroyConfirmed)
		}
	}
}

// cleanupSubsessionFromMap removes a subsession from the client's sessions map.
// This is called when Session.Close() couldn't send the destroy message
// (e.g., because IsConnected() returned false) but still needs to clean up.
// Per I2CP § Destroying Subsessions: cleanup must happen regardless of router communication.
func (c *Client) cleanupSubsessionFromMap(sessionID uint16) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, exists := c.sessions[sessionID]; exists {
		Debug("cleanupSubsessionFromMap: Removing session %d from sessions map", sessionID)
		delete(c.sessions, sessionID)
	}
}

// cascadeCloseSubsessions closes all subsessions when a primary session is closed
// but the destroy message couldn't be sent (e.g., connection already closed).
// Per I2CP § Destroying Subsessions: "Destroying the primary session will,
// however, destroy all subsessions and stop the I2CP connection."
func (c *Client) cascadeCloseSubsessions(primaryID uint16) {
	subsessions := c.collectSubsessions(primaryID)
	c.closeSubsessionList(subsessions)
	c.removeSubsessionsFromMap(primaryID)
}

// collectSubsessions gathers all subsessions associated with a primary session.
func (c *Client) collectSubsessions(primaryID uint16) []*Session {
	c.lock.Lock()
	defer c.lock.Unlock()

	var subsessions []*Session
	for id, sess := range c.sessions {
		if id != primaryID && !sess.IsPrimary() { // Thread-safe getter
			subsessions = append(subsessions, sess)
		}
	}
	return subsessions
}

// closeSubsessionList marks each subsession as closed and dispatches status.
func (c *Client) closeSubsessionList(subsessions []*Session) {
	for _, sess := range subsessions {
		Debug("cascadeCloseSubsessions: closing subsession %d", sess.ID()) // Thread-safe getter
		c.markSubsessionClosed(sess)
		sess.dispatchStatus(I2CP_SESSION_STATUS_DESTROYED)
	}
}

// markSubsessionClosed marks a single subsession as closed with timestamp.
func (c *Client) markSubsessionClosed(sess *Session) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.closed {
		sess.closed = true
		sess.closedAt = time.Now()
	}
}

// removeSubsessionsFromMap removes all subsessions from the sessions map.
func (c *Client) removeSubsessionsFromMap(primaryID uint16) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for id := range c.sessions {
		if id != primaryID {
			delete(c.sessions, id)
		}
	}
	c.primarySessionID = nil
}

// sendDestroySessionMessage sends the DestroySessionMessage to the router.
// Returns an error if the message cannot be sent.
// NOTE: sessionID is passed as parameter to avoid mutex re-entry deadlock
func sendDestroySessionMessage(c *Client, sessionID uint16, isPrimary bool, queue bool) error {
	Debug("Sending DestroySessionMessage for session %d (primary: %v)", sessionID, isPrimary)

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.messageStream.Reset()
	c.messageStream.WriteUint16(sessionID)

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

	compressedPayload, err := c.compressPayload(payload, protocol, srcPort, destPort)
	if err != nil {
		return err
	}

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.messageStream.Reset()
	c.messageStream.WriteUint16(sess.id)
	dest.WriteToMessage(c.messageStream)
	c.messageStream.WriteUint32(uint32(compressedPayload.Len()))
	c.messageStream.Write(compressedPayload.Bytes())
	c.messageStream.WriteUint32(nonce)

	if err := c.validateMessageSize(compressedPayload.Len()); err != nil {
		return err
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

	// Validate flags using public API
	if err := ValidateSendMessageFlags(flags); err != nil {
		return err
	}

	compressedPayload, err := c.compressPayload(payload, protocol, srcPort, destPort)
	if err != nil {
		return err
	}

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

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
		Warning("Message size %d exceeds conservative limit %d bytes (max %d), some routers may reject",
			totalMessageSize, I2CP_SAFE_MESSAGE_SIZE, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
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

// destroyAllSessions destroys all active sessions.
// Does not check IsConnected() to avoid blocking I/O during shutdown.
// Logs warnings for any session destruction failures but continues with others.
func (c *Client) destroyAllSessions() {
	// Skip IsConnected() check - it can block indefinitely on Peek().
	// Instead, just attempt to destroy sessions; the write will fail quickly
	// if the connection is closed, and we handle errors gracefully.
	// Thread-safe: use TCP mutex to check connection state
	c.tcp.mu.RLock()
	connNil := c.tcp.conn == nil
	c.tcp.mu.RUnlock()
	if connNil {
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
		// DEADLOCK FIX: Try to acquire the session lock. If we can't, the session is
		// already being destroyed by another goroutine (e.g., the primary session's
		// Close() which triggered this destroyAllSessions call). Skip it.
		if !sess.mu.TryLock() {
			Debug("Session %d is already locked (being destroyed elsewhere), skipping", sess.id)
			continue
		}
		// We now hold the lock, extract values and release before calling msgDestroySession
		sessionID := sess.id
		isPrimary := sess.isPrimary
		closed := sess.closed
		sess.mu.Unlock()

		if closed {
			Debug("Session %d already closed, skipping", sessionID)
			continue
		}

		Debug("Destroying session %d during shutdown", sessionID)
		// callerHoldsLock=false because we released the session's lock above
		if err := c.msgDestroySession(sess, sessionID, isPrimary, false, false); err != nil {
			Warning("Failed to destroy session %d during shutdown: %v", sessionID, err)
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

// isConnectedFast returns the cached connection state without performing socket operations.
// This is safe to call while holding other locks as it doesn't block on I/O.
// Use this for internal checks where blocking I/O could cause deadlocks.
func (c *Client) isConnectedFast() bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.connected
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

// SupportsVersion returns true if the connected router version is at least minVersion.
// Returns false if the client is not initialized or not connected.
//
// This method should be used to check feature availability before sending
// version-specific messages. Per I2CP spec § Version Notes:
// "Clients and routers should not send messages that are unsupported by the other side"
//
// Common version checks (use predefined Version* constants):
//   - VersionFastReceive (0.9.4+): Fast receive mode
//   - VersionHostLookup (0.9.11+): HostLookup/HostReply messages
//   - VersionMultiSession (0.9.21+): Multi-session support
//   - VersionCreateLeaseSet2 (0.9.39+): CreateLeaseSet2Message
//   - VersionBlindingInfo (0.9.43+): BlindingInfoMessage
//   - VersionProposal167 (0.9.66+): HostReply options mapping
//
// Example:
//
//	if client.SupportsVersion(VersionBlindingInfo) {
//	    client.msgBlindingInfo(session, info, true)
//	} else {
//	    return errors.New("router does not support blinding (requires 0.9.43+)")
//	}
func (c *Client) SupportsVersion(minVersion Version) bool {
	if err := c.ensureInitialized(); err != nil {
		return false
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	return c.router.version.AtLeast(minVersion)
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
