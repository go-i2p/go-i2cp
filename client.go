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
	length := uint32(0)
	msgType := uint8(0)
	var i int
	firstFive := NewStream(make([]byte, 5))
	i, err = c.tcp.Receive(firstFive)
	if i == 0 {
		c.trackError("network")
		if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
			c.callbacks.OnDisconnect(c, "Didn't receive anything", nil)
		}
		return fmt.Errorf("no data received from router")
	}
	if err != nil {
		c.trackError("network")
		Error("Failed to receive message header: %s", err.Error())
		return err
	}

	length, err = firstFive.ReadUint32()
	if err != nil {
		Error("Failed to read message length: %s", err.Error())
		return err
	}

	msgType, err = firstFive.ReadByte()
	if err != nil {
		Error("Failed to read message type: %s", err.Error())
		return err
	}

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
	if (typ != I2CP_MSG_ANY) && (msgType != typ) {
		c.trackError("protocol")
		Error("Expected message type %d, received %d", typ, msgType)
		return fmt.Errorf("unexpected message type: expected %d, got %d", typ, msgType)
	}

	// Allocate appropriately sized buffer for message body
	if length > 0 {
		messageBody := NewStream(make([]byte, 0, length)) // Create empty buffer with capacity
		totalReceived := 0

		// Handle partial reads for large messages
		for totalReceived < int(length) {
			remaining := int(length) - totalReceived
			tempBuffer := NewStream(make([]byte, remaining))

			i, err = c.tcp.Receive(tempBuffer)
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
	} else {
		// Empty message body
		stream.Reset()
	}

	Debug("Received message type %d with %d bytes", msgType, length)

	// Track bandwidth and message received
	if c.metrics != nil {
		c.metrics.AddBytesReceived(uint64(length + 5)) // +5 for header
		c.metrics.IncrementMessageReceived(msgType)
	}

	if dispatch {
		c.onMessage(msgType, stream)
	}
	return nil
}

func (c *Client) onMessage(msgType uint8, stream *Stream) {
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

	// DEBUG: Dump raw message bytes
	rawBytes := stream.Bytes()
	Debug("SetDate raw bytes (length=%d): %v", len(rawBytes), rawBytes)

	// Read router date (8 bytes, big-endian uint64)
	routerDate, err := stream.ReadUint64()
	if err != nil {
		Error("Failed to read router date: %s", err.Error())
		c.router.date = uint64(time.Now().Unix() * 1000) // Fallback to local time
		return
	}
	Debug("Read router.date = %d", routerDate)

	// Read version string length (1 byte)
	verLength, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read version length: %s", err.Error())
		return
	}
	Debug("Read version length = %d", verLength)

	// Read version string
	version := make([]byte, verLength)
	_, err = stream.Read(version)
	if err != nil {
		Error("Failed to read version string: %s", err.Error())
		return
	}

	c.router.date = routerDate
	c.router.version = parseVersion(string(version))
	Debug("Router version %s, date %d", string(version), c.router.date)

	if c.router.version.compare(Version{major: 0, minor: 9, micro: 10, qualifier: 0}) >= 0 {
		c.router.capabilities |= ROUTER_CAN_HOST_LOOKUP
	}

	// CRITICAL FIX: Calculate router time delta for session config timestamp sync
	// Per I2CP spec: session config date must be within ±30 seconds of router time
	localTime := uint64(time.Now().Unix() * 1000)
	c.routerTimeMu.Lock()

	// Handle edge case: router sends zero/invalid date (e.g., during initialization)
	// Zero date would cause session timestamp to become 0, triggering Java NullPointerException
	if c.router.date == 0 {
		Warning("Router sent zero/invalid date - falling back to unsynchronized local time")
		c.routerTimeDelta = 0
	} else {
		c.routerTimeDelta = int64(c.router.date) - int64(localTime)
		c.routerTimeMu.Unlock()

		Debug("Router time delta: %d ms (local: %d, router: %d)", c.routerTimeDelta, localTime, c.router.date)
		if c.routerTimeDelta > 30000 || c.routerTimeDelta < -30000 {
			Warning("Large clock skew detected: %d ms. Session creation may fail if not corrected.", c.routerTimeDelta)
		}
		return
	}
	c.routerTimeMu.Unlock()
}

func (c *Client) onMsgDisconnect(stream *Stream) {
	var err error
	Debug("Received Disconnect message")
	// size, err = stream.ReadByte()
	strbuf := make([]byte, stream.Len())
	lens := stream.Len()
	_ = lens
	_, err = stream.Read(strbuf)

	Debug("Received Disconnect message with reason %s", string(strbuf))
	if err != nil {
		Error("Could not read msgDisconnect correctly data")
	}

	// Invoke disconnect callback if registered
	if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
		c.callbacks.OnDisconnect(c, string(strbuf), nil)
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

func (c *Client) onMsgPayload(stream *Stream) {
	gzipHeader := [3]byte{0x1f, 0x8b, 0x08}
	var testHeader [3]byte
	var protocol uint8
	var sessionId, srcPort, destPort uint16
	var messageId, payloadSize uint32
	var srcDest *Destination
	var err error
	Debug("Received PayloadMessage message")
	sessionId, err = stream.ReadUint16()
	messageId, err = stream.ReadUint32()
	_ = messageId // currently unused
	c.lock.Lock()
	session, ok := c.sessions[sessionId]
	c.lock.Unlock()
	if !ok {
		Fatal("Session id %d does not match any of our currently initiated sessions by %p", sessionId, c)
	}
	payloadSize, err = stream.ReadUint32()
	_ = payloadSize // currently unused
	// Parse source destination (I2CP spec: destination follows payload size)
	srcDest, err = NewDestinationFromMessage(stream, c.crypto)
	if err != nil {
		Error("Failed to parse source destination from MessagePayload: %v", err)
		return
	}
	Debug("Message from source: %s", srcDest.Base32())
	// validate gzip header
	msgStream := bytes.NewBuffer(stream.Bytes())
	_, err = stream.Read(testHeader[:])
	if testHeader != gzipHeader {
		Warning("Payload validation failed, skipping payload")
		return
	}
	payload := bytes.NewBuffer(make([]byte, 0xffff))
	var decompress io.ReadCloser
	decompress, err = gzip.NewReader(msgStream)
	if err != nil {
		Error("Failed to create gzip reader for message payload: %v", err)
		return
	}
	_, err = io.Copy(payload, decompress)
	if err != nil {
		Error("Failed to decompress message payload: %v", err)
		decompress.Close()
		return
	}
	if err = decompress.Close(); err != nil {
		Error("Failed to close decompressor: %v", err)
		return
	}
	if payload.Len() > 0 {
		// finish reading header
		// skip gzip flags
		if _, err = stream.ReadByte(); err != nil {
			Error("Failed to read gzip flags from payload header: %v", err)
			return
		}
		if srcPort, err = stream.ReadUint16(); err != nil {
			Error("Failed to read source port from payload header: %v", err)
			return
		}
		if destPort, err = stream.ReadUint16(); err != nil {
			Error("Failed to read dest port from payload header: %v", err)
			return
		}
		if _, err = stream.ReadByte(); err != nil {
			Error("Failed to read protocol byte from payload header: %v", err)
			return
		}
		if protocol, err = stream.ReadByte(); err != nil {
			Error("Failed to read protocol from payload header: %v", err)
			return
		}
		Debug("Dispatching message payload: protocol=%d, srcPort=%d, destPort=%d, size=%d", protocol, srcPort, destPort, payload.Len())
		session.dispatchMessage(srcDest, protocol, srcPort, destPort, &Stream{payload})
	} else {
		Debug("Empty payload received for session %d", sessionId)
	}
}

func (c *Client) onMsgStatus(stream *Stream) {
	var status uint8
	var sessionId uint16
	var messageId, size, nonce uint32
	var err error
	Debug("Received MessageStatus message")
	sessionId, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from MessageStatus: %v", err)
		return
	}
	messageId, err = stream.ReadUint32()
	if err != nil {
		Error("Failed to read message ID from MessageStatus: %v", err)
		return
	}
	status, err = stream.ReadByte()
	if err != nil {
		Error("Failed to read status from MessageStatus: %v", err)
		return
	}
	size, err = stream.ReadUint32()
	if err != nil {
		Error("Failed to read size from MessageStatus: %v", err)
		return
	}
	nonce, err = stream.ReadUint32()
	if err != nil {
		Error("Failed to read nonce from MessageStatus: %v", err)
		return
	}
	Debug("Message status; session id %d, message id %d, status %d, size %d, nonce %d", sessionId, messageId, status, size, nonce)

	// Find session and dispatch status if available
	c.lock.Lock()
	sess := c.sessions[sessionId]
	c.lock.Unlock()
	if sess != nil {
		// Dispatch message status to session callbacks
		// I2CP 0.9.4+ MessageStatusMessage (type 22) - supports status codes 0-23
		sess.dispatchMessageStatus(messageId, SessionMessageStatus(status), size, nonce)
	} else {
		Warning("MessageStatus received for unknown session %d", sessionId)
	}
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
	requestId = c.lookup[b32]
	delete(c.lookup, b32)
	lup = c.lookupReq[requestId]
	delete(c.lookupReq, requestId)
	if lup == (LookupEntry{}) {
		Warning("No sesssion for destination lookup of address '%s'", b32)
	} else {
		lup.session.dispatchDestination(requestId, b32, destination)
	}
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
	var err error

	// Read client bandwidth limits (bytes/second)
	clientInbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read client inbound limit: %v", err)
		return
	}

	clientOutbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read client outbound limit: %v", err)
		return
	}

	// Read router bandwidth limits (bytes/second)
	routerInbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router inbound limit: %v", err)
		return
	}

	routerInboundBurst, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router inbound burst: %v", err)
		return
	}

	routerOutbound, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router outbound limit: %v", err)
		return
	}

	routerOutboundBurst, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read router outbound burst: %v", err)
		return
	}

	burstTime, err := stream.ReadUint32()
	if err != nil {
		Error("Failed to read burst time: %v", err)
		return
	}

	// Read 9 undefined/reserved fields (uint32 each)
	// These are reserved for future protocol extensions
	undefined := make([]uint32, 9)
	for i := 0; i < 9; i++ {
		undefined[i], err = stream.ReadUint32()
		if err != nil {
			Error("Failed to read undefined field %d: %v", i, err)
			return
		}
	}

	Debug("BandwidthLimits - Client: in=%d out=%d, Router: in=%d(%d) out=%d(%d) burst=%d",
		clientInbound, clientOutbound,
		routerInbound, routerInboundBurst,
		routerOutbound, routerOutboundBurst,
		burstTime)

	// Create BandwidthLimits structure with parsed values
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

func (c *Client) onMsgSessionStatus(stream *Stream) {
	var sess *Session
	var sessionID uint16
	var sessionStatus uint8
	var err error
	Debug("Received SessionStatus message.")

	// DEBUG: Dump raw message bytes
	rawBytes := stream.Bytes()
	Debug("SessionStatus raw bytes (length=%d): %v", len(rawBytes), rawBytes)

	// CRITICAL FIX: I2CP SessionStatus message format is [sessionID: uint16][status: uint8]
	// This is the CORRECT Java I2P router format (confirmed by testing)
	// Previous comment claiming [status][sessionID] order was WRONG
	sessionID, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from SessionStatus: %v", err)
		return
	}
	sessionStatus, err = stream.ReadByte()
	if err != nil {
		Error("Failed to read session status from SessionStatus after sessionID %d: %v", sessionID, err)
		return
	}
	Debug("SessionStatus for session %d: status %d", sessionID, sessionStatus)
	if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_CREATED {
		if c.currentSession == nil {
			Error("Received session status created without waiting for it %p", c)
			return
		}
		// CRITICAL FIX: I2CP spec § Session ID - Validate session ID is not 0xFFFF (reserved "no session" marker)
		if sessionID == I2CP_SESSION_ID_NONE {
			Error("Router assigned reserved session ID 0xFFFF - spec violation")
			return
		}
		c.currentSession.id = sessionID
		Debug("Assigned session ID %d to session %p", sessionID, c.currentSession)

		// CRITICAL FIX: Register session in map BEFORE dispatching callback
		// This prevents race condition where router sends RequestVariableLeaseSet
		// immediately after SessionStatus(CREATED), and onMsgReqVariableLease()
		// tries to lookup the session before registration completes.
		// See: GO-I2CP RACE CONDITION FIX - SESSION REGISTRATION TIMING ISSUE
		c.lock.Lock()

		// MAJOR FIX: Multi-session tracking per I2CP spec § Multi-Session (as of 0.9.21)
		// Track first session as primary, subsequent sessions as subsessions
		if c.primarySessionID == nil {
			// This is the first session - mark as primary
			id := sessionID
			c.primarySessionID = &id
			c.currentSession.isPrimary = true
			c.currentSession.primarySession = nil // Primary has no parent
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

		// Now dispatch status callback - session is already registered and can
		// handle incoming RequestVariableLeaseSet and other messages
		sess.dispatchStatus(SessionStatus(sessionStatus))
	} else {
		// For non-CREATED status updates, session should already exist
		c.lock.Lock()
		sess = c.sessions[sessionID]
		if sess == nil {
			// CRITICAL FIX: Handle router rejecting session creation
			// When router rejects CreateSession, it sends SessionStatus(DESTROYED) as the first message
			// In this case, the session was never registered (no CREATED status was received)
			// The session exists in c.currentSession but not in c.sessions map
			if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED && c.currentSession != nil {
				Debug("Router rejected session creation for sessionID %d (received DESTROYED without CREATED)", sessionID)
				sess = c.currentSession
				// Assign the router-assigned ID before dispatching callback
				sess.id = sessionID
				c.currentSession = nil // Clear currentSession
				c.lock.Unlock()        // Release lock before callback
				sess.dispatchStatus(SessionStatus(sessionStatus))
			} else {
				c.lock.Unlock() // Release lock before Fatal
				Fatal("Session with id %d doesn't exists in client instance %p.", sessionID, c)
			}
		} else {
			// I2CP SPEC COMPLIANCE: Signal destroyConfirmed when DESTROYED status received
			if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED {
				if sess.destroyConfirmed != nil {
					close(sess.destroyConfirmed)
					sess.destroyConfirmed = nil // Prevent double-close
				}
			}
			c.lock.Unlock() // Release lock before callback
			sess.dispatchStatus(SessionStatus(sessionStatus))
		}
	}
}

func (c *Client) onMsgReqVariableLease(stream *Stream) {
	var sessionId uint16
	var tunnels uint8
	var sess *Session
	var leases []*Lease
	var err error
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
	c.msgCreateLeaseSet(sessionId, sess, tunnels, leases, true)
}

func (c *Client) onMsgHostReply(stream *Stream) {
	var result uint8
	var sessionId uint16
	var requestId uint32
	var sess *Session
	var dest *Destination
	var lup LookupEntry
	var err error
	Debug("Received HostReply message.")

	// Parse message fields
	sessionId, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from HostReply: %v", err)
		return
	}
	requestId, err = stream.ReadUint32()
	if err != nil {
		Error("Failed to read request ID from HostReply: %v", err)
		return
	}
	result, err = stream.ReadByte()
	if err != nil {
		Error("Failed to read result code from HostReply: %v", err)
		return
	}

	// Parse destination if lookup succeeded (result == 0)
	var errorDetail string
	if result == HOST_REPLY_SUCCESS {
		dest, err = NewDestinationFromMessage(stream, c.crypto)
		if err != nil {
			Error("Failed to parse destination from HostReply: %v", err)
			return
		}
		Debug("HostReply lookup succeeded for request %d", requestId)
	} else {
		// MAJOR FIX: Enhanced error handling for all HostReply codes (I2CP 0.9.43+)
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

	// Find session
	c.lock.Lock()
	sess = c.sessions[sessionId]
	c.lock.Unlock()
	if sess == nil {
		Error("Session with id %d doesn't exist for HostReply", sessionId)
		return
	}

	// Get and remove lookup entry
	c.lock.Lock() // MAJOR FIX: Thread-safe access to lookupReq map
	lup = c.lookupReq[requestId]
	delete(c.lookupReq, requestId)
	c.lock.Unlock()

	if lup.address == "" {
		Warning("No lookup entry found for request ID %d", requestId)
		return
	}

	// Dispatch destination (may be nil if lookup failed)
	sess.dispatchDestination(requestId, lup.address, dest)
}

// validateReconfigureProperties validates reconfiguration property values per I2CP specification.
// This prevents invalid values (negative counts, excessive tunnel quantities) from being applied
// to session configuration, matching Java router validation behavior.
func validateReconfigureProperties(properties map[string]string) error {
	for key, value := range properties {
		// Validate tunnel quantities (must be 0-16 per I2CP spec)
		if strings.HasSuffix(key, ".quantity") {
			quantity, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid tunnel quantity value '%s' for %s: %w", value, key, err)
			}
			if quantity < 0 || quantity > 16 {
				return fmt.Errorf("tunnel quantity %d out of range [0, 16] for %s", quantity, key)
			}
		}

		// Validate tunnel lengths (must be 0-7 per I2CP spec)
		if strings.HasSuffix(key, ".length") {
			length, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid tunnel length value '%s' for %s: %w", value, key, err)
			}
			if length < 0 || length > 7 {
				return fmt.Errorf("tunnel length %d out of range [0, 7] for %s", length, key)
			}
		}

		// Validate length variance (must be 0-3 per I2CP spec)
		if strings.HasSuffix(key, ".lengthVariance") {
			variance, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid length variance value '%s' for %s: %w", value, key, err)
			}
			if variance < 0 || variance > 3 {
				return fmt.Errorf("length variance %d out of range [0, 3] for %s", variance, key)
			}
		}
	}

	return nil
}

// onMsgReconfigureSession handles ReconfigureSessionMessage (type 2) for dynamic session updates
// per I2CP specification section 7.1 - supports runtime tunnel and crypto parameter changes
func (c *Client) onMsgReconfigureSession(stream *Stream) {
	var sessionId uint16
	var sess *Session
	var err error

	Debug("Received ReconfigureSessionMessage")

	// Read session ID
	sessionId, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from ReconfigureSessionMessage: %v", err)
		return
	}

	// Find session
	c.lock.Lock()
	sess = c.sessions[sessionId]
	c.lock.Unlock()
	if sess == nil {
		Error("ReconfigureSessionMessage received for unknown session ID %d", sessionId)
		return
	}

	// Read properties mapping
	properties, err := stream.ReadMapping()
	if err != nil {
		Error("Failed to read properties mapping from ReconfigureSessionMessage: %v", err)
		return
	}

	Debug("Reconfiguring session %d with %d properties", sessionId, len(properties))

	// Validate property values before applying
	if err := validateReconfigureProperties(properties); err != nil {
		Error("Invalid reconfiguration properties for session %d: %v", sessionId, err)
		return
	}

	// Apply properties to session configuration
	if sess.config != nil {
		for key, value := range properties {
			// Convert property key to internal property enum
			prop := sess.config.propFromString(key)
			if prop >= 0 && prop < NR_OF_SESSION_CONFIG_PROPERTIES {
				sess.config.SetProperty(prop, value)
				Debug("Updated session %d property %s = %s", sessionId, key, value)
			} else {
				Warning("Unknown session property in reconfigure: %s", key)
			}
		}

		// Trigger session status update
		sess.dispatchStatus(I2CP_SESSION_STATUS_UPDATED)
	}
}

// onMsgBlindingInfo handles BlindingInfoMessage (type 42) from router
// per I2CP specification 0.9.43+ - encrypted LeaseSet blinding parameters
func (c *Client) onMsgBlindingInfo(stream *Stream) {
	var err error
	var sessionId uint16
	var authScheme uint8
	var flags uint16

	Debug("Received BlindingInfoMessage")

	// Read session ID
	sessionId, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from BlindingInfoMessage: %v", err)
		return
	}

	// Read authentication scheme
	authScheme, err = stream.ReadByte()
	if err != nil {
		Error("Failed to read auth scheme from BlindingInfoMessage: %v", err)
		return
	}

	// Read flags
	flags, err = stream.ReadUint16()
	if err != nil {
		Error("Failed to read flags from BlindingInfoMessage: %v", err)
		return
	}

	// Read blinding parameter length
	paramLen, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read param length from BlindingInfoMessage: %v", err)
		return
	}

	// Read blinding parameters
	blindingParams := make([]byte, paramLen)
	n, err := stream.Read(blindingParams)
	if err != nil || n != int(paramLen) {
		if err == nil {
			err = fmt.Errorf("expected %d bytes, got %d", paramLen, n)
		}
		Error("Failed to read blinding params from BlindingInfoMessage: %v", err)
		return
	}

	Debug("BlindingInfo for session %d: scheme %d, flags 0x%04x, params %d bytes",
		sessionId, authScheme, flags, paramLen)

	// Find session with proper locking
	c.lock.Lock()
	session, ok := c.sessions[sessionId]
	c.lock.Unlock()

	if !ok {
		Error("Session with id %d doesn't exist for BlindingInfoMessage", sessionId)
		return
	}

	// Store blinding info in session
	session.SetBlindingScheme(uint16(authScheme))
	session.SetBlindingFlags(flags)
	session.SetBlindingParams(blindingParams)

	Debug("Blinding info stored for session %d: enabled=%v", sessionId, session.IsBlindingEnabled())

	// Dispatch to session callback
	session.dispatchBlindingInfo(uint16(authScheme), flags, blindingParams)

	Debug("BlindingInfo callback not yet implemented")
}

func (c *Client) msgCreateLeaseSet(sessionId uint16, session *Session, tunnels uint8, leases []*Lease, queue bool) {
	var err error
	var nullbytes [256]byte
	var leaseSet *Stream
	var config *SessionConfig
	var dest *Destination
	var sgk *SignatureKeyPair
	Debug("Sending CreateLeaseSetMessage")
	leaseSet = NewStream(make([]byte, 4096))
	config = session.config
	dest = config.destination
	sgk = &dest.sgk
	// memset 0 nullbytes
	for i := 0; i < len(nullbytes); i++ {
		nullbytes[i] = 0
	}
	// construct the message
	c.messageStream.WriteUint16(sessionId)
	c.messageStream.Write(nullbytes[:20])
	c.messageStream.Write(nullbytes[:256])
	// Build leaseset stream and sign it
	dest.WriteToMessage(leaseSet)
	leaseSet.Write(nullbytes[:256])
	c.crypto.WritePublicSignatureToStream(sgk, leaseSet)
	leaseSet.WriteByte(tunnels)
	for i := uint8(0); i < tunnels; i++ {
		leases[i].WriteToMessage(leaseSet)
	}
	c.crypto.SignStream(sgk, leaseSet)
	c.messageStream.Write(leaseSet.Bytes())
	if err = c.sendMessage(I2CP_MSG_CREATE_LEASE_SET, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet")
	}
}

// msgCreateLeaseSet2 sends CreateLeaseSet2Message (type 41) for modern LeaseSet creation
// per I2CP specification 0.9.39+ - supports LS2/EncryptedLS/MetaLS with modern crypto
func (c *Client) msgCreateLeaseSet2(session *Session, leaseCount int, queue bool) error {
	var err error
	var leaseSet *Stream
	var config *SessionConfig
	var dest *Destination
	var sgk *SignatureKeyPair

	Debug("Sending CreateLeaseSet2Message for session %d with %d leases", session.id, leaseCount)

	leaseSet = NewStream(make([]byte, 4096))
	config = session.config
	dest = config.destination
	sgk = &dest.sgk

	c.messageStream.Reset()
	c.messageStream.WriteUint16(session.id)

	// Build LeaseSet2 stream with modern format
	// Determine LeaseSet2 type based on blinding configuration (I2CP 0.9.43+)
	var leaseSetType uint8
	if session.IsBlindingEnabled() {
		leaseSetType = LEASESET_TYPE_ENCRYPTED // Encrypted LeaseSet2 with blinding
		Debug("Creating encrypted LeaseSet2 with blinding for session %d", session.id)
	} else {
		leaseSetType = LEASESET_TYPE_STANDARD // Standard LeaseSet2
		Debug("Creating standard LeaseSet2 for session %d", session.id)
	}
	leaseSet.WriteByte(leaseSetType)

	// Destination
	dest.WriteToMessage(leaseSet)

	// Published timestamp (8 bytes)
	leaseSet.WriteUint64(uint64(c.router.date))

	// Expires timestamp (8 bytes) - 10 minutes from published
	expires := uint64(c.router.date) + 600000 // 10 minutes in milliseconds
	leaseSet.WriteUint64(expires)

	// Flags (2 bytes) - set offline signature flag if needed
	var flags uint16 = 0
	// Add blinding flags if blinding is enabled
	if session.IsBlindingEnabled() {
		flags |= session.BlindingFlags()
	}
	leaseSet.WriteUint16(flags)

	// Properties (mapping) - include blinding info if enabled
	properties := make(map[string]string)
	if session.IsBlindingEnabled() {
		// Include blinding parameters in properties per I2CP 0.9.43+ spec
		properties["blinding.scheme"] = fmt.Sprintf("%d", session.BlindingScheme())
		Debug("Added blinding scheme %d to LeaseSet2 properties", session.BlindingScheme())
	}
	if err = leaseSet.WriteMapping(properties); err != nil {
		Error("Failed to write properties to LeaseSet2: %v", err)
		return fmt.Errorf("failed to write properties: %w", err)
	}

	// Number of leases (1 byte)
	leaseSet.WriteByte(uint8(leaseCount))

	// Note: Actual lease data would be added by router in response to RequestVariableLeaseSetMessage
	// For now, we create placeholder leases
	for i := 0; i < leaseCount; i++ {
		// Gateway hash (32 bytes) - placeholder
		nullGateway := make([]byte, 32)
		leaseSet.Write(nullGateway)

		// Tunnel ID (4 bytes) - placeholder
		leaseSet.WriteUint32(uint32(i + 1))

		// End date (8 bytes) - 5 minutes from now
		leaseEndDate := uint64(c.router.date) + 300000 // 5 minutes
		leaseSet.WriteUint64(leaseEndDate)
	}

	// For encrypted LeaseSet2 with blinding, write blinding parameters after leases
	// per I2CP 0.9.43+ specification
	if session.IsBlindingEnabled() {
		blindingParams := session.BlindingParams()
		if len(blindingParams) > 0 {
			// Write length-prefixed blinding parameters
			leaseSet.WriteUint16(uint16(len(blindingParams)))
			leaseSet.Write(blindingParams)
			Debug("Added %d bytes of blinding parameters to LeaseSet2", len(blindingParams))
		} else {
			// No blinding parameters - write zero length
			leaseSet.WriteUint16(0)
			Debug("Blinding enabled but no parameters present, wrote zero-length")
		}
	}

	// Signature - sign the entire LeaseSet2 with destination's signing key
	c.crypto.SignStream(sgk, leaseSet)

	// Write LeaseSet2 to message stream
	c.messageStream.Write(leaseSet.Bytes())

	// Send message
	if err = c.sendMessage(I2CP_MSG_CREATE_LEASE_SET2, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet2Message: %v", err)
		return fmt.Errorf("failed to send CreateLeaseSet2Message: %w", err)
	}

	Debug("Successfully sent CreateLeaseSet2Message for session %d", session.id)
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
	Debug("Sending CreateSessionMessage")

	// Build the session config message first (this sets config.date)
	c.messageStream.Reset()
	config.writeToMessage(c.messageStream, c.crypto, c)

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

	if err = c.sendMessage(I2CP_MSG_CREATE_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending CreateSessionMessage.")
		return err
	}
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

	// COMPLIANCE FIX: Cascade destroy subsessions when primary is destroyed (I2CP § Multisession Notes)
	c.lock.Lock()
	if sess.isPrimary {
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
	c.lock.Unlock()

	Debug("Sending DestroySessionMessage for session %d (primary: %v)", sess.id, sess.isPrimary)
	c.messageStream.Reset()
	c.messageStream.WriteUint16(sess.id)

	if err := c.sendMessage(I2CP_MSG_DESTROY_SESSION, c.messageStream, queue); err != nil {
		Error("Error while sending DestroySessionMessage: %v", err)
		return err
	}

	// SPEC COMPLIANCE: Wait for SessionStatus(Destroyed) OR timeout for non-compliant routers
	// Dual-path handling supports both spec-compliant routers and Java I2P's deviant behavior
	wasPrimary := sess.isPrimary
	if sess.destroyConfirmed != nil {
		select {
		case <-sess.destroyConfirmed:
			Debug("Session %d destruction confirmed via SessionStatus(Destroyed)", sess.id)
		case <-time.After(2 * time.Second):
			// Timeout - router did not send SessionStatus(Destroyed)
			if wasPrimary {
				Debug("DestroySession timeout for primary session %d - router may send DisconnectMessage (Java I2P behavior)", sess.id)
			} else {
				Debug("DestroySession timeout for subsession %d - router did not respond (expected for Java I2P)", sess.id)
			}
		}
	}

	// CRITICAL FIX: Per I2CP § DestroySessionMessage Notes (0.9.67):
	// "Destroying the primary session will, however, destroy all subsessions and stop the I2CP connection."
	if wasPrimary {
		Debug("Primary session destroyed - closing I2CP connection per spec requirement")
		return c.Close()
	}

	return nil
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

	// MAJOR FIX: Validate flags per I2CP spec § SendMessageExpiresMessage
	// Bits 15-11 must be zero (reserved)
	const SEND_MSG_FLAGS_RESERVED_MASK uint16 = 0xF800
	if flags&SEND_MSG_FLAGS_RESERVED_MASK != 0 {
		return fmt.Errorf("invalid SendMessageExpires flags: reserved bits set (0x%04x)", flags)
	}

	// SPEC COMPLIANCE: Bits 10-9 are deprecated reliability override ("to be removed" per spec)
	// Reject these rather than just warning, as spec indicates removal
	const SEND_MSG_FLAGS_RELIABILITY_MASK uint16 = 0x0600
	if flags&SEND_MSG_FLAGS_RELIABILITY_MASK != 0 {
		return fmt.Errorf("deprecated reliability override flags (bits 10-9) no longer supported per I2CP spec")
	}

	// SPEC COMPLIANCE: Validate tag threshold (bits 7-4) - must be 0-15
	tagThreshold := (flags >> 4) & 0x0F
	if tagThreshold > 15 {
		return fmt.Errorf("invalid tag threshold: %d (max 15)", tagThreshold)
	}

	// SPEC COMPLIANCE: Validate tag count (bits 3-0) - must be 0-15
	tagCount := flags & 0x0F
	if tagCount > 15 {
		return fmt.Errorf("invalid tag count: %d (max 15)", tagCount)
	}

	// Log interpreted flag values for debugging
	noLeaseSet := (flags & 0x0100) != 0
	Debug("SendMessageExpires flags: noLeaseSet=%v, tagThreshold=%d, tagCount=%d",
		noLeaseSet, tagThreshold, tagCount)

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
	c.messageStream.WriteUint16(flags)
	c.messageStream.WriteUint64(expirationSeconds)

	// Validate total message size per I2CP specification (max 64KB)
	totalMessageSize := c.messageStream.Len()
	if totalMessageSize > I2CP_MAX_MESSAGE_PAYLOAD_SIZE {
		return fmt.Errorf("total I2CP message size %d exceeds maximum %d bytes (compressed payload size: %d bytes)",
			totalMessageSize, I2CP_MAX_MESSAGE_PAYLOAD_SIZE, out.Len())
	}
	// MINOR FIX: Warn if exceeding conservative size - spec says "about 64KB" (router-dependent)
	if totalMessageSize > I2CP_SAFE_MESSAGE_SIZE {
		Warning("SendMessageExpires size %d exceeds conservative limit %d bytes (max %d), some routers may reject",
			totalMessageSize, I2CP_SAFE_MESSAGE_SIZE, I2CP_MAX_MESSAGE_PAYLOAD_SIZE)
	}

	if err := c.sendMessage(I2CP_MSG_SEND_MESSAGE_EXPIRES, c.messageStream, queue); err != nil {
		Error("Error while sending SendMessageExpiresMessage: %v", err)
		return fmt.Errorf("failed to send SendMessageExpiresMessage: %w", err)
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
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before connect: %w", err)
	}

	Info("Client connecting to i2cp at %s:%s", c.properties["i2cp.tcp.host"], c.properties["i2cp.tcp.port"])

	// Setup TLS if enabled (I2CP 0.8.3+ authentication method 2)
	if c.properties["i2cp.SSL"] == "true" {
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
	}

	// Establish TCP/TLS connection
	err := c.tcp.Connect()
	if err != nil {
		c.trackError("network")
		return fmt.Errorf("failed to connect TCP: %w", err)
	}

	// Set up cleanup on error - ensures TCP disconnects if any subsequent step fails
	// This implements the defer cleanup pattern from PLAN.md section 1.3 task 2
	success := false
	defer func() {
		if !success {
			Debug("Connect failed - cleaning up TCP connection")
			c.tcp.Disconnect()
			c.connected = false
		}
	}()

	// Check context after TCP connect
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled after TCP connect: %w", err)
	}

	// Send protocol initialization byte
	c.outputStream.Reset()
	c.outputStream.WriteByte(I2CP_PROTOCOL_INIT)

	// Use circuit breaker if available
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

	Debug("Sending protocol byte message")

	// Send GetDate message
	c.msgGetDate(false)

	// Receive SetDate response with context checking
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

	c.connected = true
	success = true

	// Update metrics connection state
	if c.metrics != nil {
		c.metrics.SetConnectionState("connected")
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
func (c *Client) CreateSession(ctx context.Context, sess *Session) error {
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	// Validate parameters
	if sess == nil {
		return fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before session creation: %w", err)
	}

	if c.n_sessions == I2CP_MAX_SESSIONS_PER_CLIENT {
		Warning("Maximum number of session per client connection reached.")
		return ErrMaxSessionsReached
	}

	// Multi-session support (I2CP 0.9.21+)
	// If this is a subsession, validate router support and inherit primary configuration
	if !sess.IsPrimary() {
		primary := sess.PrimarySession()
		if primary == nil {
			return fmt.Errorf("subsession requires a primary session reference")
		}

		// Check router version supports multi-session
		if c.router.version.compare(Version{major: 0, minor: 9, micro: 21, qualifier: 0}) < 0 {
			return fmt.Errorf("router version %v does not support multi-session (requires >= 0.9.21)", c.router.version)
		}

		// Inherit all configuration from primary session
		// Per Java I2P reference: ClientMessageEventListener.java:280-388
		// "all the primary options, then the overrides from the alias"
		if primary.config != nil {
			// Copy all properties from primary to subsession
			for i := SessionConfigProperty(0); i < NR_OF_SESSION_CONFIG_PROPERTIES; i++ {
				value := primary.config.GetProperty(i)
				if value != "" {
					sess.config.SetProperty(i, value)
				}
			}
			Debug("Subsession inherited configuration from primary session %d", primary.ID())
		}

		// Override tunnel settings for subsessions - they share primary's tunnels
		// Per I2CP 0.9.21+ spec: subsessions do NOT create their own tunnels
		sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_LENGTH, "0")
		sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_LENGTH, "0")
		sess.config.SetProperty(SESSION_CONFIG_PROP_INBOUND_QUANTITY, "0")
		sess.config.SetProperty(SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "0")
		Debug("Subsession tunnel creation disabled (sharing primary's tunnels)")
	}

	// Set fastReceive mode only if router supports it (I2CP 0.9.4+)
	// Modern routers send PayloadMessage (type 31) instead of deprecated
	// ReceiveMessageBegin/End (types 6/7) messages
	if c.router.version.compare(Version{major: 0, minor: 9, micro: 4, qualifier: 0}) >= 0 {
		sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		Debug("Router %v supports fastReceive mode", c.router.version)
	} else {
		// Legacy router - do not set fastReceive, expecting ReceiveMessageBegin/End
		Warning("Router version %v does not support fastReceive mode (requires >= 0.9.4)", c.router.version)
	}

	sess.config.SetProperty(SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY, "none")

	err := c.msgCreateSession(sess.config, false)
	if err != nil {
		return fmt.Errorf("failed to send CreateSession message: %w", err)
	}

	c.currentSession = sess

	// NOTE: The SessionStatus response will be received and processed by ProcessIO.
	// The session will be registered in onMsgSessionStatus when the router responds.
	// The OnStatus callback will be invoked with I2CP_SESSION_STATUS_CREATED.
	Debug("CreateSession message sent for session, awaiting response via ProcessIO")

	// Update metrics for pending session
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
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	// Check context before processing
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before ProcessIO: %w", err)
	}

	// Check shutdown signal
	select {
	case <-c.shutdown:
		return ErrClientClosed
	default:
	}

	// Process output queue
	c.lock.Lock()
	for _, stream := range c.outputQueue {
		// Check context during queue processing
		if err := ctx.Err(); err != nil {
			c.lock.Unlock()
			return fmt.Errorf("context cancelled during output queue processing: %w", err)
		}

		Debug("Sending %d bytes message", stream.Len())

		var ret int
		var sendErr error
		// Use circuit breaker if available
		if c.circuitBreaker != nil {
			sendErr = c.circuitBreaker.Execute(func() error {
				var err error
				ret, err = c.tcp.Send(stream)
				return err
			})
		} else {
			ret, sendErr = c.tcp.Send(stream)
		}

		if ret < 0 {
			c.lock.Unlock()
			return fmt.Errorf("failed to send queued message: %w", sendErr)
		}
		if ret == 0 {
			break
		}
	}
	// Clear processed messages from queue
	c.outputQueue = make([]*Stream, 0)
	c.lock.Unlock()

	// Process incoming messages
	var err error
	for c.tcp.CanRead() {
		// Check context during message receive loop
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled during message receive: %w", err)
		}

		// Check shutdown signal
		select {
		case <-c.shutdown:
			return ErrClientClosed
		default:
		}

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
func (c *Client) DestinationLookup(ctx context.Context, session *Session, address string) (uint32, error) {
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return 0, err
	}

	// Validate parameters
	if session == nil {
		return 0, fmt.Errorf("session cannot be nil: %w", ErrInvalidArgument)
	}
	if address == "" {
		return 0, fmt.Errorf("address cannot be empty: %w", ErrInvalidArgument)
	}

	// Check context before starting
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context cancelled before lookup: %w", err)
	}

	var out *Stream
	var lup LookupEntry
	b32Len := 56 + 8 // base32-encoded 32-byte hash (56 chars with padding) + ".b32.i2p" (8 chars)
	defaultTimeout := uint32(30000)
	routerCanHostLookup := (c.router.capabilities & ROUTER_CAN_HOST_LOOKUP) == ROUTER_CAN_HOST_LOOKUP

	if !routerCanHostLookup && len(address) != b32Len {
		Warning("Address '%s' is not a b32 address %d.", address, len(address))
		return 0, ErrInvalidDestination
	}

	if len(address) == b32Len {
		Debug("Lookup of b32 address detected, decode and use hash for faster lookup.")
		host := address[:strings.Index(address, ".")]
		// Use common/base32 to decode I2P base32 address
		var decodeErr error
		var decodedBytes []byte
		decodedBytes, decodeErr = base32.DecodeString(host)
		if decodeErr != nil || len(decodedBytes) == 0 {
			Warning("Failed to decode hash of address '%s'", address)
			return 0, fmt.Errorf("failed to decode b32 address: %w", decodeErr)
		}
		out = NewStream(decodedBytes)
	}

	lup = LookupEntry{address: address, session: session}

	// MAJOR FIX: Thread-safe access to lookupReq map (I2CP HostLookup race condition)
	c.lock.Lock()
	c.lookupRequestId += 1
	requestId := c.lookupRequestId
	c.lookupReq[requestId] = lup
	c.lock.Unlock()

	// Check context before sending lookup
	if err := ctx.Err(); err != nil {
		c.lock.Lock()
		delete(c.lookupReq, requestId)
		c.lock.Unlock()
		return 0, fmt.Errorf("context cancelled before sending lookup: %w", err)
	}

	if routerCanHostLookup {
		var err error
		if out == nil || out.Len() == 0 {
			err = c.msgHostLookup(session, requestId, defaultTimeout, HOST_LOOKUP_TYPE_HOSTNAME, []byte(address), true)
		} else {
			err = c.msgHostLookup(session, requestId, defaultTimeout, HOST_LOOKUP_TYPE_HASH, out.Bytes(), true)
		}
		if err != nil {
			c.lock.Lock()
			delete(c.lookupReq, requestId)
			c.lock.Unlock()
			return 0, fmt.Errorf("failed to send host lookup: %w", err)
		}
	} else {
		// MINOR FIX: Warn when falling back to deprecated DestLookup for old routers
		Warning("Router version %v < 0.9.11 detected, using deprecated DestLookup (HostLookup unavailable)", c.router.version)
		c.lock.Lock()
		c.lookup[address] = requestId
		c.lock.Unlock()
		c.msgDestLookup(out.Bytes(), true)
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
func (c *Client) Close() error {
	// Ensure client was properly initialized with NewClient()
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	Info("Closing client %p", c)

	// Signal shutdown to all operations
	select {
	case <-c.shutdown:
		// Already closed
		return ErrClientClosed
	default:
		close(c.shutdown)
	}

	// Destroy all sessions (only if connected)
	if c.tcp.IsConnected() {
		c.lock.Lock()
		for sessionId, sess := range c.sessions {
			Debug("Destroying session %d during shutdown", sessionId)
			if err := c.msgDestroySession(sess, false); err != nil {
				Warning("Failed to destroy session %d during shutdown: %v", sessionId, err)
			}
		}
		c.lock.Unlock()
	}

	// Wait for pending operations with timeout
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

	// Close TCP connection
	c.tcp.Disconnect()
	c.connected = false

	// Update metrics connection state
	if c.metrics != nil {
		c.metrics.SetConnectionState("disconnected")
		c.metrics.SetActiveSessions(0)
	}

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
