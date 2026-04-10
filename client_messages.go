package go_i2cp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/go-i2p/common/base32"
)

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

// onMsgDisconnect handles disconnect messages from the router per I2CP specification.
func (c *Client) onMsgDisconnect(stream *Stream) {
	reason, err := c.readDisconnectReason(stream)
	if err != nil {
		Error("Could not read msgDisconnect correctly data")
	}

	c.recordDisconnectDebugInfo(reason, []byte(reason))
	c.updateSessionStatesOnDisconnect(reason)
	c.invokeDisconnectCallback(reason)

	c.connected = false
	c.attemptAutoReconnect()
}

// readDisconnectReason extracts the disconnect reason string from the message stream.
func (c *Client) readDisconnectReason(stream *Stream) (string, error) {
	Debug("Received Disconnect message")
	strbuf := make([]byte, stream.Len())
	_, err := stream.Read(strbuf)
	reason := string(strbuf)
	Debug("Received Disconnect message with reason %s", reason)
	return reason, err
}

// recordDisconnectDebugInfo records disconnect events for protocol debugging.
func (c *Client) recordDisconnectDebugInfo(reason string, rawData []byte) {
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		c.protocolDebugger.RecordDisconnect(reason, rawData)
	}
}

// updateSessionStatesOnDisconnect marks all sessions as disconnected in the state tracker.
func (c *Client) updateSessionStatesOnDisconnect(reason string) {
	if c.stateTracker == nil || !c.stateTracker.IsEnabled() {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	for sessionID := range c.sessions {
		c.stateTracker.SetState(sessionID, SessionStateDisconnected, fmt.Sprintf("disconnect: %s", reason))
	}
}

// invokeDisconnectCallback calls the registered disconnect callback if present.
func (c *Client) invokeDisconnectCallback(reason string) {
	if c.callbacks != nil && c.callbacks.OnDisconnect != nil {
		c.callbacks.OnDisconnect(c, reason, nil)
	}
}

// attemptAutoReconnect initiates auto-reconnection if enabled.
func (c *Client) attemptAutoReconnect() {
	c.reconnectMu.Lock()
	shouldReconnect := c.reconnectEnabled
	c.reconnectMu.Unlock()

	if !shouldReconnect {
		return
	}

	go func() {
		Info("Connection lost, attempting auto-reconnect...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		if err := c.autoReconnect(ctx); err != nil {
			Error("Auto-reconnect failed: %v", err)
		}
	}()
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
	payload := bytes.NewBuffer(make([]byte, 0, 0xffff))

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

	session, err := c.readPayloadMessageHeader(stream)
	if err != nil {
		Error("Failed to read payload message header: %v", err)
		return
	}

	protocol, srcPort, destPort, gzipData, err := c.readPayloadWithGzipHeader(stream)
	if err != nil {
		Error("Failed to read payload with gzip header: %v", err)
		return
	}

	payload, err := c.decompressGzipPayload(gzipData)
	if err != nil {
		Error("Failed to decompress payload: %v", err)
		return
	}

	srcDest, payload, err := c.extractSourceDestination(protocol, payload)
	if err != nil {
		Error("Failed to parse source destination: %v", err)
		return
	}

	Debug("Dispatching message payload: protocol=%d, srcPort=%d, destPort=%d, size=%d", protocol, srcPort, destPort, payload.Len())
	session.dispatchMessage(srcDest, protocol, srcPort, destPort, &Stream{payload})
}

// extractSourceDestination extracts source destination for repliable datagrams.
func (c *Client) extractSourceDestination(protocol uint8, payload *bytes.Buffer) (*Destination, *bytes.Buffer, error) {
	if protocol != 17 {
		Debug("Received payload with protocol %d (no embedded source destination)", protocol)
		return nil, payload, nil
	}

	srcDest, newPayload, err := c.parseRepliableDatagramPayload(payload)
	if err != nil {
		return nil, nil, err
	}
	Debug("Message from source: %s", srcDest.Base32())
	return srcDest, newPayload, nil
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
	gzipData, err = c.readGzipPayloadData(stream)
	if err != nil {
		return 0, 0, 0, nil, err
	}

	if err := validateGzipHeaderBytes(gzipData); err != nil {
		return 0, 0, 0, nil, err
	}

	protocol, srcPort, destPort = extractI2CPFieldsFromGzip(gzipData)
	return protocol, srcPort, destPort, gzipData, nil
}

// readGzipPayloadData reads the complete gzip payload from the stream.
func (c *Client) readGzipPayloadData(stream *Stream) ([]byte, error) {
	payloadSize, err := stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read payload size: %w", err)
	}

	if payloadSize == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	gzipData := make([]byte, payloadSize)
	n, err := stream.Read(gzipData)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip payload: %w", err)
	}
	if uint32(n) != payloadSize {
		return nil, fmt.Errorf("incomplete payload read: got %d, expected %d", n, payloadSize)
	}
	return gzipData, nil
}

// validateGzipHeaderBytes checks that the gzip header is valid.
func validateGzipHeaderBytes(gzipData []byte) error {
	if len(gzipData) < 10 {
		return fmt.Errorf("gzip data too short: %d bytes", len(gzipData))
	}
	if gzipData[0] != 0x1f || gzipData[1] != 0x8b || gzipData[2] != 0x08 {
		return fmt.Errorf("invalid gzip header: %x %x %x", gzipData[0], gzipData[1], gzipData[2])
	}
	return nil
}

// extractI2CPFieldsFromGzip extracts protocol and port info from gzip header fields.
func extractI2CPFieldsFromGzip(gzipData []byte) (protocol uint8, srcPort, destPort uint16) {
	srcPort = binary.LittleEndian.Uint16(gzipData[4:6])
	destPort = binary.LittleEndian.Uint16(gzipData[6:8])
	protocol = gzipData[9]
	return
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
	Debug("Received DestReply message.")

	destination, b32, err := c.parseDestReplyPayload(stream)
	if err != nil {
		Fatal("Failed to construct destination from stream")
		return
	}

	requestId, lup, err := c.lookupDestinationRequest(b32)
	if err != nil {
		Warning("%v", err)
		return
	}

	lup.session.dispatchDestination(requestId, b32, destination)
}

// parseDestReplyPayload extracts destination and base32 address from DestReply message.
func (c *Client) parseDestReplyPayload(stream *Stream) (*Destination, string, error) {
	if stream.Len() != 32 {
		destination, err := NewDestinationFromMessage(stream, c.crypto)
		if err != nil {
			return nil, "", err
		}
		return destination, destination.b32, nil
	}

	b32Encoded := base32.EncodeToString(stream.Bytes())
	b32 := b32Encoded + ".b32.i2p"
	Debug("Could not resolve destination")
	return nil, b32, nil
}

// lookupDestinationRequest retrieves and removes pending lookup entries for a destination.
// Thread-safe: uses lock to protect lookup and lookupReq map access.
func (c *Client) lookupDestinationRequest(b32 string) (uint32, LookupEntry, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	requestId, found := c.lookup[b32]
	if !found {
		return 0, LookupEntry{}, fmt.Errorf("no pending lookup found for address '%s'", b32)
	}
	delete(c.lookup, b32)

	lup, lupFound := c.lookupReq[requestId]
	if !lupFound {
		return 0, LookupEntry{}, fmt.Errorf("no lookup entry found for request ID %d (address '%s')", requestId, b32)
	}
	delete(c.lookupReq, requestId)

	if lup.session == nil {
		return 0, LookupEntry{}, fmt.Errorf("lookup entry for '%s' has nil session", b32)
	}

	return requestId, lup, nil
}

// readDeprecatedSessionMessage reads session ID and message ID from a deprecated
// I2CP message stream. Used by legacy ReceiveMessageBegin/End handlers.
func readDeprecatedSessionMessage(stream *Stream, msgName string) (sessionID uint16, messageID uint32, err error) {
	sessionID, err = stream.ReadUint16()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read session ID from %s: %w", msgName, err)
	}
	messageID, err = stream.ReadUint32()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read message ID from %s: %w", msgName, err)
	}
	return sessionID, messageID, nil
}

// onMsgReceiveMessageBegin handles deprecated ReceiveMessageBeginMessage (type 6)
//
// DEPRECATED: This message type is not used in fastReceive mode, which has been
// the default since I2CP 0.9.4. Modern routers and clients exclusively use
// MessagePayloadMessage (type 31) for message delivery.
//
// Protocol History:
//   - I2CP 0.6.x - 0.9.3: Used slow-receive mode requiring BEGIN/END handshake
//   - I2CP 0.9.4+: fastReceive mode became default, this message deprecated
//
// This handler is retained for backward compatibility with legacy routers
// running versions prior to 0.9.4, though such routers are extremely rare.
// When received, a warning is logged but the message is still processed.
func (c *Client) onMsgReceiveMessageBegin(stream *Stream) {
	Warning("Received deprecated ReceiveMessageBeginMessage - fastReceive mode should be used")

	sessionID, messageID, err := readDeprecatedSessionMessage(stream, "ReceiveMessageBegin")
	if err != nil {
		Error("%v", err)
		return
	}

	Debug("ReceiveMessageBegin for session %d, message %d (legacy mode)",
		sessionID, messageID)

	// In legacy slow-receive mode, the client would need to send an acknowledgment
	// However, since fastReceive is default since 0.9.4, we just log this
	// Modern clients should use MessagePayloadMessage (type 31) instead
}

// onMsgReceiveMessageEnd handles deprecated ReceiveMessageEndMessage (type 7)
//
// DEPRECATED: This message type is not used in fastReceive mode, which has been
// the default since I2CP 0.9.4. Modern routers and clients exclusively use
// MessagePayloadMessage (type 31) for message delivery.
//
// Protocol History:
//   - I2CP 0.6.x - 0.9.3: Used slow-receive mode requiring BEGIN/END handshake
//   - I2CP 0.9.4+: fastReceive mode became default, this message deprecated
//
// In the legacy slow-receive protocol flow:
//  1. Router sends ReceiveMessageBegin with message ID
//  2. Client sends ReceiveMessageEnd to acknowledge
//  3. Router sends actual message payload
//
// This handler is retained for backward compatibility with legacy routers.
func (c *Client) onMsgReceiveMessageEnd(stream *Stream) {
	Warning("Received deprecated ReceiveMessageEndMessage - fastReceive mode should be used")

	sessionID, messageID, err := readDeprecatedSessionMessage(stream, "ReceiveMessageEnd")
	if err != nil {
		Error("%v", err)
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
//
// DEPRECATED AND INTENTIONALLY A NO-OP: This message type was defined in the
// original I2CP specification for abuse reporting but was NEVER actually
// implemented in the Java I2P reference implementation.
//
// Per I2CP SPEC.md:
//
//	"DEPRECATED, UNUSED, UNSUPPORTED... Neither router nor client has a handler"
//
// Protocol Status:
//   - Message type 29 is reserved in the I2CP spec
//   - No known router implementation sends this message
//   - No client implementation is expected to handle it meaningfully
//
// This handler exists solely for protocol completeness and logs a warning if
// such a message is ever received (which would indicate a non-conforming router).
// The handler intentionally performs no action beyond logging.
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

// onMsgBandwidthLimit handles BandwidthLimitsMessage (type 23) from router
// per I2CP specification - reports bandwidth limits and burst parameters
// Note: 9 fields are undefined in the spec and reserved for future use
func (c *Client) onMsgBandwidthLimit(stream *Stream) {
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
	if err := c.validateSessionCreation(sessionID); err != nil {
		Error("%v", err)
		return
	}

	// Use sessionMu to protect currentSession access and SetID for thread-safe id assignment
	c.sessionMu.RLock()
	sess := c.currentSession
	c.sessionMu.RUnlock()

	sess.SetID(sessionID)
	Debug("Assigned session ID %d to session %p", sessionID, sess)

	registeredSess := c.registerNewSession(sessionID)
	c.trackSessionCreatedState(sessionID)

	Info(">>> Session %d CREATED - now waiting for RequestVariableLeaseSet (type 37) from router...", sessionID)
	Debug(">>> Session %d created successfully, invoking OnStatus callback with SESSION_STATUS_CREATED", sessionID)
	registeredSess.dispatchStatus(SessionStatus(sessionStatus))
}

// validateSessionCreation checks preconditions for session creation.
// Thread-safe: uses sessionMu to protect currentSession access.
func (c *Client) validateSessionCreation(sessionID uint16) error {
	c.sessionMu.RLock()
	currentSess := c.currentSession
	c.sessionMu.RUnlock()

	if currentSess == nil {
		return fmt.Errorf("received session status created without waiting for it %p", c)
	}
	if sessionID == I2CP_SESSION_ID_NONE {
		return fmt.Errorf("router assigned reserved session ID 0xFFFF - spec violation")
	}
	return nil
}

// registerNewSession registers the session in the sessions map and configures primary/subsession relationship.
// Thread-safe: uses sessionMu to protect currentSession access and lock for sessions map.
func (c *Client) registerNewSession(sessionID uint16) *Session {
	// First, get the current session with sessionMu protection
	c.sessionMu.Lock()
	sess := c.currentSession
	c.currentSession = nil
	c.sessionMu.Unlock()

	// Then update the sessions map with lock protection
	c.lock.Lock()
	defer c.lock.Unlock()

	c.configurePrimarySubsessionForSession(sessionID, sess)

	c.sessions[sessionID] = sess
	return sess
}

// configurePrimarySubsessionForSession sets up primary/subsession tracking per I2CP spec.
// Takes the session as a parameter to avoid accessing currentSession directly.
func (c *Client) configurePrimarySubsessionForSession(sessionID uint16, sess *Session) {
	if c.primarySessionID == nil {
		id := sessionID
		c.primarySessionID = &id
		sess.SetPrimary(true)
		sess.mu.Lock()
		sess.primarySession = nil
		sess.mu.Unlock()
		Debug("Session %d is primary session", sessionID)
		return
	}

	sess.SetPrimary(false)
	if primarySess, exists := c.sessions[*c.primarySessionID]; exists {
		sess.mu.Lock()
		sess.primarySession = primarySess
		sess.mu.Unlock()
		Debug("Session %d is subsession of primary %d", sessionID, *c.primarySessionID)
	} else {
		Warning("Primary session %d not found for subsession %d", *c.primarySessionID, sessionID)
	}
}

// configurePrimarySubsession sets up primary/subsession tracking per I2CP spec.
// Deprecated: Use configurePrimarySubsessionForSession instead for thread safety.
func (c *Client) configurePrimarySubsession(sessionID uint16) {
	c.sessionMu.RLock()
	sess := c.currentSession
	c.sessionMu.RUnlock()

	if sess == nil {
		Error("configurePrimarySubsession called with nil currentSession")
		return
	}

	c.configurePrimarySubsessionForSession(sessionID, sess)
}

// trackSessionCreatedState updates state tracker for newly created session.
func (c *Client) trackSessionCreatedState(sessionID uint16) {
	if c.stateTracker == nil || !c.stateTracker.IsEnabled() {
		return
	}
	c.stateTracker.SetState(sessionID, SessionStateCreated, "SessionStatus CREATED received")
	c.stateTracker.SetState(sessionID, SessionStateAwaitingLeaseSet, "waiting for RequestVariableLeaseSet")
	c.stateTracker.StartLeaseSetWait(sessionID, 120*time.Second)
}

// handleNonCreatedStatus processes status updates for existing sessions or rejected session creation.
// Handles DESTROYED status and other session state changes.
func (c *Client) handleNonCreatedStatus(sessionID uint16, sessionStatus uint8) {
	c.lock.Lock()
	sess := c.sessions[sessionID]

	if sess == nil {
		c.handleMissingSession(sessionID, sessionStatus)
		return
	}

	c.handleExistingSessionStatus(sess, sessionID, sessionStatus)
}

// handleMissingSession processes status for a session that doesn't exist in the sessions map.
// Thread-safe: uses sessionMu to protect currentSession access.
func (c *Client) handleMissingSession(sessionID uint16, sessionStatus uint8) {
	c.sessionMu.RLock()
	currentSess := c.currentSession
	c.sessionMu.RUnlock()

	if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED && currentSess != nil {
		c.handleRejectedSession(sessionID, sessionStatus)
		return
	}
	c.lock.Unlock()
	Fatal("Session with id %d doesn't exists in client instance %p.", sessionID, c)
}

// handleRejectedSession handles the case when the router rejects session creation.
// Thread-safe: uses sessionMu to protect currentSession access and SetID for thread-safe id assignment.
func (c *Client) handleRejectedSession(sessionID uint16, sessionStatus uint8) {
	Debug("Router rejected session creation for sessionID %d (received DESTROYED without CREATED)", sessionID)
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.SetState(sessionID, SessionStateRejected, "session rejected by router")
	}
	Error("❌ Session %d REJECTED by router (SessionStatus=DESTROYED without CREATED)", sessionID)

	c.sessionMu.Lock()
	sess := c.currentSession
	c.currentSession = nil
	c.sessionMu.Unlock()

	sess.SetID(sessionID)
	c.lock.Unlock()
	sess.dispatchStatus(SessionStatus(sessionStatus))
}

// handleExistingSessionStatus processes status updates for an existing session.
func (c *Client) handleExistingSessionStatus(sess *Session, sessionID uint16, sessionStatus uint8) {
	if SessionStatus(sessionStatus) == I2CP_SESSION_STATUS_DESTROYED {
		c.processDestroyedStatus(sess, sessionID)
	}
	c.lock.Unlock()
	sess.dispatchStatus(SessionStatus(sessionStatus))
}

// processDestroyedStatus handles DESTROYED status for an existing session.
func (c *Client) processDestroyedStatus(sess *Session, sessionID uint16) {
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.SetState(sessionID, SessionStateDestroyed, "SessionStatus DESTROYED received")
	}
	if sess.destroyConfirmed != nil {
		close(sess.destroyConfirmed)
		sess.destroyConfirmed = nil
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
	// This is the critical message we're debugging - log prominently
	Info(">>> RECEIVED RequestVariableLeaseSet (type 37) - router is requesting LeaseSet publication!")

	sessionId, tunnels, err := readVariableLeaseHeader(stream)
	if err != nil {
		return
	}

	c.recordLeaseSetRequest(sessionId, tunnels)

	sess, err := c.getSessionForVariableLease(sessionId)
	if err != nil {
		return
	}

	// Check if session is already closed/being destroyed - skip lease set creation
	// This prevents race conditions where a RequestVariableLeaseSet arrives after
	// the session has been destroyed locally but before the router processes our
	// DestroySession message.
	if sess.IsClosed() {
		Debug("Session %d is closed, skipping CreateLeaseSet2", sessionId)
		return
	}

	leases, err := parseVariableLeases(stream, sessionId, tunnels)
	if err != nil {
		return
	}

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

// readVariableLeaseHeader reads the session ID and tunnel count from RequestVariableLeaseSet.
func readVariableLeaseHeader(stream *Stream) (uint16, uint8, error) {
	sessionId, err := stream.ReadUint16()
	if err != nil {
		Error("Failed to read session ID from RequestVariableLeaseSet: %v", err)
		return 0, 0, err
	}
	tunnels, err := stream.ReadByte()
	if err != nil {
		Error("Failed to read tunnel count from RequestVariableLeaseSet: %v", err)
		return sessionId, 0, err
	}
	return sessionId, tunnels, nil
}

// recordLeaseSetRequest updates state tracker when a LeaseSet request is received.
func (c *Client) recordLeaseSetRequest(sessionId uint16, tunnels uint8) {
	Debug("Received RequestVariableLeaseSet message.")
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		c.stateTracker.RecordLeaseSetReceived(sessionId, tunnels)
		c.stateTracker.SetState(sessionId, SessionStateLeaseSetRequested, fmt.Sprintf("tunnels=%d", tunnels))
	}
}

// getSessionForVariableLease retrieves the session for a RequestVariableLeaseSet message.
func (c *Client) getSessionForVariableLease(sessionId uint16) (*Session, error) {
	c.lock.Lock()
	sess := c.sessions[sessionId]
	c.lock.Unlock()
	if sess == nil {
		Error("Session with id %d doesn't exist for RequestVariableLeaseSet", sessionId)
		return nil, fmt.Errorf("session not found")
	}
	return sess, nil
}

// parseVariableLeases parses all leases from a RequestVariableLeaseSet message.
func parseVariableLeases(stream *Stream, sessionId uint16, tunnels uint8) ([]*Lease, error) {
	leases := make([]*Lease, tunnels)
	for i := uint8(0); i < tunnels; i++ {
		lease, err := NewLeaseFromStream(stream)
		if err != nil {
			Error("Failed to parse lease %d/%d for session %d: %v", i+1, tunnels, sessionId, err)
			return nil, err
		}
		leases[i] = lease
	}
	Debug("Parsed %d leases for session %d", tunnels, sessionId)
	return leases, nil
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
//
// I2CP 0.9.66+ Service Record Support (Proposal 167):
//
// Lookup types 2-4 (HOST_LOOKUP_TYPE_*_WITH_OPTIONS) request that the options
// mapping from the LeaseSet be returned along with the destination:
//
//   - Type 2: Hash lookup with options
//   - Type 3: Hostname lookup with options
//   - Type 4: Destination lookup with options
//
// The options Mapping contains service-specific metadata stored in the LeaseSet,
// such as protocol information, alternate addresses, or application-defined data.
//
// Router Version Requirements:
//   - Types 0-1: Supported since I2CP 0.9.11
//   - Types 2-4: Require I2CP 0.9.66+ router (Proposal 167)
//
// If the connected router does not support types 2-4, it may return
// HOST_REPLY_LOOKUP_TYPE_UNSUPPORTED (code 7).
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
	// Get and remove lookup entry (always clean up, even if session is gone)
	if lup.address == "" {
		lup = c.lookupReq[requestId]
	}
	delete(c.lookupReq, requestId)
	// Store parsed service record options in lookup entry
	if options != nil {
		lup.options = options
	}
	c.lock.Unlock()

	if sess == nil {
		Error("Session with id %d doesn't exist for HostReply", sessionId)
		return
	}

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
