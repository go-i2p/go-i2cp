package go_i2cp

import (
"context"
"fmt"
"strings"

"github.com/go-i2p/common/base32"
)

func (c *Client) msgDestLookup(hash []byte, queue bool) {
	Debug("Sending DestLookupMessage.")

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.messageStream.Reset()
	c.messageStream.Write(hash)
	if err := c.sendMessage(I2CP_MSG_DEST_LOOKUP, c.messageStream, queue); err != nil {
		Error("Error while sending DestLookupMessage.")
	}
}

func (c *Client) msgHostLookup(sess *Session, requestId, timeout uint32, typ uint8, data []byte, queue bool) error {
	// Version check: HostLookup requires router 0.9.11+
	if !c.SupportsVersion(VersionHostLookup) {
		return fmt.Errorf("router version %s does not support HostLookup (requires %s+), use DestLookup instead",
			c.router.version.String(), VersionHostLookup.String())
	}

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

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
	hashStream, err := c.validateAndPrepareLookup(ctx, session, address)
	if err != nil {
		return 0, err
	}

	return c.executeAndRegisterLookup(ctx, session, address, hashStream)
}

// validateAndPrepareLookup performs all validation checks and prepares the address hash for lookup.
func (c *Client) validateAndPrepareLookup(ctx context.Context, session *Session, address string) (*Stream, error) {
	if err := c.ensureInitialized(); err != nil {
		return nil, err
	}

	if err := validateLookupParameters(ctx, session, address); err != nil {
		return nil, err
	}

	if err := c.validateLookupAddress(address); err != nil {
		return nil, err
	}

	return decodeB32Address(address)
}

// executeAndRegisterLookup registers the lookup request and executes it, with proper cleanup on failure.
func (c *Client) executeAndRegisterLookup(ctx context.Context, session *Session, address string, hashStream *Stream) (uint32, error) {
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

