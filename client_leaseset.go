package go_i2cp

import "fmt"

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
		WriteLeaseToMessage(leases[i], leaseSet)
	}

	return nil
}

func (c *Client) msgCreateLeaseSet(sessionId uint16, session *Session, tunnels uint8, leases []*Lease, queue bool) {
	Debug("Sending CreateLeaseSetMessage")

	// Thread-safe: protect messageStream access
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

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
	if err := c.checkLeaseSet2Support(); err != nil {
		return err
	}

	Debug("Sending CreateLeaseSet2Message for session %d with %d leases", session.id, leaseCount)

	if err := c.ensureSessionEncryptionKeyPair(session); err != nil {
		return err
	}

	leaseSet := NewStream(make([]byte, 0, 4096))
	dest := session.config.destination

	// Thread-safe: protect messageStream access for entire LeaseSet2 creation
	c.messageStreamMu.Lock()
	defer c.messageStreamMu.Unlock()

	c.prepareLeaseSet2Header(session)

	if err := c.buildLeaseSet2Content(session, leaseSet, dest, leaseCount); err != nil {
		return err
	}

	if err := c.signAndSendLeaseSet2(session, leaseSet, dest, queue); err != nil {
		return err
	}

	Debug("Successfully sent CreateLeaseSet2Message for session %d", session.id)
	return nil
}

// checkLeaseSet2Support verifies the router supports CreateLeaseSet2 messages.
func (c *Client) checkLeaseSet2Support() error {
	if !c.SupportsVersion(VersionCreateLeaseSet2) {
		return fmt.Errorf("router version %s does not support CreateLeaseSet2 (requires %s+)",
			c.router.version.String(), VersionCreateLeaseSet2.String())
	}
	return nil
}

// ensureSessionEncryptionKeyPair generates an X25519 encryption key pair if not present.
// Thread-safe: acquires session.mu to synchronize with cleanupSessionReferences.
func (c *Client) ensureSessionEncryptionKeyPair(session *Session) error {
	session.mu.Lock()
	if session.encryptionKeyPair != nil {
		session.mu.Unlock()
		return nil
	}
	if session.closed {
		session.mu.Unlock()
		Debug("Session %d is closed, skipping encryption key pair generation", session.id)
		return fmt.Errorf("session %d is closed", session.id)
	}
	session.mu.Unlock()

	keyPair, err := NewX25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 encryption key pair: %w", err)
	}

	session.mu.Lock()
	// Re-check after key generation in case session was closed concurrently
	if session.closed {
		session.mu.Unlock()
		Debug("Session %d closed during key generation, discarding key pair", session.id)
		return fmt.Errorf("session %d is closed", session.id)
	}
	session.encryptionKeyPair = keyPair
	session.mu.Unlock()

	Debug("Generated X25519 encryption key pair for session %d", session.id)
	return nil
}

// prepareLeaseSet2Header writes the session ID and LeaseSet type to the message stream.
func (c *Client) prepareLeaseSet2Header(session *Session) {
	c.messageStream.Reset()
	c.messageStream.WriteUint16(session.id)

	leaseSetType := c.determineLeaseSetType(session)
	c.messageStream.WriteByte(leaseSetType)
}

// determineLeaseSetType returns the appropriate LeaseSet type based on blinding configuration.
func (c *Client) determineLeaseSetType(session *Session) uint8 {
	if session.IsBlindingEnabled() {
		Debug("Creating encrypted LeaseSet2 with blinding for session %d", session.id)
		return LEASESET_TYPE_ENCRYPTED
	}
	Debug("Creating standard LeaseSet2 for session %d", session.id)
	return LEASESET_TYPE_STANDARD
}

// buildLeaseSet2Content constructs the complete LeaseSet2 content including header, timestamps, flags, properties, encryption keys, leases, and blinding parameters.
func (c *Client) buildLeaseSet2Content(session *Session, leaseSet *Stream, dest *Destination, leaseCount int) error {
	if err := c.writeLeaseSet2HeaderAndTimestamps(session, leaseSet, dest); err != nil {
		return err
	}

	if err := c.writeLeaseSet2FlagsAndProperties(session, leaseSet); err != nil {
		return err
	}

	if err := c.writeLeaseSet2KeysAndLeases(session, leaseSet, leaseCount); err != nil {
		return err
	}

	return c.writeLeaseSet2BlindingParams(session, leaseSet)
}

// writeLeaseSet2HeaderAndTimestamps writes the destination and timestamps to the LeaseSet stream.
func (c *Client) writeLeaseSet2HeaderAndTimestamps(session *Session, leaseSet *Stream, dest *Destination) error {
	if err := c.writeLeaseSet2Header(session, leaseSet, dest); err != nil {
		return err
	}
	Debug("LeaseSet2 after destination: %d bytes", leaseSet.Len())

	if err := c.writeLeaseSet2Timestamps(leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after timestamps: %d bytes", leaseSet.Len())
	return nil
}

// writeLeaseSet2FlagsAndProperties writes the flags and properties fields to the stream.
func (c *Client) writeLeaseSet2FlagsAndProperties(session *Session, leaseSet *Stream) error {
	if err := c.writeLeaseSet2Flags(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after flags: %d bytes", leaseSet.Len())

	if err := c.writeLeaseSet2Properties(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after properties: %d bytes", leaseSet.Len())
	Debug("LeaseSet2 bytes 391-401: %x", leaseSet.Bytes()[391:401])
	return nil
}

// writeLeaseSet2KeysAndLeases writes the encryption keys and leases to the stream.
func (c *Client) writeLeaseSet2KeysAndLeases(session *Session, leaseSet *Stream, leaseCount int) error {
	if err := c.writeLeaseSet2EncryptionKeys(session, leaseSet); err != nil {
		return err
	}
	Debug("LeaseSet2 after enc keys: %d bytes", leaseSet.Len())
	Debug("LeaseSet2 bytes 401-436: %x", leaseSet.Bytes()[401:436])

	return c.writeLeaseSet2Leases(session, leaseSet, leaseCount)
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
			if err := WriteLeaseToLeaseSet2(leases[i], leaseSet); err != nil {
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

	signature, err := c.signLeaseSet2Data(session, leaseSet, sgk)
	if err != nil {
		return err
	}

	c.messageStream.Write(leaseSet.Bytes())
	c.messageStream.Write(signature)
	c.writePrivateKeysToMessage(session)

	if err := c.sendMessage(I2CP_MSG_CREATE_LEASE_SET2, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet2Message: %v", err)
		return fmt.Errorf("failed to send CreateLeaseSet2Message: %w", err)
	}
	return nil
}

// signLeaseSet2Data creates and signs the LeaseSet2 data including the type byte.
func (c *Client) signLeaseSet2Data(session *Session, leaseSet *Stream, sgk *SignatureKeyPair) ([]byte, error) {
	var leaseSetType uint8
	if session.IsBlindingEnabled() {
		leaseSetType = LEASESET_TYPE_ENCRYPTED
	} else {
		leaseSetType = LEASESET_TYPE_STANDARD
	}

	dataToSign := NewStream(make([]byte, 0, leaseSet.Len()+1))
	dataToSign.WriteByte(leaseSetType)
	dataToSign.Write(leaseSet.Bytes())

	if err := sgk.ed25519KeyPair.SignStream(dataToSign); err != nil {
		Error("Failed to sign CreateLeaseSet2: %v", err)
		return nil, err
	}

	signedData := dataToSign.Bytes()
	return signedData[len(signedData)-64:], nil
}

// writePrivateKeysToMessage writes the private encryption keys to the message stream.
func (c *Client) writePrivateKeysToMessage(session *Session) {
	if session.encryptionKeyPair == nil {
		c.messageStream.WriteByte(0)
		return
	}

	c.messageStream.WriteByte(1)
	encType := uint16(X25519)
	keyLen := uint16(32)

	c.messageStream.WriteUint16(encType)
	c.messageStream.WriteUint16(keyLen)

	privKey := session.encryptionKeyPair.PrivateKey()
	c.messageStream.Write(privKey[:])

	Debug("Wrote X25519 encryption private key to CreateLeaseSet2Message (type=%d, len=%d), total: %d bytes",
		encType, keyLen, c.messageStream.Len())
}

// getAuthenticationMethod determines which authentication method is being used
// for I2CP session authentication based on the client's configuration properties.
//
// NOTE: This is for I2CP session authentication (GetDateMessage), NOT for
// per-client authentication to encrypted LeaseSets. For per-client auth,
// use BlindingInfoMessage via SendBlindingInfo() - see per_client_auth.go.
//
// Returns one of: AUTH_METHOD_NONE, AUTH_METHOD_USERNAME_PWD, or AUTH_METHOD_SSL_TLS
