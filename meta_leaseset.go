// meta_leaseset.go - MetaLeaseSet creation and management for I2CP
// per I2CP specification 0.9.38+ - MetaLeaseSet (type 7)
package go_i2cp

import (
	"fmt"
)

// MetaLease represents a single entry in a MetaLeaseSet.
// Unlike regular Lease2, MetaLease contains references to other LeaseSets
// rather than tunnel information.
//
// Format (40 bytes):
//   - Hash (32 bytes): SHA256 hash of the target destination/LeaseSet
//   - Flags (3 bytes): bit 0-3 = type (0=unknown, 1=LeaseSet, 3=LeaseSet2, 5=MetaLeaseSet)
//   - Cost (1 byte): 0-255, lower value = higher priority
//   - EndDate (4 bytes): seconds since epoch
//
// I2CP Specification: MetaLease structure
type MetaLease struct {
	Hash    [32]byte // SHA256 hash of the target LeaseSet destination
	Flags   uint32   // 3 bytes of flags (bits 0-3 = LeaseSet type)
	Cost    uint8    // Priority cost, 0-255, lower is better
	EndDate uint32   // Expiration in seconds since epoch
}

// MetaLeaseSet type constants for the Flags field
const (
	META_LEASE_TYPE_UNKNOWN   uint8 = 0 // Unknown type
	META_LEASE_TYPE_LEASESET  uint8 = 1 // Legacy LeaseSet
	META_LEASE_TYPE_LEASESET2 uint8 = 3 // LeaseSet2
	META_LEASE_TYPE_META      uint8 = 5 // Nested MetaLeaseSet
)

// NewMetaLease creates a new MetaLease entry with the given parameters.
//
// Parameters:
//   - hash: SHA256 hash of the target destination
//   - leaseSetType: Type of LeaseSet (1=LeaseSet, 3=LeaseSet2, 5=MetaLeaseSet)
//   - cost: Priority cost (0=highest priority, 255=lowest)
//   - endDate: Expiration timestamp in seconds since epoch
func NewMetaLease(hash [32]byte, leaseSetType, cost uint8, endDate uint32) *MetaLease {
	return &MetaLease{
		Hash:    hash,
		Flags:   uint32(leaseSetType & 0x0F), // Only bits 0-3 are used for type
		Cost:    cost,
		EndDate: endDate,
	}
}

// Type returns the LeaseSet type from the flags field (bits 0-3).
func (ml *MetaLease) Type() uint8 {
	return uint8(ml.Flags & 0x0F)
}

// SetType sets the LeaseSet type in the flags field.
func (ml *MetaLease) SetType(leaseSetType uint8) {
	ml.Flags = (ml.Flags & 0xFFFFF0) | uint32(leaseSetType&0x0F)
}

// WriteToStream writes the MetaLease to an I2CP stream in the spec format.
// Format: hash(32) + flags(3) + cost(1) + endDate(4) = 40 bytes
func (ml *MetaLease) WriteToStream(stream *Stream) error {
	// Write 32-byte hash
	if _, err := stream.Write(ml.Hash[:]); err != nil {
		return fmt.Errorf("failed to write MetaLease hash: %w", err)
	}

	// Write 3-byte flags (big-endian, only lower 24 bits)
	flags24 := ml.Flags & 0x00FFFFFF
	stream.WriteByte(uint8((flags24 >> 16) & 0xFF))
	stream.WriteByte(uint8((flags24 >> 8) & 0xFF))
	stream.WriteByte(uint8(flags24 & 0xFF))

	// Write 1-byte cost
	stream.WriteByte(ml.Cost)

	// Write 4-byte end date
	stream.WriteUint32(ml.EndDate)

	return nil
}

// ReadMetaLeaseFromStream reads a MetaLease from an I2CP stream.
// Returns the MetaLease and any error encountered.
func ReadMetaLeaseFromStream(stream *Stream) (*MetaLease, error) {
	ml := &MetaLease{}

	if err := readMetaLeaseHash(stream, ml); err != nil {
		return nil, err
	}

	if err := readMetaLeaseFlags(stream, ml); err != nil {
		return nil, err
	}

	if err := readMetaLeaseCostAndEndDate(stream, ml); err != nil {
		return nil, err
	}

	return ml, nil
}

// readMetaLeaseHash reads the 32-byte hash from the stream.
func readMetaLeaseHash(stream *Stream, ml *MetaLease) error {
	n, err := stream.Read(ml.Hash[:])
	if err != nil {
		return fmt.Errorf("failed to read MetaLease hash: %w", err)
	}
	if n != 32 {
		return fmt.Errorf("incomplete MetaLease hash: got %d bytes, expected 32", n)
	}
	return nil
}

// readMetaLeaseFlags reads the 3-byte flags from the stream.
func readMetaLeaseFlags(stream *Stream, ml *MetaLease) error {
	b0, err := stream.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read MetaLease flags byte 0: %w", err)
	}
	b1, err := stream.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read MetaLease flags byte 1: %w", err)
	}
	b2, err := stream.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read MetaLease flags byte 2: %w", err)
	}
	ml.Flags = (uint32(b0) << 16) | (uint32(b1) << 8) | uint32(b2)
	return nil
}

// readMetaLeaseCostAndEndDate reads the cost and end date fields.
func readMetaLeaseCostAndEndDate(stream *Stream, ml *MetaLease) error {
	var err error
	ml.Cost, err = stream.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read MetaLease cost: %w", err)
	}

	ml.EndDate, err = stream.ReadUint32()
	if err != nil {
		return fmt.Errorf("failed to read MetaLease end date: %w", err)
	}
	return nil
}

// MetaLeaseSetConfig holds the configuration for creating a MetaLeaseSet.
// Used when calling msgCreateMetaLeaseSet.
type MetaLeaseSetConfig struct {
	MetaLeases  []*MetaLease // References to other LeaseSets (max 16)
	Revocations [][32]byte   // Hashes of revoked LeaseSets
	Properties  map[string]string
}

// NewMetaLeaseSetConfig creates a new MetaLeaseSetConfig with default values.
func NewMetaLeaseSetConfig() *MetaLeaseSetConfig {
	return &MetaLeaseSetConfig{
		MetaLeases:  make([]*MetaLease, 0),
		Revocations: make([][32]byte, 0),
		Properties:  make(map[string]string),
	}
}

// AddMetaLease adds a MetaLease entry to the configuration.
// Returns an error if the maximum of 16 entries would be exceeded.
func (c *MetaLeaseSetConfig) AddMetaLease(ml *MetaLease) error {
	if len(c.MetaLeases) >= 16 {
		return fmt.Errorf("maximum of 16 MetaLeases allowed")
	}
	c.MetaLeases = append(c.MetaLeases, ml)
	return nil
}

// AddRevocation adds a revocation hash to the configuration.
func (c *MetaLeaseSetConfig) AddRevocation(hash [32]byte) {
	c.Revocations = append(c.Revocations, hash)
}

// msgCreateMetaLeaseSet sends CreateLeaseSet2Message (type 41) with MetaLeaseSet type (7)
// per I2CP specification 0.9.38+ - for aggregating multiple LeaseSets under one destination.
//
// MetaLeaseSet is used to create a "parent" LeaseSet that references multiple "child"
// LeaseSets, enabling load balancing and redundancy across multiple destinations.
//
// Parameters:
//   - session: The session to create the MetaLeaseSet for
//   - config: MetaLeaseSetConfig containing MetaLeases and revocations
//   - queue: If true, queue the message; if false, send immediately
//
// Returns an error if the router version doesn't support CreateLeaseSet2 or if
// the message fails to send.
func (c *Client) msgCreateMetaLeaseSet(session *Session, config *MetaLeaseSetConfig, queue bool) error {
	// Version check: CreateLeaseSet2 requires router 0.9.39+
	if !c.SupportsVersion(VersionCreateLeaseSet2) {
		return fmt.Errorf("router version %s does not support CreateLeaseSet2/MetaLeaseSet (requires %s+)",
			c.router.version.String(), VersionCreateLeaseSet2.String())
	}

	if len(config.MetaLeases) == 0 {
		return fmt.Errorf("MetaLeaseSet requires at least one MetaLease entry")
	}

	if len(config.MetaLeases) > 16 {
		return fmt.Errorf("MetaLeaseSet allows maximum 16 MetaLease entries, got %d", len(config.MetaLeases))
	}

	Debug("Sending CreateLeaseSet2Message (MetaLeaseSet) for session %d with %d entries",
		session.id, len(config.MetaLeases))

	metaLeaseSet := NewStream(make([]byte, 0, 4096))
	dest := session.config.destination

	c.messageStream.Reset()
	c.messageStream.WriteUint16(session.id)

	// Write LeaseSet type byte (7 = MetaLeaseSet)
	c.messageStream.WriteByte(LEASESET_TYPE_META)

	if err := c.buildMetaLeaseSetContent(session, metaLeaseSet, dest, config); err != nil {
		return err
	}

	if err := c.signAndSendMetaLeaseSet(session, metaLeaseSet, dest, queue); err != nil {
		return err
	}

	Debug("Successfully sent CreateLeaseSet2Message (MetaLeaseSet) for session %d", session.id)
	return nil
}

// buildMetaLeaseSetContent constructs the complete MetaLeaseSet content.
// Format: destination + published + expires + flags + properties + metaLeases + revocations
func (c *Client) buildMetaLeaseSetContent(session *Session, stream *Stream, dest *Destination, config *MetaLeaseSetConfig) error {
	// Write destination
	dest.WriteToMessage(stream)

	// Write timestamps (same format as LeaseSet2Header)
	publishedSeconds := uint32(c.router.date / 1000)
	stream.WriteUint32(publishedSeconds)

	// Expires is an offset in seconds from published time
	// MetaLeaseSet can have up to 65535 seconds (~18.2 hours) expiration
	expiresOffset := uint16(3600) // 1 hour default for MetaLeaseSet
	stream.WriteUint16(expiresOffset)

	// Write flags (2 bytes) - no offline signature for now
	var flags uint16 = 0
	stream.WriteUint16(flags)

	// Write properties mapping
	if err := stream.WriteMapping(config.Properties); err != nil {
		return fmt.Errorf("failed to write MetaLeaseSet properties: %w", err)
	}

	// Write MetaLease entries
	if err := c.writeMetaLeases(stream, config.MetaLeases); err != nil {
		return err
	}

	// Write revocations
	if err := c.writeRevocations(stream, config.Revocations); err != nil {
		return err
	}

	return nil
}

// writeMetaLeases writes the MetaLease count and entries to the stream.
func (c *Client) writeMetaLeases(stream *Stream, metaLeases []*MetaLease) error {
	// Write count (1 byte)
	stream.WriteByte(uint8(len(metaLeases)))

	// Write each MetaLease (40 bytes each)
	for i, ml := range metaLeases {
		if err := ml.WriteToStream(stream); err != nil {
			return fmt.Errorf("failed to write MetaLease %d: %w", i, err)
		}
	}

	Debug("Wrote %d MetaLease entries to MetaLeaseSet", len(metaLeases))
	return nil
}

// writeRevocations writes the revocation count and hashes to the stream.
func (c *Client) writeRevocations(stream *Stream, revocations [][32]byte) error {
	// Write count (1 byte)
	stream.WriteByte(uint8(len(revocations)))

	// Write each revocation hash (32 bytes each)
	for i, hash := range revocations {
		if _, err := stream.Write(hash[:]); err != nil {
			return fmt.Errorf("failed to write revocation hash %d: %w", i, err)
		}
	}

	if len(revocations) > 0 {
		Debug("Wrote %d revocation hashes to MetaLeaseSet", len(revocations))
	}

	return nil
}

// signAndSendMetaLeaseSet signs the MetaLeaseSet and sends it to the router.
// Per I2CP spec: signature covers [type:1][metaLeaseSetContent:var]
func (c *Client) signAndSendMetaLeaseSet(session *Session, metaLeaseSet *Stream, dest *Destination, queue bool) error {
	sgk := &dest.sgk

	// Build signable data: type byte (7) + MetaLeaseSet content
	dataToSign := NewStream(make([]byte, 0, metaLeaseSet.Len()+1))
	dataToSign.WriteByte(LEASESET_TYPE_META)
	dataToSign.Write(metaLeaseSet.Bytes())

	// Sign with Ed25519
	if err := sgk.ed25519KeyPair.SignStream(dataToSign); err != nil {
		Error("Failed to sign CreateLeaseSet2 (MetaLeaseSet): %v", err)
		return err
	}

	// Extract signature (last 64 bytes)
	signedData := dataToSign.Bytes()
	signature := signedData[len(signedData)-64:]

	// Write MetaLeaseSet content + signature to message stream
	c.messageStream.Write(metaLeaseSet.Bytes())
	c.messageStream.Write(signature)

	// MetaLeaseSet doesn't include encryption private keys
	// (it references other LeaseSets which have their own keys)
	c.messageStream.WriteByte(0) // Number of private keys = 0

	if err := c.sendMessage(I2CP_MSG_CREATE_LEASE_SET2, c.messageStream, queue); err != nil {
		Error("Error while sending CreateLeaseSet2Message (MetaLeaseSet): %v", err)
		return fmt.Errorf("failed to send CreateLeaseSet2Message (MetaLeaseSet): %w", err)
	}

	return nil
}

// Session methods for MetaLeaseSet management

// CreateMetaLeaseSet creates and sends a MetaLeaseSet for this session.
// This allows the session's destination to act as an aggregation point for
// multiple other destinations.
//
// Parameters:
//   - config: MetaLeaseSetConfig containing the MetaLease entries
//
// Returns an error if the session is not connected or if sending fails.
func (s *Session) CreateMetaLeaseSet(config *MetaLeaseSetConfig) error {
	if s.client == nil {
		return fmt.Errorf("session has no associated client")
	}

	if s.closed {
		return fmt.Errorf("session is closed")
	}

	return s.client.msgCreateMetaLeaseSet(s, config, false)
}

// CreateMetaLeaseSetQueued creates a MetaLeaseSet and queues it for sending.
// Use this when not yet connected to the router.
func (s *Session) CreateMetaLeaseSetQueued(config *MetaLeaseSetConfig) error {
	if s.client == nil {
		return fmt.Errorf("session has no associated client")
	}

	return s.client.msgCreateMetaLeaseSet(s, config, true)
}
