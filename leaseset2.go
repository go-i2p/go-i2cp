package go_i2cp

import (
	"fmt"
	"time"

	"github.com/go-i2p/common/lease"
)

// LeaseSet2 represents a modern I2CP LeaseSet2 structure (I2CP 0.9.38+).
// LeaseSet2 supports multiple types: standard (3), encrypted (5), and meta (7).
// It uses Lease2 structures with 4-byte second timestamps for efficiency.
//
// I2CP Specification: CreateLeaseSet2Message (type 41), section 3.4
// Reference: https://geti2p.net/spec/common-structures#leaseset2
type LeaseSet2 struct {
	leaseSetType uint8             // Type: 3=standard, 5=encrypted, 7=meta
	destination  *Destination      // Destination this LeaseSet is for
	published    uint32            // Published timestamp (seconds since epoch)
	expires      uint32            // Expiration timestamp (seconds since epoch)
	flags        uint16            // Flags: bit 0=offline signature present
	properties   map[string]string // Optional properties mapping
	leases       []*lease.Lease2   // Array of Lease2 structures (max 16)
	offlineSig   *OfflineSignature // Optional offline signature (if flags bit 0 set)
	signature    []byte            // Signature over the LeaseSet2 data
}

// OfflineSignature represents offline signing data for LeaseSet2.
// Offline signatures allow separation of online and offline keys for enhanced security.
//
// I2CP Specification: LeaseSet2 offline signature format
type OfflineSignature struct {
	signingKeyType uint16 // Signing key type (e.g., ED25519_SHA256)
	signingKey     []byte // Public signing key
	expires        uint32 // Expiration timestamp (seconds since epoch)
	transientType  uint16 // Transient signing key type
	transientKey   []byte // Transient public signing key
	signature      []byte // Signature of the offline data
}

// NewLeaseSet2FromStream parses a LeaseSet2 structure from an I2CP Stream.
// This function is called when receiving a CreateLeaseSet2Message from the router.
//
// Stream format (all multi-byte integers in big-endian):
//   - LeaseSet type (1 byte): 3=standard, 5=encrypted, 7=meta
//   - Destination (387+ bytes): standard I2CP destination
//   - Published timestamp (4 bytes): seconds since epoch
//   - Expires timestamp (4 bytes): seconds since epoch
//   - Flags (2 bytes): bit 0=offline signature present
//   - Properties (variable): I2CP mapping structure
//   - Lease count (1 byte): number of leases (max 16)
//   - Leases (40 bytes each): Lease2 structures
//   - [Optional] Offline signature (variable): if flags bit 0 set
//   - Signature (variable): signature over all previous data
//
// Parameters:
//
//	stream - I2CP Stream containing the LeaseSet2 data
//	crypto - Crypto instance for parsing destination
//
// Returns:
//
//	LeaseSet2 structure and any error encountered
//
// I2CP Spec: CreateLeaseSet2Message format, I2CP 0.9.38+
func NewLeaseSet2FromStream(stream *Stream, crypto *Crypto) (*LeaseSet2, error) {
	ls := &LeaseSet2{}

	// Read LeaseSet type (1 byte)
	var err error
	ls.leaseSetType, err = stream.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 type: %w", err)
	}

	// Validate LeaseSet type
	switch ls.leaseSetType {
	case LEASESET_TYPE_STANDARD, LEASESET_TYPE_ENCRYPTED, LEASESET_TYPE_META:
		// Valid types
	default:
		return nil, fmt.Errorf("invalid LeaseSet2 type: %d (expected 3, 5, or 7)", ls.leaseSetType)
	}

	// Read destination
	ls.destination, err = NewDestinationFromStream(stream, crypto)
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 destination: %w", err)
	}

	// Read published timestamp (4 bytes)
	ls.published, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 published timestamp: %w", err)
	}

	// Read expires timestamp (4 bytes)
	ls.expires, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 expires timestamp: %w", err)
	}

	// Read flags (2 bytes)
	ls.flags, err = stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 flags: %w", err)
	}

	// Read properties mapping
	ls.properties, err = stream.ReadMapping()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 properties: %w", err)
	}

	// Read lease count (1 byte)
	leaseCount, err := stream.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 lease count: %w", err)
	}

	// Validate lease count (I2CP spec: max 16 leases)
	if leaseCount > 16 {
		return nil, fmt.Errorf("invalid LeaseSet2 lease count: %d (max 16)", leaseCount)
	}

	// Read leases (40 bytes each for Lease2)
	ls.leases = make([]*lease.Lease2, leaseCount)
	for i := uint8(0); i < leaseCount; i++ {
		// Read 40-byte Lease2 structure
		leaseData := make([]byte, 40)
		n, err := stream.Read(leaseData)
		if err != nil {
			return nil, fmt.Errorf("failed to read LeaseSet2 lease %d: %w", i, err)
		}
		if n != 40 {
			return nil, fmt.Errorf("incomplete Lease2 read: got %d bytes, expected 40", n)
		}

		// Parse Lease2 using common/lease package
		l2, _, err := lease.ReadLease2(leaseData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Lease2 %d: %w", i, err)
		}
		ls.leases[i] = &l2
	}

	// Read offline signature if present (flags bit 0)
	if ls.flags&0x0001 != 0 {
		ls.offlineSig, err = readOfflineSignature(stream)
		if err != nil {
			return nil, fmt.Errorf("failed to read offline signature: %w", err)
		}
	}

	// Read signature (variable length based on destination's signing key type)
	sigLen := getSignatureLength(ls.destination)
	if sigLen == 0 {
		return nil, fmt.Errorf("invalid signature length from destination")
	}

	ls.signature = make([]byte, sigLen)
	n, err := stream.Read(ls.signature)
	if err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet2 signature: %w", err)
	}
	if n != sigLen {
		return nil, fmt.Errorf("incomplete signature read: got %d bytes, expected %d", n, sigLen)
	}

	return ls, nil
}

// readOfflineSignature reads an OfflineSignature from the stream.
// Format:
//   - Signing key type (2 bytes)
//   - Signing key length (2 bytes)
//   - Signing key (variable)
//   - Expires (4 bytes)
//   - Transient key type (2 bytes)
//   - Transient key length (2 bytes)
//   - Transient key (variable)
//   - Signature length (2 bytes)
//   - Signature (variable)
func readOfflineSignature(stream *Stream) (*OfflineSignature, error) {
	sig := &OfflineSignature{}

	// Read signing key type
	var err error
	sig.signingKeyType, err = stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature signing key type: %w", err)
	}

	// Read signing key length
	signingKeyLen, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature signing key length: %w", err)
	}

	// Read signing key
	sig.signingKey = make([]byte, signingKeyLen)
	n, err := stream.Read(sig.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signing key: %w", err)
	}
	if n != int(signingKeyLen) {
		return nil, fmt.Errorf("incomplete signing key read: got %d bytes, expected %d", n, signingKeyLen)
	}

	// Read expires timestamp
	sig.expires, err = stream.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature expires: %w", err)
	}

	// Read transient key type
	sig.transientType, err = stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature transient key type: %w", err)
	}

	// Read transient key length
	transientKeyLen, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature transient key length: %w", err)
	}

	// Read transient key
	sig.transientKey = make([]byte, transientKeyLen)
	n, err = stream.Read(sig.transientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read offline transient key: %w", err)
	}
	if n != int(transientKeyLen) {
		return nil, fmt.Errorf("incomplete transient key read: got %d bytes, expected %d", n, transientKeyLen)
	}

	// Read signature length
	sigLen, err := stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature length: %w", err)
	}

	// Read signature
	sig.signature = make([]byte, sigLen)
	n, err = stream.Read(sig.signature)
	if err != nil {
		return nil, fmt.Errorf("failed to read offline signature data: %w", err)
	}
	if n != int(sigLen) {
		return nil, fmt.Errorf("incomplete signature read: got %d bytes, expected %d", n, sigLen)
	}

	return sig, nil
}

// getSignatureLength returns the expected signature length based on the destination's certificate.
// This determines the size of the signature field in the LeaseSet2.
//
// Signature lengths per I2CP specification:
//   - DSA (type 0): 40 bytes (20 bytes r + 20 bytes s)
//   - Ed25519 (type 7): 64 bytes
//   - Other types: determined by certificate specification
//
// Returns 0 if the signature type cannot be determined.
func getSignatureLength(dest *Destination) int {
	if dest == nil || dest.cert == nil || dest.cert.cert == nil {
		return 0
	}

	// Check certificate type to determine signature algorithm
	certType, err := dest.cert.cert.Type()
	if err != nil {
		// If we can't determine type, default to DSA
		return 40
	}

	// For NULL certificates (type 0), use DSA (40 bytes)
	if certType == int(CERTIFICATE_NULL) {
		return 40 // DSA signature
	}

	// For other certificate types, check the signature type in extra data
	// This is a simplified implementation - full certificate parsing would
	// read the signature type from cert extra data

	// Default to DSA for backward compatibility
	return 40
}

// Type returns the LeaseSet2 type (3=standard, 5=encrypted, 7=meta)
func (ls *LeaseSet2) Type() uint8 {
	return ls.leaseSetType
}

// Destination returns the destination this LeaseSet is for
func (ls *LeaseSet2) Destination() *Destination {
	return ls.destination
}

// Published returns the published timestamp as time.Time
func (ls *LeaseSet2) Published() time.Time {
	return time.Unix(int64(ls.published), 0)
}

// PublishedSeconds returns the published timestamp in seconds since epoch
func (ls *LeaseSet2) PublishedSeconds() uint32 {
	return ls.published
}

// Expires returns the expiration timestamp as time.Time
func (ls *LeaseSet2) Expires() time.Time {
	return time.Unix(int64(ls.expires), 0)
}

// ExpiresSeconds returns the expiration timestamp in seconds since epoch
func (ls *LeaseSet2) ExpiresSeconds() uint32 {
	return ls.expires
}

// Flags returns the flags field
func (ls *LeaseSet2) Flags() uint16 {
	return ls.flags
}

// Properties returns the properties mapping
func (ls *LeaseSet2) Properties() map[string]string {
	return ls.properties
}

// Leases returns the array of Lease2 structures
func (ls *LeaseSet2) Leases() []*lease.Lease2 {
	return ls.leases
}

// LeaseCount returns the number of leases
func (ls *LeaseSet2) LeaseCount() int {
	return len(ls.leases)
}

// OfflineSignature returns the offline signature (may be nil)
func (ls *LeaseSet2) OfflineSignature() *OfflineSignature {
	return ls.offlineSig
}

// Signature returns the signature bytes
func (ls *LeaseSet2) Signature() []byte {
	return ls.signature
}

// IsExpired checks if the LeaseSet2 has expired based on current time
func (ls *LeaseSet2) IsExpired() bool {
	now := uint32(time.Now().Unix())
	return now >= ls.expires
}

// HasOfflineSignature returns true if the LeaseSet2 has an offline signature
func (ls *LeaseSet2) HasOfflineSignature() bool {
	return ls.offlineSig != nil
}

// VerifySignature performs basic validation of the signature.
// This is a placeholder for actual cryptographic verification which would
// require access to the Crypto instance and signature verification logic.
// Full implementation will be added when integrating with session callbacks.
//
// Returns:
//
//	true if signature appears valid (basic checks), false otherwise
func (ls *LeaseSet2) VerifySignature() bool {
	// Basic validation: signature must be non-empty and correct length
	if len(ls.signature) == 0 {
		return false
	}

	expectedLen := getSignatureLength(ls.destination)
	if expectedLen == 0 || len(ls.signature) != expectedLen {
		return false
	}

	// TODO: Implement actual cryptographic signature verification
	// This requires:
	// 1. Reconstructing the signed data (all fields before signature)
	// 2. Using destination's signing public key
	// 3. Verifying signature with appropriate algorithm (DSA/Ed25519)
	//
	// For now, basic length validation passes
	return true
}

// String returns a debug-friendly string representation of the LeaseSet2
func (ls *LeaseSet2) String() string {
	typeStr := "unknown"
	switch ls.leaseSetType {
	case LEASESET_TYPE_STANDARD:
		typeStr = "standard"
	case LEASESET_TYPE_ENCRYPTED:
		typeStr = "encrypted"
	case LEASESET_TYPE_META:
		typeStr = "meta"
	}

	destStr := "unknown"
	if ls.destination != nil {
		// Use the destination's base32 address for identification
		if len(ls.destination.b32) > 8 {
			destStr = ls.destination.b32[:8]
		}
	}

	return fmt.Sprintf("LeaseSet2{type=%s, dest=%s, published=%s, expires=%s, leases=%d, hasOffline=%v, expired=%v}",
		typeStr,
		destStr,
		ls.Published().Format(time.RFC3339),
		ls.Expires().Format(time.RFC3339),
		len(ls.leases),
		ls.HasOfflineSignature(),
		ls.IsExpired())
}

// OfflineSignature getter methods

// SigningKeyType returns the signing key type
func (os *OfflineSignature) SigningKeyType() uint16 {
	return os.signingKeyType
}

// SigningKey returns the signing public key
func (os *OfflineSignature) SigningKey() []byte {
	return os.signingKey
}

// Expires returns the expiration timestamp as time.Time
func (os *OfflineSignature) Expires() time.Time {
	return time.Unix(int64(os.expires), 0)
}

// ExpiresSeconds returns the expiration timestamp in seconds since epoch
func (os *OfflineSignature) ExpiresSeconds() uint32 {
	return os.expires
}

// TransientKeyType returns the transient signing key type
func (os *OfflineSignature) TransientKeyType() uint16 {
	return os.transientType
}

// TransientKey returns the transient public signing key
func (os *OfflineSignature) TransientKey() []byte {
	return os.transientKey
}

// Signature returns the signature bytes
func (os *OfflineSignature) Signature() []byte {
	return os.signature
}

// IsExpired checks if the offline signature has expired
func (os *OfflineSignature) IsExpired() bool {
	now := uint32(time.Now().Unix())
	return now >= os.expires
}

// String returns a debug-friendly string representation
func (os *OfflineSignature) String() string {
	return fmt.Sprintf("OfflineSignature{sigType=%d, expires=%s, transientType=%d, expired=%v}",
		os.signingKeyType,
		os.Expires().Format(time.RFC3339),
		os.transientType,
		os.IsExpired())
}
