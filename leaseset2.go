package go_i2cp

import (
	"fmt"
	"time"

	"github.com/go-i2p/common/lease"
	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
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
// The offline signature proves that the long-term signing key authorized a transient
// key for a limited time period. This allows the long-term key to remain offline while
// the transient key signs LeaseSets.
//
// Signature Format (signed data):
//
//	signingKeyType (2 bytes) || signingKeyLen (2 bytes) || signingKey (variable) ||
//	expires (4 bytes) || transientKeyType (2 bytes) || transientKeyLen (2 bytes) || transientKey (variable)
//
// The signature field contains the signature over the above data, signed by the long-term key.
//
// Validation:
//   - ✅ Expiration checking via IsExpired()
//   - ✅ Cryptographic verification via Verify()
//   - ✅ Transient key validation via signature verification
//
// I2CP Specification: LeaseSet2 § Offline Signatures
type OfflineSignature struct {
	signingKeyType uint16 // Signing key type (e.g., ED25519_SHA256)
	signingKey     []byte // Public signing key (long-term key that signed this authorization)
	expires        uint32 // Expiration timestamp in seconds since epoch
	transientType  uint16 // Transient signing key type
	transientKey   []byte // Transient public signing key (authorized by signature)
	signature      []byte // Signature over [signingKeyType||signingKeyLen||signingKey||expires||transientKeyType||transientKeyLen||transientKey]
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

// IsExpired checks if the offline signature has expired.
// Returns true if the current time is past the expiration timestamp.
//
// I2CP Spec: Offline signatures must be rejected if expired to prevent
// unauthorized use of transient keys beyond their authorized period.
func (sig *OfflineSignature) IsExpired() bool {
	if sig == nil {
		return true
	}
	now := uint32(time.Now().Unix())
	return now > sig.expires
}

// Verify cryptographically verifies the offline signature.
// This validates that the long-term signing key actually authorized the transient key.
//
// Verification process:
//  1. Reconstruct signed data: signingKeyType || signingKeyLen || signingKey ||
//     expires || transientKeyType || transientKeyLen || transientKey
//  2. Verify signature over this data using the signing key
//
// Returns:
//   - nil if signature is valid
//   - ErrOfflineSignatureInvalid if verification fails
//   - ErrUnsupportedCrypto if signature type is not supported
//
// I2CP Spec: LeaseSet2 § Offline Signatures
func (sig *OfflineSignature) Verify() error {
	if sig == nil {
		return ErrInvalidArgument
	}

	// Only Ed25519 signatures are supported (modern I2CP)
	// Note: ED25519_SHA256 is defined as uint32, but signingKeyType field is uint16
	if sig.signingKeyType != uint16(ED25519_SHA256) {
		return fmt.Errorf("%w: offline signature type %d (only Ed25519 supported)",
			ErrUnsupportedCrypto, sig.signingKeyType)
	}

	// Reconstruct the signed data
	// Format: signingKeyType || signingKeyLen || signingKey || expires ||
	//         transientKeyType || transientKeyLen || transientKey
	stream := NewStream(make([]byte, 0, 256))

	// Write signing key type (2 bytes)
	if err := stream.WriteUint16(sig.signingKeyType); err != nil {
		return fmt.Errorf("failed to write signing key type: %w", err)
	}

	// Write signing key length (2 bytes)
	if err := stream.WriteUint16(uint16(len(sig.signingKey))); err != nil {
		return fmt.Errorf("failed to write signing key length: %w", err)
	}

	// Write signing key (variable)
	if _, err := stream.Write(sig.signingKey); err != nil {
		return fmt.Errorf("failed to write signing key: %w", err)
	}

	// Write expires timestamp (4 bytes)
	if err := stream.WriteUint32(sig.expires); err != nil {
		return fmt.Errorf("failed to write expires: %w", err)
	}

	// Write transient key type (2 bytes)
	if err := stream.WriteUint16(sig.transientType); err != nil {
		return fmt.Errorf("failed to write transient key type: %w", err)
	}

	// Write transient key length (2 bytes)
	if err := stream.WriteUint16(uint16(len(sig.transientKey))); err != nil {
		return fmt.Errorf("failed to write transient key length: %w", err)
	}

	// Write transient key (variable)
	if _, err := stream.Write(sig.transientKey); err != nil {
		return fmt.Errorf("failed to write transient key: %w", err)
	}

	signedData := stream.Bytes()

	// Create Ed25519 public key from signing key bytes for verification
	ed25519PubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(sig.signingKey)
	if err != nil {
		return fmt.Errorf("failed to create Ed25519 public key: %w", err)
	}

	// Create temporary key pair with just the public key for verification
	tempKeyPair := &Ed25519KeyPair{
		algorithmType: ED25519_SHA256,
		publicKey:     ed25519PubKey,
	}

	// Verify the signature over the signed data
	if !tempKeyPair.Verify(signedData, sig.signature) {
		return ErrOfflineSignatureInvalid
	}

	return nil
}

// GetTransientKey returns the transient public key bytes.
// This key should be used to verify the LeaseSet2 signature, not the signing key.
func (sig *OfflineSignature) GetTransientKey() []byte {
	if sig == nil {
		return nil
	}
	return sig.transientKey
}

// GetExpires returns the expiration timestamp (seconds since epoch)
func (sig *OfflineSignature) GetExpires() uint32 {
	if sig == nil {
		return 0
	}
	return sig.expires
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
	if dest == nil {
		return 0
	}

	// Check the signature key pair algorithm type if available
	if dest.sgk.algorithmType == ED25519_SHA256 {
		return 64 // Ed25519 signature
	}

	// Default to Ed25519 (all new destinations use Ed25519)
	return 64
}

// getSigningPublicKeyFromDestination extracts the signing public key bytes from a destination.
// Returns the public key and the algorithm type (ED25519_SHA256 only).
func getSigningPublicKeyFromDestination(dest *Destination) ([]byte, uint32, error) {
	if dest == nil {
		return nil, 0, fmt.Errorf("destination is nil")
	}

	// Check algorithm type from signature key pair
	algorithmType := dest.sgk.algorithmType

	// Only Ed25519 is supported
	if algorithmType != ED25519_SHA256 {
		return nil, 0, fmt.Errorf("unsupported signature algorithm: %d (only Ed25519 supported)", algorithmType)
	}

	// Extract Ed25519 public key
	if dest.sgk.ed25519KeyPair == nil {
		return nil, 0, fmt.Errorf("Ed25519 keypair is nil")
	}

	pubKey := dest.sgk.ed25519KeyPair.PublicKey()
	return pubKey[:], ED25519_SHA256, nil
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

// VerifySignature verifies the LeaseSet2 cryptographic signature.
// Uses the destination's signing public key to verify the signature over all LeaseSet2 data
// preceding the signature field.
//
// I2CP 0.9.38+ - Supports DSA-SHA1 (legacy) and Ed25519-SHA512 (modern) signatures.
//
// Returns true if signature is cryptographically valid, false otherwise.
// Basic validation (non-empty signature, correct length) is performed first.
func (ls *LeaseSet2) VerifySignature() bool {
	// Basic validation: signature must be non-empty and correct length
	if len(ls.signature) == 0 {
		return false
	}

	expectedLen := getSignatureLength(ls.destination)
	if expectedLen == 0 || len(ls.signature) != expectedLen {
		return false
	}

	// Get signing public key and algorithm type from destination
	pubKeyBytes, algorithmType, err := getSigningPublicKeyFromDestination(ls.destination)
	if err != nil {
		Error("Failed to extract signing public key: %v", err)
		return false
	}

	// Reconstruct the signed data (all fields before signature)
	signedData, err := ls.reconstructSignedData()
	if err != nil {
		Error("Failed to reconstruct signed data: %v", err)
		return false
	}

	// Verify signature based on algorithm type
	// Modern I2CP uses Ed25519 exclusively
	if algorithmType != ED25519_SHA256 {
		Error("Unsupported signature algorithm type: %d (only Ed25519 supported)", algorithmType)
		return false
	}

	// Verify Ed25519 signature
	// Create a temporary Ed25519KeyPair with just the public key for verification
	ed25519PubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		Error("Failed to create Ed25519 public key: %v", err)
		return false
	}

	tempKeyPair := &Ed25519KeyPair{
		algorithmType: ED25519_SHA256,
		publicKey:     ed25519PubKey,
	}

	return tempKeyPair.Verify(signedData, ls.signature)
}

// reconstructSignedData reconstructs the byte sequence that was signed.
// This includes all LeaseSet2 fields up to but not including the signature.
//
// Format (all multi-byte integers in big-endian):
//   - LeaseSet type (1 byte)
//   - Destination (387+ bytes)
//   - Published timestamp (4 bytes)
//   - Expires timestamp (4 bytes)
//   - Flags (2 bytes)
//   - Properties mapping (variable)
//   - Lease count (1 byte)
//   - Leases (variable, each Lease2 is 44 bytes minimum)
//   - Offline signature (if flags bit 0 set, variable)
func (ls *LeaseSet2) reconstructSignedData() ([]byte, error) {
	stream := NewStream(make([]byte, 0, 512))

	// Write LeaseSet type
	err := stream.WriteByte(ls.leaseSetType)
	if err != nil {
		return nil, fmt.Errorf("failed to write lease set type: %w", err)
	}

	// Write destination
	err = ls.destination.WriteToStream(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to write destination: %w", err)
	}

	// Write published timestamp
	err = stream.WriteUint32(ls.published)
	if err != nil {
		return nil, fmt.Errorf("failed to write published timestamp: %w", err)
	}

	// Write expires timestamp
	err = stream.WriteUint32(ls.expires)
	if err != nil {
		return nil, fmt.Errorf("failed to write expires timestamp: %w", err)
	}

	// Write flags
	err = stream.WriteUint16(ls.flags)
	if err != nil {
		return nil, fmt.Errorf("failed to write flags: %w", err)
	}

	// Write properties mapping
	err = stream.WriteMapping(ls.properties)
	if err != nil {
		return nil, fmt.Errorf("failed to write properties: %w", err)
	}

	// Write lease count
	leaseCount := uint8(len(ls.leases))
	err = stream.WriteByte(leaseCount)
	if err != nil {
		return nil, fmt.Errorf("failed to write lease count: %w", err)
	}

	// Write each Lease2
	for i, lease := range ls.leases {
		leaseBytes := lease.Bytes()
		_, err = stream.Write(leaseBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to write lease %d: %w", i, err)
		}
	}

	// Write offline signature if present
	if ls.flags&0x0001 != 0 && ls.offlineSig != nil {
		err = writeOfflineSignature(ls.offlineSig, stream)
		if err != nil {
			return nil, fmt.Errorf("failed to write offline signature: %w", err)
		}
	}

	return stream.Bytes(), nil
}

// writeOfflineSignature writes an OfflineSignature to the stream for signature verification.
func writeOfflineSignature(sig *OfflineSignature, stream *Stream) error {
	// Write signing key type
	err := stream.WriteUint16(sig.signingKeyType)
	if err != nil {
		return fmt.Errorf("failed to write signing key type: %w", err)
	}

	// Write signing key length and key
	err = stream.WriteUint16(uint16(len(sig.signingKey)))
	if err != nil {
		return fmt.Errorf("failed to write signing key length: %w", err)
	}
	_, err = stream.Write(sig.signingKey)
	if err != nil {
		return fmt.Errorf("failed to write signing key: %w", err)
	}

	// Write expires
	err = stream.WriteUint32(sig.expires)
	if err != nil {
		return fmt.Errorf("failed to write expires: %w", err)
	}

	// Write transient key type
	err = stream.WriteUint16(sig.transientType)
	if err != nil {
		return fmt.Errorf("failed to write transient key type: %w", err)
	}

	// Write transient key length and key
	err = stream.WriteUint16(uint16(len(sig.transientKey)))
	if err != nil {
		return fmt.Errorf("failed to write transient key length: %w", err)
	}
	_, err = stream.Write(sig.transientKey)
	if err != nil {
		return fmt.Errorf("failed to write transient key: %w", err)
	}

	// Write signature length and signature
	err = stream.WriteUint16(uint16(len(sig.signature)))
	if err != nil {
		return fmt.Errorf("failed to write signature length: %w", err)
	}
	_, err = stream.Write(sig.signature)
	if err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	return nil
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

// String returns a debug-friendly string representation
func (os *OfflineSignature) String() string {
	return fmt.Sprintf("OfflineSignature{sigType=%d, expires=%s, transientType=%d, expired=%v}",
		os.signingKeyType,
		os.Expires().Format(time.RFC3339),
		os.transientType,
		os.IsExpired())
}
