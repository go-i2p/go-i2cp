package go_i2cp

// I2CP Protocol Constants
//
// This file contains constants defined by the I2CP specification for the
// I2P Control Protocol. I2CP is a lower-level protocol for managing sessions,
// leases, and message routing between I2P clients and routers.
//
// Note: This library focuses solely on I2CP. Higher-level application protocols
// such as streaming (protocol 6) and datagram (protocol 17/18) are intentionally
// NOT defined here as they are built on top of I2CP, not part of the I2CP spec.
// Applications using I2CP can define their own protocol identifiers as needed.

// I2CP Client Constants
// Moved from: client.go
const (
	I2CP_CLIENT_VERSION                 = "0.9.33"
	I2CP_PROTOCOL_INIT            uint8 = 0x2a
	I2CP_MESSAGE_SIZE                   = 0xffff
	I2CP_MAX_MESSAGE_PAYLOAD_SIZE       = 65536 // 64KB max payload per I2CP spec (spec says "about 64 KB")
	I2CP_SAFE_MESSAGE_SIZE              = 64000 // Conservative limit for universal router compatibility
	I2CP_MAX_SESSIONS                   = 0xffff
	I2CP_MAX_SESSIONS_PER_CLIENT        = 32
	// Session ID 0xFFFF is reserved per I2CP spec for "no session" operations
	// Used for hostname lookups and other operations that don't require a session
	I2CP_SESSION_ID_NONE uint16 = 0xFFFF
)

// I2CP Message Type Constants
// Moved from: client.go
const (
	I2CP_MSG_ANY                       uint8 = 0
	I2CP_MSG_BANDWIDTH_LIMITS          uint8 = 23
	I2CP_MSG_CREATE_LEASE_SET          uint8 = 4
	I2CP_MSG_CREATE_LEASE_SET2         uint8 = 41
	I2CP_MSG_CREATE_SESSION            uint8 = 1
	I2CP_MSG_DEST_LOOKUP               uint8 = 34
	I2CP_MSG_DEST_REPLY                uint8 = 35
	I2CP_MSG_DESTROY_SESSION           uint8 = 3
	I2CP_MSG_DISCONNECT                uint8 = 30
	I2CP_MSG_GET_BANDWIDTH_LIMITS      uint8 = 8
	I2CP_MSG_GET_DATE                  uint8 = 32
	I2CP_MSG_HOST_LOOKUP               uint8 = 38
	I2CP_MSG_HOST_REPLY                uint8 = 39
	I2CP_MSG_MESSAGE_STATUS            uint8 = 22
	I2CP_MSG_PAYLOAD_MESSAGE           uint8 = 31
	I2CP_MSG_RECEIVE_MESSAGE_BEGIN     uint8 = 6 // DEPRECATED: Not used in fastReceive mode (default since 0.9.4)
	I2CP_MSG_RECEIVE_MESSAGE_END       uint8 = 7 // DEPRECATED: Not used in fastReceive mode (default since 0.9.4)
	I2CP_MSG_RECONFIGURE_SESSION       uint8 = 2
	I2CP_MSG_REPORT_ABUSE              uint8 = 29 // DEPRECATED: Never fully implemented, unsupported
	I2CP_MSG_REQUEST_LEASESET          uint8 = 21
	I2CP_MSG_REQUEST_VARIABLE_LEASESET uint8 = 37
	I2CP_MSG_SEND_MESSAGE              uint8 = 5
	I2CP_MSG_SEND_MESSAGE_EXPIRES      uint8 = 36
	I2CP_MSG_SESSION_STATUS            uint8 = 20
	I2CP_MSG_SET_DATE                  uint8 = 33
	I2CP_MSG_BLINDING_INFO             uint8 = 42
)

// Authentication Method Constants
// per I2CP specification for protocol initialization and authentication
//
// Support Status in go-i2cp:
//   - AUTH_METHOD_NONE (0):           ✅ Fully supported
//   - AUTH_METHOD_USERNAME_PWD (1):   ✅ Fully supported (via i2cp.username, i2cp.password)
//   - AUTH_METHOD_SSL_TLS (2):        ✅ Fully supported (via i2cp.SSL configuration)
//   - AUTH_METHOD_PER_CLIENT_DH (3):  ❌ Not yet implemented (planned for Phase 4)
//   - AUTH_METHOD_PER_CLIENT_PSK (4): ❌ Not yet implemented (planned for Phase 4)
const (
	AUTH_METHOD_NONE           uint8 = 0 // No authentication required
	AUTH_METHOD_USERNAME_PWD   uint8 = 1 // Username/password authentication (0.9.11+)
	AUTH_METHOD_SSL_TLS        uint8 = 2 // SSL/TLS certificate authentication (0.8.3+)
	AUTH_METHOD_PER_CLIENT_DH  uint8 = 3 // Per-client DH authentication (0.9.41+) - NOT IMPLEMENTED
	AUTH_METHOD_PER_CLIENT_PSK uint8 = 4 // Per-client PSK authentication (0.9.41+) - NOT IMPLEMENTED
)

// HostReply Error Codes (I2CP Proposal 167)
// per I2CP specification for HostReplyMessage error handling
const (
	HOST_REPLY_SUCCESS                   uint8 = 0 // Lookup successful
	HOST_REPLY_FAILURE                   uint8 = 1 // General lookup failure
	HOST_REPLY_PASSWORD_REQUIRED         uint8 = 2 // Password required for encrypted LeaseSet (since 0.9.43)
	HOST_REPLY_PRIVATE_KEY_REQUIRED      uint8 = 3 // Private key required for per-client auth (since 0.9.43)
	HOST_REPLY_PASSWORD_AND_KEY_REQUIRED uint8 = 4 // Both password and key required (since 0.9.43)
	HOST_REPLY_DECRYPTION_FAILURE        uint8 = 5 // Failed to decrypt LeaseSet (since 0.9.43)
	HOST_REPLY_LEASESET_LOOKUP_FAILURE   uint8 = 6 // LeaseSet not found in network database (since 0.9.66)
	HOST_REPLY_LOOKUP_TYPE_UNSUPPORTED   uint8 = 7 // Lookup type not supported by router (since 0.9.66)
)

// LeaseSet Type Constants
// per I2CP specification for CreateLeaseSet2Message
const (
	LEASESET_TYPE_LEGACY    uint8 = 1 // Legacy LeaseSet (deprecated)
	LEASESET_TYPE_STANDARD  uint8 = 3 // Standard LeaseSet2
	LEASESET_TYPE_ENCRYPTED uint8 = 5 // EncryptedLeaseSet
	LEASESET_TYPE_META      uint8 = 7 // MetaLeaseSet (preliminary)
)

// Blinding Authentication Scheme Constants
// per I2CP specification for BlindingInfoMessage authentication
//
// Blinding is used for encrypted LeaseSet access (I2CP 0.9.43+).
// The client sends BlindingInfoMessage to advise the router about blinded destinations
// with optional lookup passwords and/or private keys for decryption.
//
// Support Status in go-i2cp:
//   - BLINDING_AUTH_SCHEME_DH (0):  ✅ Supported via msgBlindingInfo()
//   - BLINDING_AUTH_SCHEME_PSK (1): ✅ Supported via msgBlindingInfo()
//
// Blinding workflow:
//  1. Client sends BlindingInfoMessage to router before messaging a blinded destination
//  2. Router uses the info to look up and decrypt the destination's LeaseSet
//  3. Router does NOT reply to this message
//
// Per SPEC.md § BlindingInfoMessage:
// "Before a client sends a message to a blinded destination, it must either lookup
// the 'b33' in a Host Lookup message, or send a Blinding Info message."
const (
	BLINDING_AUTH_SCHEME_DH  uint8 = 0 // Diffie-Hellman client authentication (or no per-client auth)
	BLINDING_AUTH_SCHEME_PSK uint8 = 1 // Pre-Shared Key client authentication
)

// Blinding Endpoint Type Constants
// per I2CP specification for BlindingInfoMessage endpoint identification
//
// The endpoint identifies which blinded destination the blinding info applies to.
// Different types allow specifying the destination by hash, hostname, full destination, or signing key.
const (
	BLINDING_ENDPOINT_HASH        uint8 = 0 // 32-byte SHA-256 hash of destination
	BLINDING_ENDPOINT_HOSTNAME    uint8 = 1 // hostname String (address book lookup)
	BLINDING_ENDPOINT_DESTINATION uint8 = 2 // full binary Destination
	BLINDING_ENDPOINT_SIGKEY      uint8 = 3 // 2-byte sig type + SigningPublicKey
)

// Blinding Flag Constants
// per I2CP specification for BlindingInfoMessage flags field
//
// Flags field is 1 byte with bit layout: 76543210
//   - Bit 0: 0=everybody, 1=per-client authentication
//   - Bits 3-1: Auth scheme (if bit 0 is 1), otherwise 000
//   - Bit 4: 1=secret (lookup password) required
//   - Bits 7-5: Reserved, must be 0
const (
	BLINDING_FLAG_PER_CLIENT    uint8 = 0x01 // Bit 0: per-client authentication enabled
	BLINDING_FLAG_SECRET        uint8 = 0x10 // Bit 4: lookup password required
	BLINDING_FLAG_AUTH_DH       uint8 = 0x00 // Bits 3-1: DH authentication (000)
	BLINDING_FLAG_AUTH_PSK      uint8 = 0x02 // Bits 3-1: PSK authentication (001)
	BLINDING_FLAG_AUTH_MASK     uint8 = 0x0E // Bits 3-1: authentication scheme mask
	BLINDING_FLAG_RESERVED_MASK uint8 = 0xE0 // Bits 7-5: reserved, must be 0
)

// SendMessageExpires Flag Constants
// per I2CP specification § SendMessageExpiresMessage (I2CP 0.8.4+)
//
// These flags control message delivery options for SendMessageExpiresMessage (type 36).
// The flags field is 2 bytes (16 bits) with the following layout (bit order 15...0):
//
//	Bits 15-11: Reserved, must be 0
//	Bits 10-9:  Message Reliability Override (DEPRECATED - unimplemented, to be removed)
//	Bit 8:      Don't bundle LeaseSet (SEND_MSG_FLAG_NO_LEASESET)
//	Bits 7-4:   Low tag threshold (ElGamal only, ignored for ECIES-Ratchet)
//	Bits 3-0:   Tags to send (ElGamal only, ignored for ECIES-Ratchet)
//
// IMPORTANT: ElGamal-specific flags (bits 7-0) are obsolete in modern I2P.
// As of I2CP 0.9.39+, all encryption uses ECIES-Ratchet, which does not use session tags.
// These flags are kept for backward compatibility but have no effect with ECIES-Ratchet.
//
// Usage Example:
//
//	flags := SEND_MSG_FLAG_NO_LEASESET | BuildSendMessageFlags(0, 0)
//	session.SendMessageExpires(dest, protocol, srcPort, destPort, payload, flags, expiration)
const (
	// Bit masks for validation
	SEND_MSG_FLAGS_RESERVED_MASK    uint16 = 0xF800 // Bits 15-11: reserved, must be 0
	SEND_MSG_FLAGS_RELIABILITY_MASK uint16 = 0x0600 // Bits 10-9: deprecated reliability override
	SEND_MSG_FLAGS_TAG_THRESHOLD    uint16 = 0x00F0 // Bits 7-4: low tag threshold (ElGamal only)
	SEND_MSG_FLAGS_TAG_COUNT        uint16 = 0x000F // Bits 3-0: tags to send (ElGamal only)

	// Bit 8: LeaseSet bundling control (the only modern flag still used)
	SEND_MSG_FLAG_NO_LEASESET uint16 = 0x0100 // Don't bundle LeaseSet with message
)

// SendMessageExpires Tag Threshold Values (ElGamal Only - OBSOLETE)
// per I2CP specification § SendMessageExpiresMessage Flags Field
//
// NOTE: These are only relevant for ElGamal encryption, which is deprecated.
// Modern ECIES-Ratchet encryption ignores these values. These constants are
// provided for completeness but should not be used in new code.
//
// Tag threshold: if there are fewer than this many tags available, send more.
// This is advisory and does not force tags to be delivered.
const (
	SEND_MSG_TAG_THRESHOLD_DEFAULT uint8 = 0  // Use session key manager settings
	SEND_MSG_TAG_THRESHOLD_2       uint8 = 1  // Threshold: 2 tags
	SEND_MSG_TAG_THRESHOLD_3       uint8 = 2  // Threshold: 3 tags
	SEND_MSG_TAG_THRESHOLD_6       uint8 = 3  // Threshold: 6 tags
	SEND_MSG_TAG_THRESHOLD_9       uint8 = 4  // Threshold: 9 tags
	SEND_MSG_TAG_THRESHOLD_14      uint8 = 5  // Threshold: 14 tags
	SEND_MSG_TAG_THRESHOLD_20      uint8 = 6  // Threshold: 20 tags
	SEND_MSG_TAG_THRESHOLD_27      uint8 = 7  // Threshold: 27 tags
	SEND_MSG_TAG_THRESHOLD_35      uint8 = 8  // Threshold: 35 tags
	SEND_MSG_TAG_THRESHOLD_45      uint8 = 9  // Threshold: 45 tags
	SEND_MSG_TAG_THRESHOLD_57      uint8 = 10 // Threshold: 57 tags
	SEND_MSG_TAG_THRESHOLD_72      uint8 = 11 // Threshold: 72 tags
	SEND_MSG_TAG_THRESHOLD_92      uint8 = 12 // Threshold: 92 tags
	SEND_MSG_TAG_THRESHOLD_117     uint8 = 13 // Threshold: 117 tags
	SEND_MSG_TAG_THRESHOLD_147     uint8 = 14 // Threshold: 147 tags
	SEND_MSG_TAG_THRESHOLD_192     uint8 = 15 // Threshold: 192 tags
)

// SendMessageExpires Tags to Send Values (ElGamal Only - OBSOLETE)
// per I2CP specification § SendMessageExpiresMessage Flags Field
//
// NOTE: These are only relevant for ElGamal encryption, which is deprecated.
// Modern ECIES-Ratchet encryption ignores these values. These constants are
// provided for completeness but should not be used in new code.
//
// Number of tags to send if required. This is advisory and does not force
// tags to be delivered.
const (
	SEND_MSG_TAG_COUNT_DEFAULT uint8 = 0  // Use session key manager settings
	SEND_MSG_TAG_COUNT_2       uint8 = 1  // Send 2 tags
	SEND_MSG_TAG_COUNT_4       uint8 = 2  // Send 4 tags
	SEND_MSG_TAG_COUNT_6       uint8 = 3  // Send 6 tags
	SEND_MSG_TAG_COUNT_8       uint8 = 4  // Send 8 tags
	SEND_MSG_TAG_COUNT_12      uint8 = 5  // Send 12 tags
	SEND_MSG_TAG_COUNT_16      uint8 = 6  // Send 16 tags
	SEND_MSG_TAG_COUNT_24      uint8 = 7  // Send 24 tags
	SEND_MSG_TAG_COUNT_32      uint8 = 8  // Send 32 tags
	SEND_MSG_TAG_COUNT_40      uint8 = 9  // Send 40 tags
	SEND_MSG_TAG_COUNT_51      uint8 = 10 // Send 51 tags
	SEND_MSG_TAG_COUNT_64      uint8 = 11 // Send 64 tags
	SEND_MSG_TAG_COUNT_80      uint8 = 12 // Send 80 tags
	SEND_MSG_TAG_COUNT_100     uint8 = 13 // Send 100 tags
	SEND_MSG_TAG_COUNT_125     uint8 = 14 // Send 125 tags
	SEND_MSG_TAG_COUNT_160     uint8 = 15 // Send 160 tags
)

// Router Capabilities Constants
// Moved from: client.go
const ROUTER_CAN_HOST_LOOKUP uint32 = 1

// Host Lookup Type Constants (I2CP § HostLookupMessage)
//
// Per I2CP 0.9.11+, extended in 0.9.66 with options mappings (Proposal 167 - Service Records).
//
// Basic lookups (types 0-1) resolve an I2P destination from either a hash or hostname.
// Service record lookups (types 2-4) additionally return the LeaseSet's options Mapping,
// which can contain service-specific metadata like protocol information.
//
// Router Version Requirements:
//   - Types 0-1: Require I2CP 0.9.11+ router
//   - Types 2-4: Require I2CP 0.9.66+ router (Proposal 167)
//
// Note: If the router does not support the requested lookup type, it returns
// HOST_REPLY_LOOKUP_TYPE_UNSUPPORTED (code 7).
const (
	HOST_LOOKUP_TYPE_HASH                  = 0 // Basic hash lookup (since 0.9.11)
	HOST_LOOKUP_TYPE_HOSTNAME              = 1 // Basic hostname lookup (since 0.9.11)
	HOST_LOOKUP_TYPE_HASH_WITH_OPTIONS     = 2 // Hash + LeaseSet options mapping (since 0.9.66)
	HOST_LOOKUP_TYPE_HOSTNAME_WITH_OPTIONS = 3 // Hostname + LeaseSet options mapping (since 0.9.66)
	HOST_LOOKUP_TYPE_DEST_WITH_OPTIONS     = 4 // Destination + LeaseSet options mapping (since 0.9.66)
)

// Certificate Type Constants
// Moved from: certificate.go
const (
	CERTIFICATE_NULL     uint8 = 0
	CERTIFICATE_HASHCASH uint8 = 1
	CERTIFICATE_SIGNED   uint8 = 2
	CERTIFICATE_MULTIPLE uint8 = 3
	CERTIFICATE_KEY      uint8 = 5
)

// Destination Size Constants
// Moved from: destination.go
const (
	PUB_KEY_SIZE = 256
	DIGEST_SIZE  = 32 // SHA-256 digest size for Ed25519
	DEST_SIZE    = 4096
)

// Hash Algorithm Constants
// Moved from: crypto.go
const (
	HASH_SHA1   uint8 = iota
	HASH_SHA256 uint8 = iota
)

// Signature Algorithm Constants
// Moved from: crypto.go
// Modern I2CP uses Ed25519 (type 7) exclusively
const (
	ED25519_SHA256 uint32 = 7
)

// Codec Algorithm Constants
// Moved from: crypto.go
const (
	CODEC_BASE32 uint8 = iota
	CODEC_BASE64 uint8 = iota
)

// Key Exchange Algorithm Constants
const (
	X25519 uint32 = 4
)

// Encryption Algorithm Constants
const (
	CHACHA20_POLY1305 uint32 = 4
)

// TLS Configuration
//
// TLS support is controlled via client properties, not a global constant.
// The legacy USE_TLS constant has been removed in favor of per-client configuration.
//
// To enable TLS, set these client properties:
//   - i2cp.SSL="true"                  // Enable TLS connection to router
//   - i2cp.SSL.certFile="path/to/cert" // Client certificate (optional)
//   - i2cp.SSL.keyFile="path/to/key"   // Client private key (optional)
//   - i2cp.SSL.caFile="path/to/ca"     // CA certificate (optional, system pool used as fallback)
//   - i2cp.SSL.insecure="false"        // Skip certificate verification (DEV ONLY, default: false)
//
// For details, see client.go SetProperty() and tcp.go SetupTLS().

// Logger Level Constants
// Moved from: logger.go
const (
	PROTOCOL = 1 << 0
	LOGIC    = 1 << 1

	DEBUG   = 1 << 4
	INFO    = 1 << 5
	WARNING = 1 << 6
	ERROR   = 1 << 7
	FATAL   = 1 << 8

	STRINGMAP      = 1 << 9
	INTMAP         = 1 << 10
	QUEUE          = 1 << 11
	STREAM         = 1 << 12
	CRYPTO         = 1 << 13
	TCP            = 1 << 14
	CLIENT         = 1 << 15
	CERTIFICATE    = 1 << 16
	LEASE          = 1 << 17
	DESTINATION    = 1 << 18
	SESSION        = 1 << 19
	SESSION_CONFIG = 1 << 20
	TEST           = 1 << 21
	DATAGRAM       = 1 << 22
	CONFIG_FILE    = 1 << 23
	VERSION        = 1 << 24

	TAG_MASK       = 0x0000000f
	LEVEL_MASK     = 0x000001f0
	COMPONENT_MASK = 0xfffffe00

	ALL = 0xffffffff
)

// Tag Constants
// Moved from: crypto.go, destination.go, client.go
const (
	tAG = CRYPTO
	tag = DESTINATION
	TAG = CLIENT
)

// MessageStatus Codes (I2CP MessageStatusMessage)
// Complete status codes 0-23 per I2CP specification
// Used in MessageStatusMessage (type 22) to report delivery status
const (
	MSG_STATUS_AVAILABLE                uint8 = 0  // DEPRECATED: Message available for pickup
	MSG_STATUS_ACCEPTED                 uint8 = 1  // Message accepted by router
	MSG_STATUS_BEST_EFFORT_SUCCESS      uint8 = 2  // Best-effort delivery succeeded
	MSG_STATUS_BEST_EFFORT_FAILURE      uint8 = 3  // Best-effort delivery failed
	MSG_STATUS_GUARANTEED_SUCCESS       uint8 = 4  // Guaranteed delivery succeeded
	MSG_STATUS_GUARANTEED_FAILURE       uint8 = 5  // Guaranteed delivery failed
	MSG_STATUS_LOCAL_SUCCESS            uint8 = 6  // Local delivery succeeded
	MSG_STATUS_LOCAL_FAILURE            uint8 = 7  // Local delivery failed
	MSG_STATUS_ROUTER_FAILURE           uint8 = 8  // Router error
	MSG_STATUS_NETWORK_FAILURE          uint8 = 9  // Network error
	MSG_STATUS_BAD_SESSION              uint8 = 10 // Invalid session ID
	MSG_STATUS_BAD_MESSAGE              uint8 = 11 // Malformed message
	MSG_STATUS_OVERFLOW_FAILURE         uint8 = 12 // Queue overflow
	MSG_STATUS_MESSAGE_EXPIRED          uint8 = 13 // Message expired
	MSG_STATUS_BAD_LOCAL_LEASESET       uint8 = 14 // Local LeaseSet invalid
	MSG_STATUS_NO_LOCAL_TUNNELS         uint8 = 15 // No local tunnels available
	MSG_STATUS_UNSUPPORTED_ENCRYPTION   uint8 = 16 // Encryption type unsupported
	MSG_STATUS_BAD_DESTINATION          uint8 = 17 // Destination invalid
	MSG_STATUS_BAD_LEASESET             uint8 = 18 // Remote LeaseSet invalid
	MSG_STATUS_EXPIRED_LEASESET         uint8 = 19 // Remote LeaseSet expired
	MSG_STATUS_NO_LEASESET              uint8 = 20 // Remote LeaseSet not found
	MSG_STATUS_SEND_BEST_EFFORT_FAILURE uint8 = 21 // Send best-effort failed (since 0.9.37)
	MSG_STATUS_META_LEASESET            uint8 = 22 // MetaLeaseSet received (since 0.9.41)
	MSG_STATUS_LOOPBACK_DENIED          uint8 = 23 // Loopback message denied (since 0.9.62)
)

// Legacy type alias for backward compatibility
// DEPRECATED: Use uint8 MSG_STATUS_* constants directly
type SessionMessageStatus = uint8

// IsMessageStatusSuccess returns true if the message status indicates successful delivery.
// Success statuses include accepted, best-effort success, guaranteed success, and local success.
func IsMessageStatusSuccess(status SessionMessageStatus) bool {
	switch status {
	case MSG_STATUS_ACCEPTED,
		MSG_STATUS_BEST_EFFORT_SUCCESS,
		MSG_STATUS_GUARANTEED_SUCCESS,
		MSG_STATUS_LOCAL_SUCCESS:
		return true
	}
	return false
}

// IsMessageStatusFailure returns true if the message status indicates a delivery failure.
// This includes all failure codes except transient/retriable failures.
func IsMessageStatusFailure(status SessionMessageStatus) bool {
	switch status {
	case MSG_STATUS_BEST_EFFORT_FAILURE,
		MSG_STATUS_GUARANTEED_FAILURE,
		MSG_STATUS_LOCAL_FAILURE,
		MSG_STATUS_ROUTER_FAILURE,
		MSG_STATUS_BAD_SESSION,
		MSG_STATUS_BAD_MESSAGE,
		MSG_STATUS_MESSAGE_EXPIRED,
		MSG_STATUS_BAD_LOCAL_LEASESET,
		MSG_STATUS_UNSUPPORTED_ENCRYPTION,
		MSG_STATUS_BAD_DESTINATION,
		MSG_STATUS_BAD_LEASESET,
		MSG_STATUS_EXPIRED_LEASESET,
		MSG_STATUS_NO_LEASESET,
		MSG_STATUS_SEND_BEST_EFFORT_FAILURE,
		MSG_STATUS_LOOPBACK_DENIED:
		return true
	}
	return false
}

// IsMessageStatusRetriable returns true if the message status indicates a transient failure
// that may succeed if retried later. This includes queue overflow, network failures,
// and temporary tunnel unavailability.
func IsMessageStatusRetriable(status SessionMessageStatus) bool {
	switch status {
	case MSG_STATUS_OVERFLOW_FAILURE, // Queue full - retry later
		MSG_STATUS_NO_LOCAL_TUNNELS, // Tunnels building - retry
		MSG_STATUS_NETWORK_FAILURE:  // Transient network error
		return true
	}
	return false
}

// GetMessageStatusCategory returns a human-readable category for the message status.
// Categories: "success", "failure", "retriable", "pending", or "unknown"
func GetMessageStatusCategory(status SessionMessageStatus) string {
	if IsMessageStatusSuccess(status) {
		return "success"
	}
	if IsMessageStatusRetriable(status) {
		return "retriable"
	}
	if IsMessageStatusFailure(status) {
		return "failure"
	}
	if status == MSG_STATUS_AVAILABLE {
		return "pending" // Deprecated status
	}
	if status == MSG_STATUS_META_LEASESET {
		return "meta" // Special status for MetaLeaseSet
	}
	return "unknown"
}

// Session Status Constants
// I2CP specification: SessionStatusMessage (type 20) status field values
// Per https://geti2p.net/spec/i2cp#sessionstatusmessage:
//
//	0 = Destroyed - The session with the given ID is terminated
//	1 = Created - In response to CreateSessionMessage, a new session is now active
//	2 = Updated - In response to ReconfigureSessionMessage
//	3 = Invalid - The configuration is invalid
//	4 = Refused - Router was unable to create the session (0.9.12+)
type SessionStatus int

const (
	I2CP_SESSION_STATUS_DESTROYED SessionStatus = 0 // 0 - Session destroyed
	I2CP_SESSION_STATUS_CREATED   SessionStatus = 1 // 1 - Session created successfully
	I2CP_SESSION_STATUS_UPDATED   SessionStatus = 2 // 2 - Session configuration updated
	I2CP_SESSION_STATUS_INVALID   SessionStatus = 3 // 3 - Session invalid (see errors.go: ErrSessionInvalid)
	I2CP_SESSION_STATUS_REFUSED   SessionStatus = 4 // 4 - Session creation refused (0.9.12+, see errors.go: ErrSessionRefused)
)

// getSessionStatusName returns a human-readable name for SessionStatus values.
// This is useful for debugging and logging session state transitions.
func getSessionStatusName(status SessionStatus) string {
	switch status {
	case I2CP_SESSION_STATUS_CREATED:
		return "CREATED"
	case I2CP_SESSION_STATUS_DESTROYED:
		return "DESTROYED"
	case I2CP_SESSION_STATUS_UPDATED:
		return "UPDATED"
	case I2CP_SESSION_STATUS_INVALID:
		return "INVALID"
	case I2CP_SESSION_STATUS_REFUSED:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}
