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
	I2CP_CLIENT_VERSION                = "0.9.33"
	I2CP_PROTOCOL_INIT           uint8 = 0x2a
	I2CP_MESSAGE_SIZE                  = 0xffff
	I2CP_MAX_SESSIONS                  = 0xffff
	I2CP_MAX_SESSIONS_PER_CLIENT       = 32
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
// When a router sends BlindingInfo to a client, it indicates the authentication
// scheme and parameters required to access an encrypted LeaseSet.
//
// Support Status in go-i2cp:
//   - BLINDING_AUTH_SCHEME_DH (0):  ⚠️  Partial (storage only, crypto pending Phase 4)
//   - BLINDING_AUTH_SCHEME_PSK (1): ⚠️  Partial (storage only, crypto pending Phase 4)
//
// Blinding workflow:
//  1. Router sends BlindingInfoMessage with scheme, flags, and parameters
//  2. Client stores blinding info in session (via SetBlindingInfo)
//  3. Client uses blinding parameters when creating encrypted LeaseSet2
//  4. Encrypted LeaseSet2 requires password or key for access
const (
	BLINDING_AUTH_SCHEME_DH  uint8 = 0 // Diffie-Hellman authentication
	BLINDING_AUTH_SCHEME_PSK uint8 = 1 // Pre-Shared Key authentication
)

// Router Capabilities Constants
// Moved from: client.go
const ROUTER_CAN_HOST_LOOKUP uint32 = 1

// Host Lookup Type Constants
// Moved from: client.go
const (
	HOST_LOOKUP_TYPE_HASH = iota
	HOST_LOOKUP_TYPE_HOST = iota
)

// Certificate Type Constants
// Moved from: certificate.go
const (
	CERTIFICATE_NULL     uint8 = iota
	CERTIFICATE_HASHCASH uint8 = iota
	CERTIFICATE_SIGNED   uint8 = iota
	CERTIFICATE_MULTIPLE uint8 = iota
)

// Destination Size Constants
// Moved from: destination.go
const (
	PUB_KEY_SIZE          = 256
	DSA_SHA1_PUB_KEY_SIZE = 128
	DIGEST_SIZE           = 40
	DEST_SIZE             = 4096
)

// Hash Algorithm Constants
// Moved from: crypto.go
const (
	HASH_SHA1   uint8 = iota
	HASH_SHA256 uint8 = iota
)

// Signature Algorithm Constants
// Moved from: crypto.go
const (
	DSA_SHA1       uint32 = iota
	DSA_SHA256     uint32 = iota
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
	X25519 uint32 = 3
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

// Session Status Constants
// Moved from: session.go
type SessionStatus int

const (
	I2CP_SESSION_STATUS_DESTROYED SessionStatus = iota
	I2CP_SESSION_STATUS_CREATED
	I2CP_SESSION_STATUS_UPDATED
	I2CP_SESSION_STATUS_INVALID
)
