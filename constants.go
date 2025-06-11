package go_i2cp

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
	I2CP_MSG_RECONFIGURE_SESSION       uint8 = 2
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
const (
	AUTH_METHOD_NONE           uint8 = 0 // No authentication required
	AUTH_METHOD_USERNAME_PWD   uint8 = 1 // Username/password authentication (0.9.11+)
	AUTH_METHOD_SSL_TLS        uint8 = 2 // SSL/TLS certificate authentication (0.8.3+)
	AUTH_METHOD_PER_CLIENT_DH  uint8 = 3 // Per-client DH authentication (0.9.41+)
	AUTH_METHOD_PER_CLIENT_PSK uint8 = 4 // Per-client PSK authentication (0.9.41+)
)

// Host Lookup Result Codes
// per I2CP specification for HostReplyMessage error handling
const (
	HOST_LOOKUP_RESULT_SUCCESS          uint8 = 0 // Lookup successful
	HOST_LOOKUP_RESULT_NOT_FOUND        uint8 = 1 // Destination not found
	HOST_LOOKUP_RESULT_TIMEOUT          uint8 = 2 // Lookup timed out
	HOST_LOOKUP_RESULT_INVALID_KEY      uint8 = 3 // Invalid lookup key format
	HOST_LOOKUP_RESULT_INVALID_SESSION  uint8 = 4 // Invalid session ID
	HOST_LOOKUP_RESULT_UNSUPPORTED_TYPE uint8 = 5 // Unsupported lookup type
	HOST_LOOKUP_RESULT_NETWORK_ERROR    uint8 = 6 // Network connectivity issue
	HOST_LOOKUP_RESULT_GENERIC_ERROR    uint8 = 7 // Generic lookup failure
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
const (
	BLINDING_AUTH_SCHEME_DH  uint8 = 0 // Diffie-Hellman authentication
	BLINDING_AUTH_SCHEME_PSK uint8 = 1 // Pre-Shared Key authentication
)

// Router Capabilities Constants
// Moved from: client.go
const ROUTER_CAN_HOST_LOOKUP uint32 = 1

// Protocol Constants
// Moved from: client.go
const (
	PROTOCOL_STREAMING    = 6
	PROTOCOL_DATAGRAM     = 17
	PROTOCOL_RAW_DATAGRAM = 18
)

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
	PUB_KEY_SIZE = 256
	DIGEST_SIZE  = 40
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

// TLS Constants
// Moved from: tcp.go
const USE_TLS = false

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

// Session Message Status Constants
// Moved from: session.go
type SessionMessageStatus int

const (
	I2CP_MSG_STATUS_AVAILABLE SessionMessageStatus = iota
	I2CP_MSG_STATUS_ACCEPTED
	I2CP_MSG_STATUS_BEST_EFFORT_SUCCESS
	I2CP_MSG_STATUS_BEST_EFFORT_FAILURE
	I2CP_MSG_STATUS_GUARANTEED_SUCCESS
	I2CP_MSG_STATUS_GUARANTEED_FAILURE
	I2CP_MSG_STATUS_LOCAL_SUCCESS
	I2CP_MSG_STATUS_LOCAL_FAILURE
	I2CP_MSG_STATUS_ROUTER_FAILURE
	I2CP_MSG_STATUS_NETWORK_FAILURE
	I2CP_MSG_STATUS_BAD_SESSION
	I2CP_MSG_STATUS_BAD_MESSAGE
	I2CP_MSG_STATUS_OVERFLOW_FAILURE
	I2CP_MSG_STATUS_MESSAGE_EXPIRED
	I2CP_MSG_STATUS_MESSAGE_BAD_LOCAL_LEASESET
	I2CP_MSG_STATUS_MESSAGE_NO_LOCAL_TUNNELS
	I2CP_MSG_STATUS_MESSAGE_UNSUPPORTED_ENCRYPTION
	I2CP_MSG_STATUS_MESSAGE_BAD_DESTINATION
	I2CP_MSG_STATUS_MESSAGE_BAD_LEASESET
	I2CP_MSG_STATUS_MESSAGE_EXPIRED_LEASESET
	I2CP_MSG_STATUS_MESSAGE_NO_LEASESET
)

// Session Status Constants
// Moved from: session.go
type SessionStatus int

const (
	I2CP_SESSION_STATUS_DESTROYED SessionStatus = iota
	I2CP_SESSION_STATUS_CREATED
	I2CP_SESSION_STATUS_UPDATED
	I2CP_SESSION_STATUS_INVALID
)
