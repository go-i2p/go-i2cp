package go_i2cp

// RouterInfo contains information about the I2P router.
// Moved from: client.go
//
// MINOR FIX: Router Version Tracking Documentation
// Per I2CP § Set Date (0.8.7+) and § Version Notes:
// The router sends its I2CP API version string in SetDateMessage, which clients
// should use for feature detection and compatibility checks.
//
// Router Version Features by Release:
//   - 0.8.7+:  Version exchange in Get/Set Date messages
//   - 0.9.4+:  Fast receive mode (deprecates ReceiveMessageBegin/End)
//   - 0.9.7+:  RequestVariableLeaseSet (deprecates RequestLeaseSet)
//   - 0.9.11+: HostLookup/HostReply with session IDs (deprecates DestLookup/DestReply)
//   - 0.9.21+: Enhanced bandwidth limits, session reconfiguration
//   - 0.9.38+: ECIES-X25519 encryption support
//   - 0.9.46+: BlindingInfoMessage, offline signature keys
//   - 0.9.56+: MetaLeaseSet support
//
// The Client uses router.version for automatic feature detection:
//   - HostLookup vs DestLookup selection (0.9.11+ check)
//   - Authentication method validation (0.9.46+ for auth 3-4)
//   - Bandwidth limits interpretation (0.9.21+ enhanced features)
//
// This enables graceful degradation when connecting to older routers and
// prevents use of unsupported features that would cause protocol errors.
type RouterInfo struct {
	date         uint64  // Router time in milliseconds since epoch (from SetDateMessage)
	version      Version // I2CP protocol version parsed from SetDateMessage
	capabilities uint32  // Feature flags (e.g., ROUTER_CAN_HOST_LOOKUP for 0.9.11+)
}
