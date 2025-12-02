package go_i2cp

import "fmt"

// BandwidthLimits represents bandwidth limitation parameters received from the I2P router.
// This structure contains both client-side and router-side bandwidth limits, plus burst
// parameters that control how bandwidth constraints are enforced.
//
// I2CP Specification: BandwidthLimitsMessage (type 23)
// Introduced in I2CP 0.9.3+ to communicate bandwidth constraints from router to client.
//
// Fields represent bytes/second unless otherwise noted. Burst parameters allow temporary
// exceeding of base limits for bursty traffic patterns.
type BandwidthLimits struct {
	// ClientInbound is the maximum inbound bandwidth for the client in bytes/second.
	// This limit applies to data received by the client application.
	ClientInbound uint32

	// ClientOutbound is the maximum outbound bandwidth for the client in bytes/second.
	// This limit applies to data sent by the client application.
	ClientOutbound uint32

	// RouterInbound is the router's maximum inbound bandwidth in bytes/second.
	// This is the router's overall limit, shared across all clients.
	RouterInbound uint32

	// RouterInboundBurst is the maximum burst size for inbound router traffic in bytes.
	// Allows temporary exceeding of RouterInbound limit.
	RouterInboundBurst uint32

	// RouterOutbound is the router's maximum outbound bandwidth in bytes/second.
	// This is the router's overall limit, shared across all clients.
	RouterOutbound uint32

	// RouterOutboundBurst is the maximum burst size for outbound router traffic in bytes.
	// Allows temporary exceeding of RouterOutbound limit.
	RouterOutboundBurst uint32

	// BurstTime is the time window in seconds over which burst limits are calculated.
	// For example, if BurstTime=10 and RouterInboundBurst=100KB, the router can
	// receive up to 100KB over any 10-second window before throttling.
	BurstTime uint32

	// Undefined contains 9 reserved fields for future protocol extensions.
	// Per I2CP spec, these are currently unused but must be parsed for forward compatibility.
	Undefined [9]uint32
}

// String returns a human-readable representation of the bandwidth limits.
// Format: BandwidthLimits{Client: inbound/outbound, Router: inbound(burst)/outbound(burst), Burst: Ns}
func (b *BandwidthLimits) String() string {
	return fmt.Sprintf("BandwidthLimits{Client: %d/%d, Router: %d(%d)/%d(%d), Burst: %ds}",
		b.ClientInbound, b.ClientOutbound,
		b.RouterInbound, b.RouterInboundBurst,
		b.RouterOutbound, b.RouterOutboundBurst,
		b.BurstTime)
}
