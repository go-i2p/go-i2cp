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
	// ClientInbound is the maximum inbound bandwidth for the client in kilobytes per second (KBps).
	// This limit applies to data received by the client application.
	ClientInbound uint32

	// ClientOutbound is the maximum outbound bandwidth for the client in kilobytes per second (KBps).
	// This limit applies to data sent by the client application.
	ClientOutbound uint32

	// RouterInbound is the router's maximum inbound bandwidth in kilobytes per second (KBps).
	// This is the router's overall limit, shared across all clients.
	RouterInbound uint32

	// RouterInboundBurst is the maximum burst bandwidth for inbound router traffic in kilobytes per second (KBps).
	// This allows temporary exceeding of the RouterInbound baseline rate during the BurstTime window.
	// Per I2CP spec § BandwidthLimitsMessage: This is a RATE (KBps), not a size (bytes).
	RouterInboundBurst uint32

	// RouterOutbound is the router's maximum outbound bandwidth in kilobytes per second (KBps).
	// This is the router's overall limit, shared across all clients.
	RouterOutbound uint32

	// RouterOutboundBurst is the maximum burst bandwidth for outbound router traffic in kilobytes per second (KBps).
	// This allows temporary exceeding of the RouterOutbound baseline rate during the BurstTime window.
	// Per I2CP spec § BandwidthLimitsMessage: This is a RATE (KBps), not a size (bytes).
	RouterOutboundBurst uint32

	// BurstTime is the time window in seconds over which burst limits are calculated.
	// For example, if BurstTime=10 and RouterInboundBurst=100, the router can
	// burst up to 100 KBps over any 10-second window before throttling.
	BurstTime uint32

	// Undefined contains 9 reserved 32-bit fields for future protocol extensions.
	//
	// Per I2CP BandwidthLimitsMessage specification, these fields are currently
	// undefined and reserved for future protocol versions. They must be:
	//   - Parsed by clients for forward compatibility
	//   - Set to 0 by routers in current protocol versions
	//   - Ignored by clients until a future I2CP version defines their meaning
	//
	// Possible future uses (speculative, not in current spec):
	//   - Per-destination bandwidth limits
	//   - Quality of service parameters
	//   - Tunnel-specific bandwidth allocation
	//   - Congestion control hints
	//
	// Applications should NOT rely on these fields until officially specified.
	Undefined [9]uint32
}

// String returns a human-readable representation of the bandwidth limits.
// Format: BandwidthLimits{Client: inbound/outbound KBps, Router: inbound(burst)/outbound(burst) KBps, Burst: Ns}
func (b *BandwidthLimits) String() string {
	return fmt.Sprintf("BandwidthLimits{Client: %d/%d KBps, Router: %d(%d)/%d(%d) KBps, Burst: %ds}",
		b.ClientInbound, b.ClientOutbound,
		b.RouterInbound, b.RouterInboundBurst,
		b.RouterOutbound, b.RouterOutboundBurst,
		b.BurstTime)
}

// kbpsToBytesPerSec converts kilobytes per second to bytes per second.
// Helper function used by all BytesPerSecond getter methods to avoid duplication.
func kbpsToBytesPerSec(kbps uint32) int {
	return int(kbps) * 1024
}

// InboundBytesPerSecond returns the client inbound limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) InboundBytesPerSecond() int {
	return kbpsToBytesPerSec(b.ClientInbound)
}

// OutboundBytesPerSecond returns the client outbound limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) OutboundBytesPerSecond() int {
	return kbpsToBytesPerSec(b.ClientOutbound)
}

// RouterInboundBytesPerSecond returns the router inbound limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) RouterInboundBytesPerSecond() int {
	return kbpsToBytesPerSec(b.RouterInbound)
}

// RouterOutboundBytesPerSecond returns the router outbound limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) RouterOutboundBytesPerSecond() int {
	return kbpsToBytesPerSec(b.RouterOutbound)
}

// RouterInboundBurstBytesPerSecond returns the router inbound burst limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) RouterInboundBurstBytesPerSecond() int {
	return kbpsToBytesPerSec(b.RouterInboundBurst)
}

// RouterOutboundBurstBytesPerSecond returns the router outbound burst limit in bytes per second.
// Converts from KBps (as transmitted in I2CP protocol) to bytes/sec.
func (b *BandwidthLimits) RouterOutboundBurstBytesPerSecond() int {
	return kbpsToBytesPerSec(b.RouterOutboundBurst)
}
