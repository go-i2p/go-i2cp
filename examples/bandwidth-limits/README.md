# Bandwidth Limits Example

This example demonstrates how to use the I2CP BandwidthLimits callback to implement rate limiting in your application based on bandwidth constraints reported by the I2P router.

## Overview

The I2P router sends bandwidth limits information to connected clients via the BandwidthLimitsMessage (type 23). This example shows:

1. **Setting up a callback** to receive bandwidth limit updates from the router
2. **Implementing a token bucket rate limiter** to enforce bandwidth constraints
3. **Adapting application behavior** based on router-reported limits

## What You'll Learn

- How to register the `OnBandwidthLimits` callback
- Understanding the `BandwidthLimits` structure fields
- Implementing token bucket rate limiting
- Adapting to dynamic bandwidth changes

## Running the Example

### Prerequisites

- I2P router running locally with I2CP enabled (default: `127.0.0.1:7654`)
- Go 1.19 or later

### Run

```bash
cd examples/bandwidth-limits
go run bandwidth_limits_example.go
```

### With Custom Router

```bash
I2CP_ROUTER_HOST=192.168.1.100 I2CP_ROUTER_PORT=7654 go run bandwidth_limits_example.go
```

## Code Walkthrough

### 1. BandwidthLimits Structure

The router sends these fields:

```go
type BandwidthLimits struct {
    ClientInbound       uint32    // Your application's inbound limit (bytes/sec)
    ClientOutbound      uint32    // Your application's outbound limit (bytes/sec)
    RouterInbound       uint32    // Router's total inbound limit (bytes/sec)
    RouterInboundBurst  uint32    // Router's inbound burst size (bytes)
    RouterOutbound      uint32    // Router's total outbound limit (bytes/sec)
    RouterOutboundBurst uint32    // Router's outbound burst size (bytes)
    BurstTime           uint32    // Burst time window (seconds)
    Undefined           [9]uint32 // Reserved for future use
}
```

### 2. Registering the Callback

```go
callbacks := &i2cp.ClientCallBacks{
    OnBandwidthLimits: func(client *i2cp.Client, limits *i2cp.BandwidthLimits) {
        fmt.Printf("Received limits: %s\n", limits.String())
        // Update your rate limiters here
    },
}

client := i2cp.NewClient(callbacks)
```

### 3. Token Bucket Rate Limiter

The example implements a simple token bucket algorithm:

- **Tokens per second**: Based on bandwidth limit
- **Burst size**: Allows temporary exceeding of base rate
- **Refill**: Tokens automatically refill over time

```go
limiter := NewRateLimiter(tokensPerSec, burst)
if limiter.Allow(packetSize) {
    // Proceed with sending
} else {
    // Rate limited - defer or drop
}
```

### 4. Bandwidth Manager

Coordinates inbound and outbound rate limiting:

```go
bwManager := NewBandwidthManager()

// Update when router sends new limits
bwManager.UpdateLimits(limits)

// Check before operations
if bwManager.CanSend(dataSize) {
    // Send data
}
```

## I2CP Protocol Details

**Message Type:** 23 (BandwidthLimitsMessage)  
**Direction:** Router → Client  
**Since:** I2CP 0.9.3+

The router sends this message:
- Shortly after connection establishment
- When bandwidth allocation changes
- Periodically (router-dependent)

## Practical Applications

### 1. Adaptive Streaming
Adjust video/audio quality based on available bandwidth:

```go
OnBandwidthLimits: func(client *i2cp.Client, limits *i2cp.BandwidthLimits) {
    if limits.ClientOutbound < 100000 {
        streamQuality = "low"
    } else if limits.ClientOutbound < 500000 {
        streamQuality = "medium"
    } else {
        streamQuality = "high"
    }
}
```

### 2. Batch Processing
Delay non-urgent operations during bandwidth constraints:

```go
if !bwManager.CanSend(batchSize) {
    queue.Defer(batch)  // Process later
}
```

### 3. Multi-Client Coordination
For applications with multiple I2CP connections, distribute limits:

```go
perClientLimit := limits.RouterOutbound / uint32(numClients)
```

## Expected Output

```
I2CP Bandwidth Limits Example
=============================

Connecting to I2P router at 127.0.0.1:7654...
Connected to I2P router!

Waiting for bandwidth limits message from router...
(The router should send this automatically after connection)

[Router] Received bandwidth limits:
  BandwidthLimits{Client: 512000/512000, Router: 1024000(2048000)/1024000(2048000), Burst: 10s}
[BandwidthManager] Updated limits: IN=512000(2048000) OUT=512000(2048000)

[Demo] Simulating data transfer with rate limiting...
  ✓ Allowed to send 1024 bytes
  ✓ Allowed to send 4096 bytes
  ✓ Allowed to send 16384 bytes
  ✓ Allowed to send 65536 bytes
  ✗ Rate limited - cannot send 262144 bytes (would exceed limit)
```

## Notes

- **Zero values**: If `ClientInbound/Outbound` are 0, fall back to `RouterInbound/Outbound`
- **Burst limits**: Allow temporary spikes within `BurstTime` window
- **Undefined fields**: Reserved for future protocol extensions, currently unused
- **Thread safety**: The example's rate limiter uses mutexes for concurrent access

## Further Reading

- [I2CP Specification](https://geti2p.net/spec/i2cp)
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [COMPLIANCE.md](../../COMPLIANCE.md) - Protocol compliance details
- [ROADMAP.md](../../ROADMAP.md) - Future enhancements roadmap

## License

Same as parent project (see LICENSE file in repository root).
