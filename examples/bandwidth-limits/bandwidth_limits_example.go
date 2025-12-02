package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// RateLimiter implements a simple token bucket rate limiter based on bandwidth limits
type RateLimiter struct {
	mu           sync.Mutex
	tokensPerSec uint32
	burst        uint32
	tokens       float64
	lastUpdate   time.Time
}

// NewRateLimiter creates a new rate limiter with specified tokens/sec and burst size
func NewRateLimiter(tokensPerSec, burst uint32) *RateLimiter {
	return &RateLimiter{
		tokensPerSec: tokensPerSec,
		burst:        burst,
		tokens:       float64(burst),
		lastUpdate:   time.Now(),
	}
}

// Allow checks if n tokens can be consumed, returning true if allowed
func (rl *RateLimiter) Allow(n uint32) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.lastUpdate = now

	// Add tokens based on elapsed time
	rl.tokens += elapsed * float64(rl.tokensPerSec)
	if rl.tokens > float64(rl.burst) {
		rl.tokens = float64(rl.burst)
	}

	// Check if we have enough tokens
	if rl.tokens >= float64(n) {
		rl.tokens -= float64(n)
		return true
	}

	return false
}

// Update updates the rate limiter parameters
func (rl *RateLimiter) Update(tokensPerSec, burst uint32) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.tokensPerSec = tokensPerSec
	rl.burst = burst
}

// BandwidthManager manages rate limiting based on router bandwidth limits
type BandwidthManager struct {
	inboundLimiter  *RateLimiter
	outboundLimiter *RateLimiter
	mu              sync.RWMutex
	lastUpdate      time.Time
}

// NewBandwidthManager creates a new bandwidth manager with default unlimited settings
func NewBandwidthManager() *BandwidthManager {
	return &BandwidthManager{
		inboundLimiter:  NewRateLimiter(1000000, 2000000), // 1MB/s, 2MB burst
		outboundLimiter: NewRateLimiter(1000000, 2000000),
		lastUpdate:      time.Now(),
	}
}

// UpdateLimits updates rate limiters based on bandwidth limits from router
func (bm *BandwidthManager) UpdateLimits(limits *i2cp.BandwidthLimits) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Use client-specific limits if available, otherwise fall back to router limits
	inbound := limits.ClientInbound
	if inbound == 0 {
		inbound = limits.RouterInbound
	}
	inboundBurst := limits.RouterInboundBurst
	if inboundBurst == 0 {
		inboundBurst = inbound * 2 // Default to 2x rate as burst
	}

	outbound := limits.ClientOutbound
	if outbound == 0 {
		outbound = limits.RouterOutbound
	}
	outboundBurst := limits.RouterOutboundBurst
	if outboundBurst == 0 {
		outboundBurst = outbound * 2
	}

	bm.inboundLimiter.Update(inbound, inboundBurst)
	bm.outboundLimiter.Update(outbound, outboundBurst)
	bm.lastUpdate = time.Now()

	fmt.Printf("[BandwidthManager] Updated limits: IN=%d(%d) OUT=%d(%d)\n",
		inbound, inboundBurst, outbound, outboundBurst)
}

// CanSend checks if we can send n bytes based on current outbound limit
func (bm *BandwidthManager) CanSend(n uint32) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.outboundLimiter.Allow(n)
}

// CanReceive checks if we can receive n bytes based on current inbound limit
func (bm *BandwidthManager) CanReceive(n uint32) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.inboundLimiter.Allow(n)
}

func main() {
	fmt.Println("I2CP Bandwidth Limits Example")
	fmt.Println("=============================")
	fmt.Println()

	// Create bandwidth manager
	bwManager := NewBandwidthManager()

	// Create client with bandwidth limits callback
	callbacks := &i2cp.ClientCallBacks{
		OnBandwidthLimits: func(client *i2cp.Client, limits *i2cp.BandwidthLimits) {
			fmt.Println("\n[Router] Received bandwidth limits:")
			fmt.Printf("  %s\n", limits.String())

			// Update our rate limiters based on router limits
			bwManager.UpdateLimits(limits)
		},
	}

	client := i2cp.NewClient(callbacks)

	// Configure connection (use environment variables or defaults)
	routerHost := os.Getenv("I2CP_ROUTER_HOST")
	if routerHost == "" {
		routerHost = "127.0.0.1"
	}
	routerPort := os.Getenv("I2CP_ROUTER_PORT")
	if routerPort == "" {
		routerPort = "7654"
	}

	client.SetProperty("i2cp.tcp.host", routerHost)
	client.SetProperty("i2cp.tcp.port", routerPort)

	fmt.Printf("Connecting to I2P router at %s:%s...\n", routerHost, routerPort)

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to I2P router: %v", err)
	}

	fmt.Println("Connected to I2P router!")
	fmt.Println("\nWaiting for bandwidth limits message from router...")
	fmt.Println("(The router should send this automatically after connection)")

	// Demonstrate rate limiting in action
	go func() {
		time.Sleep(2 * time.Second)
		fmt.Println("\n[Demo] Simulating data transfer with rate limiting...")

		// Simulate sending various packet sizes
		testSizes := []uint32{1024, 4096, 16384, 65536, 262144}
		for _, size := range testSizes {
			if bwManager.CanSend(size) {
				fmt.Printf("  ✓ Allowed to send %d bytes\n", size)
			} else {
				fmt.Printf("  ✗ Rate limited - cannot send %d bytes (would exceed limit)\n", size)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	select {
	case <-sigChan:
		fmt.Println("\n\nReceived interrupt, shutting down...")
	case <-time.After(10 * time.Second):
		fmt.Println("\n\nTimeout reached, shutting down...")
	}

	// Cleanup
	client.Close()
	fmt.Println("Disconnected from I2P router")
}
