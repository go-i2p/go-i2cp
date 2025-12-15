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

	bwManager := NewBandwidthManager()
	client := createClientWithBandwidthCallback(bwManager)

	configureClientConnection(client)
	connectToRouter(client)

	startRateLimitingDemo(bwManager)
	waitForShutdown()

	client.Close()
	fmt.Println("Disconnected from I2P router")
}

// createClientWithBandwidthCallback creates a new I2CP client with a callback
// that updates the bandwidth manager when router bandwidth limits are received.
func createClientWithBandwidthCallback(bwManager *BandwidthManager) *i2cp.Client {
	callbacks := &i2cp.ClientCallBacks{
		OnBandwidthLimits: func(client *i2cp.Client, limits *i2cp.BandwidthLimits) {
			fmt.Println("\n[Router] Received bandwidth limits:")
			fmt.Printf("  %s\n", limits.String())
			bwManager.UpdateLimits(limits)
		},
	}
	return i2cp.NewClient(callbacks)
}

// configureClientConnection configures the I2CP client with router host and port
// from environment variables or default values.
func configureClientConnection(client *i2cp.Client) {
	routerHost := getEnvOrDefault("I2CP_ROUTER_HOST", "127.0.0.1")
	routerPort := getEnvOrDefault("I2CP_ROUTER_PORT", "7654")

	client.SetProperty("i2cp.tcp.host", routerHost)
	client.SetProperty("i2cp.tcp.port", routerPort)

	fmt.Printf("Connecting to I2P router at %s:%s...\n", routerHost, routerPort)
}

// getEnvOrDefault retrieves an environment variable value or returns a default value if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// connectToRouter establishes a connection to the I2P router with a timeout.
// Fatally exits if connection fails.
func connectToRouter(client *i2cp.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to I2P router: %v", err)
	}

	fmt.Println("Connected to I2P router!")
	fmt.Println("\nWaiting for bandwidth limits message from router...")
	fmt.Println("(The router should send this automatically after connection)")
}

// startRateLimitingDemo launches a goroutine that demonstrates rate limiting
// by attempting to send various packet sizes through the bandwidth manager.
func startRateLimitingDemo(bwManager *BandwidthManager) {
	go func() {
		time.Sleep(2 * time.Second)
		fmt.Println("\n[Demo] Simulating data transfer with rate limiting...")

		testSizes := []uint32{1024, 4096, 16384, 65536, 262144}
		for _, size := range testSizes {
			reportRateLimitStatus(bwManager, size)
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

// reportRateLimitStatus checks if a given size can be sent and reports the result.
func reportRateLimitStatus(bwManager *BandwidthManager, size uint32) {
	if bwManager.CanSend(size) {
		fmt.Printf("  ✓ Allowed to send %d bytes\n", size)
	} else {
		fmt.Printf("  ✗ Rate limited - cannot send %d bytes (would exceed limit)\n", size)
	}
}

// waitForShutdown blocks until an interrupt signal is received or timeout occurs.
func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	select {
	case <-sigChan:
		fmt.Println("\n\nReceived interrupt, shutting down...")
	case <-time.After(10 * time.Second):
		fmt.Println("\n\nTimeout reached, shutting down...")
	}
}
