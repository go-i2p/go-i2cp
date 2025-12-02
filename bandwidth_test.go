package go_i2cp

import (
	"strings"
	"sync"
	"testing"
)

// TestBandwidthLimitsString tests the String() method of BandwidthLimits
func TestBandwidthLimitsString(t *testing.T) {
	tests := []struct {
		name     string
		limits   *BandwidthLimits
		expected string
	}{
		{
			name: "typical values",
			limits: &BandwidthLimits{
				ClientInbound:       1024000,
				ClientOutbound:      512000,
				RouterInbound:       2048000,
				RouterInboundBurst:  4096000,
				RouterOutbound:      1536000,
				RouterOutboundBurst: 3072000,
				BurstTime:           10,
			},
			expected: "BandwidthLimits{Client: 1024000/512000, Router: 2048000(4096000)/1536000(3072000), Burst: 10s}",
		},
		{
			name: "zero values",
			limits: &BandwidthLimits{
				ClientInbound:       0,
				ClientOutbound:      0,
				RouterInbound:       0,
				RouterInboundBurst:  0,
				RouterOutbound:      0,
				RouterOutboundBurst: 0,
				BurstTime:           0,
			},
			expected: "BandwidthLimits{Client: 0/0, Router: 0(0)/0(0), Burst: 0s}",
		},
		{
			name: "maximum uint32 values",
			limits: &BandwidthLimits{
				ClientInbound:       4294967295,
				ClientOutbound:      4294967295,
				RouterInbound:       4294967295,
				RouterInboundBurst:  4294967295,
				RouterOutbound:      4294967295,
				RouterOutboundBurst: 4294967295,
				BurstTime:           4294967295,
			},
			expected: "BandwidthLimits{Client: 4294967295/4294967295, Router: 4294967295(4294967295)/4294967295(4294967295), Burst: 4294967295s}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.limits.String()
			if result != tt.expected {
				t.Errorf("String() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestBandwidthLimitsUndefinedFields tests that undefined fields are properly stored
func TestBandwidthLimitsUndefinedFields(t *testing.T) {
	limits := &BandwidthLimits{
		Undefined: [9]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}

	for i := 0; i < 9; i++ {
		if limits.Undefined[i] != uint32(i+1) {
			t.Errorf("Undefined[%d] = %d, want %d", i, limits.Undefined[i], i+1)
		}
	}
}

// TestOnMsgBandwidthLimitCallback tests that the callback is invoked correctly
func TestOnMsgBandwidthLimitCallback(t *testing.T) {
	var callbackInvoked bool
	var receivedLimits *BandwidthLimits
	var wg sync.WaitGroup

	callbacks := &ClientCallBacks{
		OnBandwidthLimits: func(client *Client, limits *BandwidthLimits) {
			callbackInvoked = true
			receivedLimits = limits
			wg.Done()
		},
	}

	client := NewClient(callbacks)

	// Create a stream with bandwidth limits message data
	stream := NewStream(make([]byte, 0, 256))
	stream.WriteUint32(1000) // ClientInbound
	stream.WriteUint32(2000) // ClientOutbound
	stream.WriteUint32(3000) // RouterInbound
	stream.WriteUint32(4000) // RouterInboundBurst
	stream.WriteUint32(5000) // RouterOutbound
	stream.WriteUint32(6000) // RouterOutboundBurst
	stream.WriteUint32(10)   // BurstTime
	for i := 0; i < 9; i++ { // 9 undefined fields
		stream.WriteUint32(uint32(i + 100))
	}

	wg.Add(1)
	client.onMsgBandwithLimit(stream)
	wg.Wait()

	if !callbackInvoked {
		t.Error("Callback was not invoked")
	}

	if receivedLimits == nil {
		t.Fatal("Received limits is nil")
	}

	// Validate all fields
	if receivedLimits.ClientInbound != 1000 {
		t.Errorf("ClientInbound = %d, want 1000", receivedLimits.ClientInbound)
	}
	if receivedLimits.ClientOutbound != 2000 {
		t.Errorf("ClientOutbound = %d, want 2000", receivedLimits.ClientOutbound)
	}
	if receivedLimits.RouterInbound != 3000 {
		t.Errorf("RouterInbound = %d, want 3000", receivedLimits.RouterInbound)
	}
	if receivedLimits.RouterInboundBurst != 4000 {
		t.Errorf("RouterInboundBurst = %d, want 4000", receivedLimits.RouterInboundBurst)
	}
	if receivedLimits.RouterOutbound != 5000 {
		t.Errorf("RouterOutbound = %d, want 5000", receivedLimits.RouterOutbound)
	}
	if receivedLimits.RouterOutboundBurst != 6000 {
		t.Errorf("RouterOutboundBurst = %d, want 6000", receivedLimits.RouterOutboundBurst)
	}
	if receivedLimits.BurstTime != 10 {
		t.Errorf("BurstTime = %d, want 10", receivedLimits.BurstTime)
	}

	// Validate undefined fields
	for i := 0; i < 9; i++ {
		expected := uint32(i + 100)
		if receivedLimits.Undefined[i] != expected {
			t.Errorf("Undefined[%d] = %d, want %d", i, receivedLimits.Undefined[i], expected)
		}
	}
}

// TestOnMsgBandwidthLimitNoCallback tests behavior when no callback is registered
func TestOnMsgBandwidthLimitNoCallback(t *testing.T) {
	client := NewClient(&ClientCallBacks{})

	// Create a stream with bandwidth limits message data
	stream := NewStream(make([]byte, 0, 256))
	stream.WriteUint32(1000)
	stream.WriteUint32(2000)
	stream.WriteUint32(3000)
	stream.WriteUint32(4000)
	stream.WriteUint32(5000)
	stream.WriteUint32(6000)
	stream.WriteUint32(10)
	for i := 0; i < 9; i++ {
		stream.WriteUint32(uint32(i + 100))
	}

	// Should not panic when callback is nil
	client.onMsgBandwithLimit(stream)
}

// TestOnMsgBandwidthLimitNilCallbacks tests behavior when callbacks struct is nil
func TestOnMsgBandwidthLimitNilCallbacks(t *testing.T) {
	client := NewClient(nil)

	// Create a stream with bandwidth limits message data
	stream := NewStream(make([]byte, 0, 256))
	stream.WriteUint32(1000)
	stream.WriteUint32(2000)
	stream.WriteUint32(3000)
	stream.WriteUint32(4000)
	stream.WriteUint32(5000)
	stream.WriteUint32(6000)
	stream.WriteUint32(10)
	for i := 0; i < 9; i++ {
		stream.WriteUint32(uint32(i + 100))
	}

	// Should not panic when callbacks is nil
	client.onMsgBandwithLimit(stream)
}

// TestOnMsgBandwidthLimitTruncatedMessage tests error handling for incomplete messages
func TestOnMsgBandwidthLimitTruncatedMessage(t *testing.T) {
	tests := []struct {
		name       string
		writeCount int // number of uint32 values to write (need 16 total)
	}{
		{"no data", 0},
		{"only client inbound", 1},
		{"only client limits", 2},
		{"missing undefined fields", 7},
		{"one undefined field missing", 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var callbackInvoked bool
			callbacks := &ClientCallBacks{
				OnBandwidthLimits: func(client *Client, limits *BandwidthLimits) {
					callbackInvoked = true
				},
			}

			client := NewClient(callbacks)

			// Create truncated stream
			stream := NewStream(make([]byte, 0, 256))
			for i := 0; i < tt.writeCount; i++ {
				stream.WriteUint32(uint32(i))
			}

			// Should handle error gracefully without invoking callback
			client.onMsgBandwithLimit(stream)

			if callbackInvoked {
				t.Error("Callback should not be invoked for truncated message")
			}
		})
	}
}

// TestBandwidthLimitsStringFormat tests that the String output contains expected components
func TestBandwidthLimitsStringFormat(t *testing.T) {
	limits := &BandwidthLimits{
		ClientInbound:       100,
		ClientOutbound:      200,
		RouterInbound:       300,
		RouterInboundBurst:  400,
		RouterOutbound:      500,
		RouterOutboundBurst: 600,
		BurstTime:           5,
	}

	result := limits.String()

	// Check that all components are present
	expectedComponents := []string{
		"BandwidthLimits",
		"Client:",
		"100/200",
		"Router:",
		"300(400)/500(600)",
		"Burst:",
		"5s",
	}

	for _, component := range expectedComponents {
		if !strings.Contains(result, component) {
			t.Errorf("String() output missing component: %q", component)
		}
	}
}

// TestBandwidthLimitsConcurrentCallback tests thread-safety of callback invocation
func TestBandwidthLimitsConcurrentCallback(t *testing.T) {
	var callbackCount int
	var mu sync.Mutex
	var wg sync.WaitGroup

	callbacks := &ClientCallBacks{
		OnBandwidthLimits: func(client *Client, limits *BandwidthLimits) {
			mu.Lock()
			callbackCount++
			mu.Unlock()
			wg.Done()
		},
	}

	client := NewClient(callbacks)

	// Invoke callback concurrently
	numGoroutines := 10
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			stream := NewStream(make([]byte, 0, 256))
			stream.WriteUint32(1000)
			stream.WriteUint32(2000)
			stream.WriteUint32(3000)
			stream.WriteUint32(4000)
			stream.WriteUint32(5000)
			stream.WriteUint32(6000)
			stream.WriteUint32(10)
			for j := 0; j < 9; j++ {
				stream.WriteUint32(0)
			}
			client.onMsgBandwithLimit(stream)
		}()
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if callbackCount != numGoroutines {
		t.Errorf("Expected %d callback invocations, got %d", numGoroutines, callbackCount)
	}
}
