package go_i2cp

import (
	"sync"
	"testing"
	"time"
)

// TestInMemoryMetrics_MessageCounters tests message sent/received counters
func TestInMemoryMetrics_MessageCounters(t *testing.T) {
	metrics := NewInMemoryMetrics()

	// Test increment and retrieval
	metrics.IncrementMessageSent(I2CP_MSG_SEND_MESSAGE)
	metrics.IncrementMessageSent(I2CP_MSG_SEND_MESSAGE)
	metrics.IncrementMessageReceived(I2CP_MSG_PAYLOAD_MESSAGE)

	if got := metrics.MessagesSent(I2CP_MSG_SEND_MESSAGE); got != 2 {
		t.Errorf("MessagesSent() = %d, want 2", got)
	}

	if got := metrics.MessagesReceived(I2CP_MSG_PAYLOAD_MESSAGE); got != 1 {
		t.Errorf("MessagesReceived() = %d, want 1", got)
	}

	// Test unincremented type returns zero
	if got := metrics.MessagesSent(I2CP_MSG_CREATE_SESSION); got != 0 {
		t.Errorf("MessagesSent(unincremented) = %d, want 0", got)
	}
}

// TestInMemoryMetrics_ActiveSessions tests session gauge
func TestInMemoryMetrics_ActiveSessions(t *testing.T) {
	metrics := NewInMemoryMetrics()

	metrics.SetActiveSessions(5)
	if got := metrics.ActiveSessions(); got != 5 {
		t.Errorf("ActiveSessions() = %d, want 5", got)
	}

	metrics.SetActiveSessions(0)
	if got := metrics.ActiveSessions(); got != 0 {
		t.Errorf("ActiveSessions() = %d, want 0", got)
	}
}

// TestInMemoryMetrics_ErrorTracking tests error counters by type
func TestInMemoryMetrics_ErrorTracking(t *testing.T) {
	metrics := NewInMemoryMetrics()

	metrics.IncrementError("network")
	metrics.IncrementError("network")
	metrics.IncrementError("protocol")

	if got := metrics.Errors("network"); got != 2 {
		t.Errorf("Errors(network) = %d, want 2", got)
	}

	if got := metrics.Errors("protocol"); got != 1 {
		t.Errorf("Errors(protocol) = %d, want 1", got)
	}

	if got := metrics.Errors("timeout"); got != 0 {
		t.Errorf("Errors(timeout) = %d, want 0", got)
	}
}

// TestInMemoryMetrics_AllErrors tests retrieving all error counts
func TestInMemoryMetrics_AllErrors(t *testing.T) {
	metrics := NewInMemoryMetrics()

	metrics.IncrementError("network")
	metrics.IncrementError("protocol")
	metrics.IncrementError("protocol")

	allErrors := metrics.AllErrors()

	if got := allErrors["network"]; got != 1 {
		t.Errorf("AllErrors()[network] = %d, want 1", got)
	}

	if got := allErrors["protocol"]; got != 2 {
		t.Errorf("AllErrors()[protocol] = %d, want 2", got)
	}

	if len(allErrors) != 2 {
		t.Errorf("AllErrors() length = %d, want 2", len(allErrors))
	}
}

// TestInMemoryMetrics_Latency tests latency tracking
func TestInMemoryMetrics_Latency(t *testing.T) {
	metrics := NewInMemoryMetrics()

	// Record various latencies
	metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 10*time.Millisecond)
	metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 20*time.Millisecond)
	metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 30*time.Millisecond)

	// Check average: (10 + 20 + 30) / 3 = 20ms
	avg := metrics.AvgLatency(I2CP_MSG_SEND_MESSAGE)
	expected := 20 * time.Millisecond
	if avg != expected {
		t.Errorf("AvgLatency() = %v, want %v", avg, expected)
	}

	// Check min: 10ms
	min := metrics.MinLatency(I2CP_MSG_SEND_MESSAGE)
	expectedMin := 10 * time.Millisecond
	if min != expectedMin {
		t.Errorf("MinLatency() = %v, want %v", min, expectedMin)
	}

	// Check max: 30ms
	max := metrics.MaxLatency(I2CP_MSG_SEND_MESSAGE)
	expectedMax := 30 * time.Millisecond
	if max != expectedMax {
		t.Errorf("MaxLatency() = %v, want %v", max, expectedMax)
	}

	// Test unrecorded message type returns zero
	if got := metrics.AvgLatency(I2CP_MSG_CREATE_SESSION); got != 0 {
		t.Errorf("AvgLatency(unrecorded) = %v, want 0", got)
	}
}

// TestInMemoryMetrics_ConnectionState tests connection state tracking
func TestInMemoryMetrics_ConnectionState(t *testing.T) {
	metrics := NewInMemoryMetrics()

	// Initial state should be disconnected
	if got := metrics.ConnectionState(); got != "disconnected" {
		t.Errorf("ConnectionState() = %s, want disconnected", got)
	}

	metrics.SetConnectionState("connected")
	if got := metrics.ConnectionState(); got != "connected" {
		t.Errorf("ConnectionState() = %s, want connected", got)
	}

	metrics.SetConnectionState("reconnecting")
	if got := metrics.ConnectionState(); got != "reconnecting" {
		t.Errorf("ConnectionState() = %s, want reconnecting", got)
	}
}

// TestInMemoryMetrics_Bandwidth tests bandwidth tracking
func TestInMemoryMetrics_Bandwidth(t *testing.T) {
	metrics := NewInMemoryMetrics()

	metrics.AddBytesSent(1024)
	metrics.AddBytesSent(512)
	metrics.AddBytesReceived(2048)

	if got := metrics.BytesSent(); got != 1536 {
		t.Errorf("BytesSent() = %d, want 1536", got)
	}

	if got := metrics.BytesReceived(); got != 2048 {
		t.Errorf("BytesReceived() = %d, want 2048", got)
	}
}

// TestInMemoryMetrics_Reset tests resetting all metrics
func TestInMemoryMetrics_Reset(t *testing.T) {
	metrics := NewInMemoryMetrics()

	// Populate with data
	metrics.IncrementMessageSent(I2CP_MSG_SEND_MESSAGE)
	metrics.IncrementMessageReceived(I2CP_MSG_PAYLOAD_MESSAGE)
	metrics.SetActiveSessions(5)
	metrics.IncrementError("network")
	metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 10*time.Millisecond)
	metrics.SetConnectionState("connected")
	metrics.AddBytesSent(1024)
	metrics.AddBytesReceived(512)

	// Reset
	metrics.Reset()

	// Verify all metrics are cleared
	if got := metrics.MessagesSent(I2CP_MSG_SEND_MESSAGE); got != 0 {
		t.Errorf("After Reset: MessagesSent() = %d, want 0", got)
	}

	if got := metrics.MessagesReceived(I2CP_MSG_PAYLOAD_MESSAGE); got != 0 {
		t.Errorf("After Reset: MessagesReceived() = %d, want 0", got)
	}

	if got := metrics.ActiveSessions(); got != 0 {
		t.Errorf("After Reset: ActiveSessions() = %d, want 0", got)
	}

	if got := metrics.Errors("network"); got != 0 {
		t.Errorf("After Reset: Errors() = %d, want 0", got)
	}

	if got := metrics.AvgLatency(I2CP_MSG_SEND_MESSAGE); got != 0 {
		t.Errorf("After Reset: AvgLatency() = %v, want 0", got)
	}

	if got := metrics.ConnectionState(); got != "disconnected" {
		t.Errorf("After Reset: ConnectionState() = %s, want disconnected", got)
	}

	if got := metrics.BytesSent(); got != 0 {
		t.Errorf("After Reset: BytesSent() = %d, want 0", got)
	}

	if got := metrics.BytesReceived(); got != 0 {
		t.Errorf("After Reset: BytesReceived() = %d, want 0", got)
	}
}

// TestInMemoryMetrics_Concurrency tests thread-safe operations
func TestInMemoryMetrics_Concurrency(t *testing.T) {
	metrics := NewInMemoryMetrics()
	var wg sync.WaitGroup

	// Concurrent message increments
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.IncrementMessageSent(I2CP_MSG_SEND_MESSAGE)
			metrics.IncrementMessageReceived(I2CP_MSG_PAYLOAD_MESSAGE)
		}()
	}

	// Concurrent error increments
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.IncrementError("network")
			metrics.IncrementError("protocol")
		}()
	}

	// Concurrent latency recordings
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 10*time.Millisecond)
		}()
	}

	// Concurrent session updates
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(count int) {
			defer wg.Done()
			metrics.SetActiveSessions(count)
		}(i)
	}

	// Concurrent state updates
	states := []string{"connected", "disconnected", "reconnecting"}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(state string) {
			defer wg.Done()
			metrics.SetConnectionState(state)
		}(states[i%len(states)])
	}

	// Concurrent bandwidth updates
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.AddBytesSent(100)
			metrics.AddBytesReceived(200)
		}()
	}

	wg.Wait()

	// Verify final counts (should be deterministic for counters)
	if got := metrics.MessagesSent(I2CP_MSG_SEND_MESSAGE); got != 100 {
		t.Errorf("Concurrent MessagesSent() = %d, want 100", got)
	}

	if got := metrics.MessagesReceived(I2CP_MSG_PAYLOAD_MESSAGE); got != 100 {
		t.Errorf("Concurrent MessagesReceived() = %d, want 100", got)
	}

	if got := metrics.Errors("network"); got != 50 {
		t.Errorf("Concurrent Errors(network) = %d, want 50", got)
	}

	if got := metrics.Errors("protocol"); got != 50 {
		t.Errorf("Concurrent Errors(protocol) = %d, want 50", got)
	}

	if got := metrics.BytesSent(); got != 5000 {
		t.Errorf("Concurrent BytesSent() = %d, want 5000", got)
	}

	if got := metrics.BytesReceived(); got != 10000 {
		t.Errorf("Concurrent BytesReceived() = %d, want 10000", got)
	}

	// Latency tracking should have 50 measurements
	if avg := metrics.AvgLatency(I2CP_MSG_SEND_MESSAGE); avg != 10*time.Millisecond {
		t.Errorf("Concurrent AvgLatency() = %v, want 10ms", avg)
	}
}

// TestClient_SetMetrics tests enabling/disabling metrics on client
func TestClient_SetMetrics(t *testing.T) {
	client := NewClient(nil)

	// Initially no metrics
	if got := client.GetMetrics(); got != nil {
		t.Errorf("GetMetrics() = %v, want nil", got)
	}

	// Enable metrics
	metrics := NewInMemoryMetrics()
	client.SetMetrics(metrics)

	if got := client.GetMetrics(); got != metrics {
		t.Error("GetMetrics() did not return the same metrics instance")
	}

	// Disable metrics
	client.SetMetrics(nil)

	if got := client.GetMetrics(); got != nil {
		t.Errorf("GetMetrics() after disable = %v, want nil", got)
	}
}

// TestClient_MetricsIntegration tests that client operations update metrics
func TestClient_MetricsIntegration(t *testing.T) {
	client := NewClient(nil)
	metrics := NewInMemoryMetrics()
	client.SetMetrics(metrics)

	// Test error tracking
	client.trackError("network")
	client.trackError("protocol")

	if got := metrics.Errors("network"); got != 1 {
		t.Errorf("Errors(network) = %d, want 1", got)
	}

	if got := metrics.Errors("protocol"); got != 1 {
		t.Errorf("Errors(protocol) = %d, want 1", got)
	}
}

// BenchmarkInMemoryMetrics_IncrementMessageSent benchmarks message counter increments
func BenchmarkInMemoryMetrics_IncrementMessageSent(b *testing.B) {
	metrics := NewInMemoryMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.IncrementMessageSent(I2CP_MSG_SEND_MESSAGE)
	}
}

// BenchmarkInMemoryMetrics_RecordLatency benchmarks latency recording
func BenchmarkInMemoryMetrics_RecordLatency(b *testing.B) {
	metrics := NewInMemoryMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordMessageLatency(I2CP_MSG_SEND_MESSAGE, 10*time.Millisecond)
	}
}

// BenchmarkInMemoryMetrics_IncrementError benchmarks error tracking
func BenchmarkInMemoryMetrics_IncrementError(b *testing.B) {
	metrics := NewInMemoryMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.IncrementError("network")
	}
}
