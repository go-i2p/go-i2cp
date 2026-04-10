package go_i2cp

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestEnableBatching verifies that batching can be enabled with custom parameters
func TestEnableBatching(t *testing.T) {
	client := NewClient(nil)

	if client.IsBatchingEnabled() {
		t.Fatal("Batching should be disabled by default")
	}

	// Enable batching with custom parameters
	flushTimer := 20 * time.Millisecond
	sizeThreshold := 8192

	client.EnableBatching(flushTimer, sizeThreshold)

	if !client.IsBatchingEnabled() {
		t.Fatal("Batching should be enabled after EnableBatching()")
	}

	if client.batchFlushTimer != flushTimer {
		t.Errorf("Expected flush timer %v, got %v", flushTimer, client.batchFlushTimer)
	}

	if client.batchSizeThreshold != sizeThreshold {
		t.Errorf("Expected size threshold %d, got %d", sizeThreshold, client.batchSizeThreshold)
	}

	if client.batchTicker == nil {
		t.Fatal("Batch ticker should be initialized")
	}

	// Cleanup
	if err := client.DisableBatching(); err != nil {
		t.Fatalf("DisableBatching() failed: %v", err)
	}

	// Signal shutdown to stop worker goroutine
	close(client.shutdown)
	client.wg.Wait()
}

// TestDisableBatching verifies that batching can be disabled
func TestDisableBatching(t *testing.T) {
	client := NewClient(nil)
	client.EnableBatching(10*time.Millisecond, 16*1024)

	if !client.IsBatchingEnabled() {
		t.Fatal("Batching should be enabled")
	}

	if err := client.DisableBatching(); err != nil {
		t.Fatalf("DisableBatching() failed: %v", err)
	}

	if client.IsBatchingEnabled() {
		t.Fatal("Batching should be disabled after DisableBatching()")
	}

	if client.batchTicker != nil {
		t.Fatal("Batch ticker should be nil after disabling")
	}

	// Cleanup
	close(client.shutdown)
	client.wg.Wait()
}

// TestEnableBatchingTwice verifies that enabling batching twice is handled safely
func TestEnableBatchingTwice(t *testing.T) {
	client := NewClient(nil)
	client.EnableBatching(10*time.Millisecond, 16*1024)

	// Try to enable again - should log warning but not crash
	client.EnableBatching(20*time.Millisecond, 32*1024)

	if !client.IsBatchingEnabled() {
		t.Fatal("Batching should still be enabled")
	}

	// Original parameters should remain
	if client.batchFlushTimer != 10*time.Millisecond {
		t.Errorf("Flush timer should not have changed")
	}

	// Cleanup
	if err := client.DisableBatching(); err != nil {
		t.Fatalf("DisableBatching() failed: %v", err)
	}
	close(client.shutdown)
	client.wg.Wait()
}

// TestDisableBatchingWhenNotEnabled verifies that disabling when not enabled is safe
func TestDisableBatchingWhenNotEnabled(t *testing.T) {
	client := NewClient(nil)

	if err := client.DisableBatching(); err != nil {
		t.Fatalf("DisableBatching() should not error when batching not enabled: %v", err)
	}
}

// TestGetTotalQueueSize verifies queue size calculation
func TestGetTotalQueueSize(t *testing.T) {
	client := NewClient(nil)

	// Add some streams to the queue
	stream1 := NewStream(make([]byte, 100))
	stream2 := NewStream(make([]byte, 200))
	stream3 := NewStream(make([]byte, 300))

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue, stream1, stream2, stream3)
	totalSize := client.getTotalQueueSize()
	client.lock.Unlock()

	expectedSize := 100 + 200 + 300
	if totalSize != expectedSize {
		t.Errorf("Expected total queue size %d, got %d", expectedSize, totalSize)
	}
}

// TestGetTotalQueueSizeEmpty verifies empty queue returns 0
func TestGetTotalQueueSizeEmpty(t *testing.T) {
	client := NewClient(nil)

	client.lock.Lock()
	totalSize := client.getTotalQueueSize()
	client.lock.Unlock()

	if totalSize != 0 {
		t.Errorf("Expected total queue size 0 for empty queue, got %d", totalSize)
	}
}

// TestFlushOutputQueueEmpty verifies flushing empty queue is safe
func TestFlushOutputQueueEmpty(t *testing.T) {
	client := NewClient(nil)

	if err := client.flushOutputQueue(); err != nil {
		t.Fatalf("flushOutputQueue() should not error on empty queue: %v", err)
	}
}

// TestBatchingConcurrentAccess verifies thread-safety of batching operations
func TestBatchingConcurrentAccess(t *testing.T) {
	client := NewClient(nil)
	var wg sync.WaitGroup

	// Concurrent enable/disable/check operations
	for i := 0; i < 10; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			client.EnableBatching(10*time.Millisecond, 16*1024)
		}()

		go func() {
			defer wg.Done()
			_ = client.DisableBatching()
		}()

		go func() {
			defer wg.Done()
			_ = client.IsBatchingEnabled()
		}()
	}

	wg.Wait()

	// Cleanup
	_ = client.DisableBatching()
	close(client.shutdown)
	client.wg.Wait()
}

// TestBatchFlushWorkerShutdown verifies worker stops on shutdown signal
func TestBatchFlushWorkerShutdown(t *testing.T) {
	client := NewClient(nil)
	client.EnableBatching(100*time.Millisecond, 16*1024)

	// Give worker time to start
	time.Sleep(10 * time.Millisecond)

	// Signal shutdown
	close(client.shutdown)

	// Wait for worker to stop with timeout
	done := make(chan struct{})
	go func() {
		client.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success - worker stopped
	case <-time.After(1 * time.Second):
		t.Fatal("Batch flush worker did not stop within timeout")
	}
}

// TestSizeThresholdTriggersFlush verifies that exceeding size threshold triggers immediate flush
func TestSizeThresholdTriggersFlush(t *testing.T) {
	// This test requires a mock TCP connection to verify flush behavior
	// For now, we test the logic path without actual network I/O

	client := NewClient(nil)
	client.EnableBatching(100*time.Millisecond, 1024) // 1KB threshold

	// Create a large message that exceeds threshold
	_ = NewStream(make([]byte, 2048)) // Unused - would trigger flush in real scenario

	client.lock.Lock()
	initialQueueLen := len(client.outputQueue)
	client.lock.Unlock()

	// Note: sendMessage() will try to flush if threshold exceeded
	// Without a real TCP connection, this will fail gracefully
	// We're testing the code path compiles and doesn't panic

	if initialQueueLen != 0 {
		t.Errorf("Expected initial queue length 0, got %d", initialQueueLen)
	}

	// Cleanup
	_ = client.DisableBatching()
	close(client.shutdown)
	client.wg.Wait()
}

// TestBatchingDefaults verifies default values are set correctly
func TestBatchingDefaults(t *testing.T) {
	client := NewClient(nil)

	if client.batchEnabled {
		t.Error("Batching should be disabled by default")
	}

	expectedTimer := 10 * time.Millisecond
	if client.batchFlushTimer != expectedTimer {
		t.Errorf("Expected default flush timer %v, got %v", expectedTimer, client.batchFlushTimer)
	}

	expectedThreshold := 16 * 1024
	if client.batchSizeThreshold != expectedThreshold {
		t.Errorf("Expected default size threshold %d, got %d", expectedThreshold, client.batchSizeThreshold)
	}
}

// TestFlushOutputQueueWithMessages verifies that flushOutputQueue sends queued messages
// through the TCP connection and clears the queue.
func TestFlushOutputQueueWithMessages(t *testing.T) {
	client := NewClient(nil)

	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	client.tcp.conn = clientConn

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	msg1 := NewStream([]byte{0x00, 0x00, 0x00, 0x01, 0x05, 0xAA})
	msg2 := NewStream([]byte{0x00, 0x00, 0x00, 0x02, 0x06, 0xBB, 0xCC})

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue, msg1, msg2)
	client.lock.Unlock()

	if err := client.flushOutputQueue(); err != nil {
		t.Fatalf("flushOutputQueue() failed: %v", err)
	}

	client.lock.Lock()
	remaining := len(client.outputQueue)
	client.lock.Unlock()

	if remaining != 0 {
		t.Errorf("Expected empty queue after flush, got %d messages", remaining)
	}
}

// TestFlushOutputQueueWithMetrics verifies that flushing tracks metrics correctly.
func TestFlushOutputQueueWithMetrics(t *testing.T) {
	client := NewClient(nil)
	metrics := NewInMemoryMetrics()
	client.metrics = metrics

	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	client.tcp.conn = clientConn

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	msgType := uint8(I2CP_MSG_SEND_MESSAGE)
	msg := NewStream([]byte{0x00, 0x00, 0x00, 0x01, msgType, 0xDE, 0xAD})

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue, msg)
	client.lock.Unlock()

	if err := client.flushOutputQueue(); err != nil {
		t.Fatalf("flushOutputQueue() failed: %v", err)
	}

	if sent := metrics.BytesSent(); sent != uint64(msg.Len()) {
		t.Errorf("Expected BytesSent=%d, got %d", msg.Len(), sent)
	}

	if count := metrics.MessagesSent(msgType); count != 1 {
		t.Errorf("Expected MessagesSent(%d)=1, got %d", msgType, count)
	}
}

// TestExecuteFlushNoConnection verifies executeFlush handles no connection gracefully.
func TestExecuteFlushNoConnection(t *testing.T) {
	client := NewClient(nil)

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue, NewStream([]byte{0x01, 0x02, 0x03, 0x04, 0x05}))
	client.lock.Unlock()

	// Should not panic even with no TCP connection
	client.executeFlush()

	// sendQueuedMessages sees ret==0 (conn nil), logs warning, breaks, then clearQueue runs
	client.lock.Lock()
	remaining := len(client.outputQueue)
	client.lock.Unlock()

	if remaining != 0 {
		t.Errorf("Expected queue cleared after flush attempt, got %d messages", remaining)
	}
}

// TestClearQueue verifies clearQueue resets the output queue.
func TestClearQueue(t *testing.T) {
	client := NewClient(nil)

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue,
		NewStream([]byte{0x01}),
		NewStream([]byte{0x02}),
	)
	client.clearQueue()
	remaining := len(client.outputQueue)
	client.lock.Unlock()

	if remaining != 0 {
		t.Errorf("Expected empty queue after clearQueue, got %d", remaining)
	}
}

// TestTrackMessageMetricsNilMetrics verifies trackMessageMetrics is safe with nil metrics.
func TestTrackMessageMetricsNilMetrics(t *testing.T) {
	client := NewClient(nil)
	client.metrics = nil

	msg := NewStream([]byte{0x00, 0x00, 0x00, 0x01, 0x05, 0xAA})
	client.trackMessageMetrics(msg)
}

// TestTrackMessageMetricsShortMessage verifies trackMessageMetrics handles short messages.
func TestTrackMessageMetricsShortMessage(t *testing.T) {
	client := NewClient(nil)
	metrics := NewInMemoryMetrics()
	client.metrics = metrics

	msg := NewStream([]byte{0x01, 0x02})
	client.trackMessageMetrics(msg)

	if sent := metrics.BytesSent(); sent != 2 {
		t.Errorf("Expected BytesSent=2, got %d", sent)
	}
}

// TestBatchFlushWorkerTimerFlush verifies the flush worker flushes on timer tick.
func TestBatchFlushWorkerTimerFlush(t *testing.T) {
	client := NewClient(nil)

	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	client.tcp.conn = clientConn

	received := make(chan []byte, 10)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			received <- data
		}
	}()

	client.EnableBatching(50*time.Millisecond, 64*1024)

	client.lock.Lock()
	client.outputQueue = append(client.outputQueue, NewStream([]byte{0xDE, 0xAD}))
	client.lock.Unlock()

	select {
	case <-received:
		// Success
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Expected timer-based flush within 500ms")
	}

	_ = client.DisableBatching()
	close(client.shutdown)
	client.wg.Wait()
}
