package go_i2cp

import (
	"testing"
	"time"
)

// BenchmarkBatchingDisabled measures throughput with batching disabled
func BenchmarkBatchingDisabled(b *testing.B) {
	client := NewClient(nil)
	defer func() {
		close(client.shutdown)
		client.wg.Wait()
	}()

	// Create a realistic message
	stream := NewStream(make([]byte, 512))
	stream.WriteByte(I2CP_MSG_SEND_MESSAGE)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Queue message without batching
		client.lock.Lock()
		client.outputQueue = append(client.outputQueue, stream)
		client.lock.Unlock()

		// Simulate manual flush every 100 messages
		if i%100 == 0 {
			_ = client.flushOutputQueue()
		}
	}
}

// BenchmarkBatchingEnabled measures throughput with batching enabled
func BenchmarkBatchingEnabled(b *testing.B) {
	client := NewClient(nil)
	client.EnableBatching(10*time.Millisecond, 16*1024)
	defer func() {
		_ = client.DisableBatching()
		close(client.shutdown)
		client.wg.Wait()
	}()

	// Create a realistic message
	stream := NewStream(make([]byte, 512))
	stream.WriteByte(I2CP_MSG_SEND_MESSAGE)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Queue message with batching (auto-flush on threshold)
		client.lock.Lock()
		client.outputQueue = append(client.outputQueue, stream)
		client.lock.Unlock()
	}
}

// BenchmarkGetTotalQueueSize measures queue size calculation performance
func BenchmarkGetTotalQueueSize(b *testing.B) {
	client := NewClient(nil)

	// Fill queue with various sized messages
	for i := 0; i < 100; i++ {
		stream := NewStream(make([]byte, 100+i*10))
		client.outputQueue = append(client.outputQueue, stream)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		client.lock.Lock()
		_ = client.getTotalQueueSize()
		client.lock.Unlock()
	}
}

// BenchmarkFlushOutputQueue measures flush performance
func BenchmarkFlushOutputQueue(b *testing.B) {
	client := NewClient(nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Add 10 messages to queue
		for j := 0; j < 10; j++ {
			stream := NewStream(make([]byte, 512))
			client.outputQueue = append(client.outputQueue, stream)
		}
		b.StartTimer()

		_ = client.flushOutputQueue()
	}
}

// BenchmarkBatchingSmallMessages measures batching with many small messages
func BenchmarkBatchingSmallMessages(b *testing.B) {
	client := NewClient(nil)
	client.EnableBatching(50*time.Millisecond, 16*1024)
	defer func() {
		_ = client.DisableBatching()
		close(client.shutdown)
		client.wg.Wait()
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 64)) // Small 64-byte messages
		client.lock.Lock()
		client.outputQueue = append(client.outputQueue, stream)
		client.lock.Unlock()
	}
}

// BenchmarkBatchingLargeMessages measures batching with fewer large messages
func BenchmarkBatchingLargeMessages(b *testing.B) {
	client := NewClient(nil)
	client.EnableBatching(50*time.Millisecond, 16*1024)
	defer func() {
		_ = client.DisableBatching()
		close(client.shutdown)
		client.wg.Wait()
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 4096)) // Large 4KB messages
		client.lock.Lock()
		client.outputQueue = append(client.outputQueue, stream)
		client.lock.Unlock()
	}
}

// BenchmarkEnableDisableBatching measures control operation overhead
func BenchmarkEnableDisableBatching(b *testing.B) {
	client := NewClient(nil)
	defer func() {
		close(client.shutdown)
		client.wg.Wait()
	}()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		client.EnableBatching(10*time.Millisecond, 16*1024)
		_ = client.DisableBatching()
	}
}
