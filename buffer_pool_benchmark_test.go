package go_i2cp

import (
	"testing"
)

// Baseline: NewStream without pooling
func BenchmarkNewStreamNoPoll(b *testing.B) {
	DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 1024))
		stream.WriteString("test data")
		// Let GC handle cleanup
		_ = stream
	}
}

// With pooling: NewStreamPooled + ReleaseStream
func BenchmarkNewStreamPooled(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStreamPooled(1024)
		stream.WriteString("test data")
		ReleaseStream(stream)
	}
}

// Benchmark different size classes
func BenchmarkBufferPool512(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := globalBufferPool.GetBuffer(512)
		buf = append(buf, []byte("test")...)
		globalBufferPool.PutBuffer(buf)
	}
}

func BenchmarkBufferPool1K(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := globalBufferPool.GetBuffer(1024)
		buf = append(buf, []byte("test")...)
		globalBufferPool.PutBuffer(buf)
	}
}

func BenchmarkBufferPool4K(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := globalBufferPool.GetBuffer(4096)
		buf = append(buf, []byte("test")...)
		globalBufferPool.PutBuffer(buf)
	}
}

func BenchmarkBufferPool16K(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := globalBufferPool.GetBuffer(16384)
		buf = append(buf, []byte("test")...)
		globalBufferPool.PutBuffer(buf)
	}
}

// Benchmark concurrent access
func BenchmarkBufferPoolParallel(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := globalBufferPool.GetBuffer(1024)
			buf = append(buf, []byte("test data")...)
			globalBufferPool.PutBuffer(buf)
		}
	})
}

// Benchmark realistic I2CP message creation
func BenchmarkRealisticMessageNoPoll(b *testing.B) {
	DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStream(make([]byte, 0, 512))
		stream.WriteUint16(uint16(i))
		stream.WriteUint32(uint32(i * 2))
		stream.WriteString("session-property-value")
		_ = stream
	}
}

func BenchmarkRealisticMessagePooled(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		stream := NewStreamPooled(512)
		stream.WriteUint16(uint16(i))
		stream.WriteUint32(uint32(i * 2))
		stream.WriteString("session-property-value")
		ReleaseStream(stream)
	}
}

// Benchmark high-frequency small allocations (worst case for GC)
func BenchmarkHighFrequencySmallNoPoll(b *testing.B) {
	DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 10; j++ {
			stream := NewStream(make([]byte, 0, 64))
			stream.WriteByte(byte(j))
			_ = stream
		}
	}
}

func BenchmarkHighFrequencySmallPooled(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 10; j++ {
			stream := NewStreamPooled(64)
			stream.WriteByte(byte(j))
			ReleaseStream(stream)
		}
	}
}

// Benchmark pool overhead
func BenchmarkPoolGetPut(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := globalBufferPool.GetBuffer(1024)
		globalBufferPool.PutBuffer(buf)
	}
}

// Benchmark stats collection overhead
func BenchmarkGetBufferPoolStats(b *testing.B) {
	EnableBufferPool()
	defer DisableBufferPool()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = GetBufferPoolStats()
	}
}
