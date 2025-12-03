package go_i2cp

import (
	"sync"
	"sync/atomic"
)

// bufferPool manages reusable byte slices to reduce GC pressure.
// Uses sync.Pool with size-based buckets for efficient allocation.
//
// Size classes (power of 2 for efficient growth):
//   - 512 bytes:  Small messages (typical I2CP control messages)
//   - 1024 bytes: Medium messages (session creation, leasesets)
//   - 4096 bytes: Large messages (destination creation, large payloads)
//   - 16384 bytes: Extra large messages (bulk data transfer)
type bufferPool struct {
	pool512  sync.Pool
	pool1K   sync.Pool
	pool4K   sync.Pool
	pool16K  sync.Pool
	enabled  bool
	mu       sync.RWMutex
	
	// Metrics for monitoring pool effectiveness (optional)
	// Using uint64 for atomic operations
	gets512  uint64
	gets1K   uint64
	gets4K   uint64
	gets16K  uint64
	getsOversized uint64
	puts512  uint64
	puts1K   uint64
	puts4K   uint64
	puts16K  uint64
}

// Global buffer pool instance
var globalBufferPool = &bufferPool{
	pool512: sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 512)
			return &buf
		},
	},
	pool1K: sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 1024)
			return &buf
		},
	},
	pool4K: sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 4096)
			return &buf
		},
	},
	pool16K: sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 16384)
			return &buf
		},
	},
	enabled: false, // Disabled by default for backward compatibility
}

// EnableBufferPool enables global buffer pooling for Stream allocations.
// This reduces GC pressure by reusing byte slices across Stream instances.
func EnableBufferPool() {
	globalBufferPool.mu.Lock()
	globalBufferPool.enabled = true
	globalBufferPool.mu.Unlock()
}

// DisableBufferPool disables global buffer pooling.
// After calling this, NewStream will allocate fresh buffers.
func DisableBufferPool() {
	globalBufferPool.mu.Lock()
	globalBufferPool.enabled = false
	globalBufferPool.mu.Unlock()
}

// IsBufferPoolEnabled returns whether buffer pooling is currently enabled.
func IsBufferPoolEnabled() bool {
	globalBufferPool.mu.RLock()
	defer globalBufferPool.mu.RUnlock()
	return globalBufferPool.enabled
}

// GetBuffer retrieves a buffer from the appropriate pool based on requested size.
// Returns a buffer with capacity >= size. The buffer's length is 0.
func (bp *bufferPool) GetBuffer(size int) []byte {
	bp.mu.RLock()
	enabled := bp.enabled
	bp.mu.RUnlock()
	
	if !enabled {
		return make([]byte, 0, size)
	}
	
	// Select pool based on size (find smallest bucket that fits)
	var bufPtr *[]byte
	switch {
	case size <= 512:
		atomic.AddUint64(&bp.gets512, 1)
		bufPtr = bp.pool512.Get().(*[]byte)
	case size <= 1024:
		atomic.AddUint64(&bp.gets1K, 1)
		bufPtr = bp.pool1K.Get().(*[]byte)
	case size <= 4096:
		atomic.AddUint64(&bp.gets4K, 1)
		bufPtr = bp.pool4K.Get().(*[]byte)
	case size <= 16384:
		atomic.AddUint64(&bp.gets16K, 1)
		bufPtr = bp.pool16K.Get().(*[]byte)
	default:
		// Size too large for pooling - allocate directly
		atomic.AddUint64(&bp.getsOversized, 1)
		return make([]byte, 0, size)
	}
	
	// Reset buffer to empty but preserve capacity
	buf := (*bufPtr)[:0]
	return buf
}

// PutBuffer returns a buffer to the appropriate pool for reuse.
// The buffer will be reset to length 0 before being returned to the pool.
func (bp *bufferPool) PutBuffer(buf []byte) {
	bp.mu.RLock()
	enabled := bp.enabled
	bp.mu.RUnlock()
	
	if !enabled {
		return // Let GC handle it
	}
	
	// Don't pool buffers that are too large or nil
	if buf == nil || cap(buf) > 16384 {
		return
	}
	
	// Reset buffer to empty (preserve capacity)
	buf = buf[:0]
	
	// Return to appropriate pool based on capacity
	switch cap(buf) {
	case 512:
		atomic.AddUint64(&bp.puts512, 1)
		bp.pool512.Put(&buf)
	case 1024:
		atomic.AddUint64(&bp.puts1K, 1)
		bp.pool1K.Put(&buf)
	case 4096:
		atomic.AddUint64(&bp.puts4K, 1)
		bp.pool4K.Put(&buf)
	case 16384:
		atomic.AddUint64(&bp.puts16K, 1)
		bp.pool16K.Put(&buf)
	default:
		// Non-standard capacity - let GC handle it
		// This can happen if buffer grew beyond original pool size
	}
}

// BufferPoolStats returns statistics about buffer pool usage.
// Returns nil if buffer pooling is disabled.
type BufferPoolStats struct {
	Gets512       uint64
	Gets1K        uint64
	Gets4K        uint64
	Gets16K       uint64
	GetsOversized uint64
	Puts512       uint64
	Puts1K        uint64
	Puts4K        uint64
	Puts16K       uint64
}

// GetBufferPoolStats returns current buffer pool statistics.
// Returns nil if buffer pooling is disabled.
func GetBufferPoolStats() *BufferPoolStats {
	globalBufferPool.mu.RLock()
	defer globalBufferPool.mu.RUnlock()
	
	if !globalBufferPool.enabled {
		return nil
	}
	
	return &BufferPoolStats{
		Gets512:       atomic.LoadUint64(&globalBufferPool.gets512),
		Gets1K:        atomic.LoadUint64(&globalBufferPool.gets1K),
		Gets4K:        atomic.LoadUint64(&globalBufferPool.gets4K),
		Gets16K:       atomic.LoadUint64(&globalBufferPool.gets16K),
		GetsOversized: atomic.LoadUint64(&globalBufferPool.getsOversized),
		Puts512:       atomic.LoadUint64(&globalBufferPool.puts512),
		Puts1K:        atomic.LoadUint64(&globalBufferPool.puts1K),
		Puts4K:        atomic.LoadUint64(&globalBufferPool.puts4K),
		Puts16K:       atomic.LoadUint64(&globalBufferPool.puts16K),
	}
}

// NewStreamPooled creates a new Stream using a buffer from the pool.
// When the Stream is no longer needed, call ReleaseStream() to return the buffer.
// If buffer pooling is disabled, this behaves identically to NewStream().
func NewStreamPooled(size int) *Stream {
	buf := globalBufferPool.GetBuffer(size)
	return NewStream(buf)
}

// ReleaseStream returns a Stream's buffer to the pool for reuse.
// After calling this, the Stream should not be used.
// If buffer pooling is disabled, this is a no-op.
func ReleaseStream(s *Stream) {
	if s == nil || s.Buffer == nil {
		return
	}
	
	// Get the underlying byte slice
	buf := s.Bytes()
	globalBufferPool.PutBuffer(buf)
}
