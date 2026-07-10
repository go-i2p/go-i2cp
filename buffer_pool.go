package go_i2cp

import (
	"sync"
	"sync/atomic"
)

// bufferSizeClass is a single pooled bucket for a fixed buffer capacity, along
// with atomic get/put counters for that bucket.
type bufferSizeClass struct {
	size int
	pool sync.Pool
	gets uint64
	puts uint64
}

// bufferSizeClasses defines the pooled bucket capacities, smallest first.
// Size classes (power of 2 for efficient growth):
//   - 512 bytes:  Small messages (typical I2CP control messages)
//   - 1024 bytes: Medium messages (session creation, leasesets)
//   - 4096 bytes: Large messages (destination creation, large payloads)
//   - 16384 bytes: Extra large messages (bulk data transfer)
var bufferSizeClasses = [4]int{512, 1024, 4096, 16384}

// bufferPool manages reusable byte slices to reduce GC pressure.
// Uses sync.Pool with size-based buckets for efficient allocation.
type bufferPool struct {
	classes [4]*bufferSizeClass
	enabled bool
	mu      sync.RWMutex

	// getsOversized counts GetBuffer calls for sizes larger than any size class.
	getsOversized uint64
}

// newBufferPool constructs a bufferPool with a sync.Pool per size class.
func newBufferPool() *bufferPool {
	bp := &bufferPool{}
	for i, size := range bufferSizeClasses {
		size := size // capture for the New closure
		bp.classes[i] = &bufferSizeClass{
			size: size,
			pool: sync.Pool{
				New: func() interface{} {
					buf := make([]byte, 0, size)
					return &buf
				},
			},
		}
	}
	return bp
}

// Global buffer pool instance
var globalBufferPool = func() *bufferPool {
	bp := newBufferPool()
	bp.enabled = false // Disabled by default for backward compatibility
	return bp
}()

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
	return globalBufferPool.isEnabled()
}

// isEnabled reports whether this pool is currently enabled.
func (bp *bufferPool) isEnabled() bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.enabled
}

// bucketFor returns the size class that fits the requested size (smallest
// class with size >= requested), or nil if no class is large enough.
func (bp *bufferPool) bucketFor(size int) *bufferSizeClass {
	for _, c := range bp.classes {
		if size <= c.size {
			return c
		}
	}
	return nil
}

// GetBuffer retrieves a buffer from the appropriate pool based on requested size.
// Returns a buffer with capacity >= size. The buffer's length is 0.
func (bp *bufferPool) GetBuffer(size int) []byte {
	if !bp.isEnabled() {
		return make([]byte, 0, size)
	}

	class := bp.bucketFor(size)
	if class == nil {
		// Size too large for pooling - allocate directly
		atomic.AddUint64(&bp.getsOversized, 1)
		return make([]byte, 0, size)
	}

	atomic.AddUint64(&class.gets, 1)
	bufPtr := class.pool.Get().(*[]byte)

	// Reset buffer to empty but preserve capacity
	return (*bufPtr)[:0]
}

// PutBuffer returns a buffer to the appropriate pool for reuse.
// The buffer will be reset to length 0 before being returned to the pool.
func (bp *bufferPool) PutBuffer(buf []byte) {
	if !bp.isEnabled() {
		return // Let GC handle it
	}

	// Don't pool buffers that are too large or nil
	capacity := cap(buf)
	if buf == nil || capacity > bufferSizeClasses[len(bufferSizeClasses)-1] {
		return
	}

	// Reset buffer to empty (preserve capacity)
	buf = buf[:0]

	// Return to the pool whose size class exactly matches this buffer's capacity
	for _, class := range bp.classes {
		if class.size == capacity {
			atomic.AddUint64(&class.puts, 1)
			class.pool.Put(&buf)
			return
		}
	}
	// Non-standard capacity - let GC handle it
	// This can happen if buffer grew beyond original pool size
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
	if !globalBufferPool.isEnabled() {
		return nil
	}

	classes := globalBufferPool.classes
	return &BufferPoolStats{
		Gets512:       atomic.LoadUint64(&classes[0].gets),
		Gets1K:        atomic.LoadUint64(&classes[1].gets),
		Gets4K:        atomic.LoadUint64(&classes[2].gets),
		Gets16K:       atomic.LoadUint64(&classes[3].gets),
		GetsOversized: atomic.LoadUint64(&globalBufferPool.getsOversized),
		Puts512:       atomic.LoadUint64(&classes[0].puts),
		Puts1K:        atomic.LoadUint64(&classes[1].puts),
		Puts4K:        atomic.LoadUint64(&classes[2].puts),
		Puts16K:       atomic.LoadUint64(&classes[3].puts),
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
