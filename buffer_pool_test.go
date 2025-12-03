package go_i2cp

import (
"sync"
"sync/atomic"
"testing"
)

func TestBufferPoolDisabledByDefault(t *testing.T) {
	if IsBufferPoolEnabled() {
		t.Fatal("Buffer pool should be disabled by default")
	}
}

func TestEnableDisableBufferPool(t *testing.T) {
	// Ensure disabled initially
	DisableBufferPool()
	
	if IsBufferPoolEnabled() {
		t.Fatal("Buffer pool should be disabled")
	}
	
	EnableBufferPool()
	if !IsBufferPoolEnabled() {
		t.Fatal("Buffer pool should be enabled after EnableBufferPool()")
	}
	
	DisableBufferPool()
	if IsBufferPoolEnabled() {
		t.Fatal("Buffer pool should be disabled after DisableBufferPool()")
	}
}

func TestGetBufferSizeClasses(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	tests := []struct {
		name            string
		requestedSize   int
		expectedMinCap  int
	}{
		{"tiny", 64, 512},
		{"small", 512, 512},
		{"medium", 1024, 1024},
		{"large", 4096, 4096},
		{"xlarge", 16384, 16384},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := globalBufferPool.GetBuffer(tt.requestedSize)
			
			if cap(buf) < tt.expectedMinCap {
				t.Errorf("Expected capacity >= %d, got %d", tt.expectedMinCap, cap(buf))
			}
			
			if len(buf) != 0 {
				t.Errorf("Expected length 0, got %d", len(buf))
			}
			
			// Return to pool
			globalBufferPool.PutBuffer(buf)
		})
	}
}

func TestGetBufferOversized(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	// Request size larger than largest pool
	buf := globalBufferPool.GetBuffer(32768)
	
	if cap(buf) < 32768 {
		t.Errorf("Expected capacity >= 32768, got %d", cap(buf))
	}
	
	// Should not be pooled
	initialOversized := globalBufferPool.getsOversized
	globalBufferPool.PutBuffer(buf)
	
	// Stats should reflect oversized allocation
	if globalBufferPool.getsOversized <= initialOversized {
		t.Error("Oversized get should be tracked in stats")
	}
}

func TestPutBufferInvalidSize(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	// Put nil buffer - should not crash
	globalBufferPool.PutBuffer(nil)
	
	// Put oversized buffer - should be ignored
	oversized := make([]byte, 0, 32768)
	globalBufferPool.PutBuffer(oversized)
}

func TestBufferPoolReuse(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	// Get buffer, write data, return it
	buf1 := globalBufferPool.GetBuffer(512)
	buf1 = append(buf1, []byte("test data")...)
	
	if len(buf1) != 9 {
		t.Errorf("Expected length 9, got %d", len(buf1))
	}
	
	globalBufferPool.PutBuffer(buf1)
	
	// Get another buffer from same pool - should be reset
	buf2 := globalBufferPool.GetBuffer(512)
	
	if len(buf2) != 0 {
		t.Errorf("Expected reused buffer to have length 0, got %d", len(buf2))
	}
	
	if cap(buf2) < 512 {
		t.Errorf("Expected capacity >= 512, got %d", cap(buf2))
	}
}

func TestBufferPoolDisabledAllocations(t *testing.T) {
	DisableBufferPool()
	
	buf := globalBufferPool.GetBuffer(1024)
	
	if cap(buf) != 1024 {
		t.Errorf("Expected exact capacity 1024 when pooling disabled, got %d", cap(buf))
	}
	
	// Put should be no-op when disabled
	globalBufferPool.PutBuffer(buf)
}

func TestNewStreamPooled(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	stream := NewStreamPooled(1024)
	
	if stream == nil {
		t.Fatal("NewStreamPooled returned nil")
	}
	
	if stream.Cap() < 1024 {
		t.Errorf("Expected capacity >= 1024, got %d", stream.Cap())
	}
	
	// Write some data
	stream.WriteString("test")
	
	if stream.Len() != 4 {
		t.Errorf("Expected length 4, got %d", stream.Len())
	}
	
	// Release back to pool
	ReleaseStream(stream)
}

func TestReleaseStreamNil(t *testing.T) {
	// Should not crash with nil stream
	ReleaseStream(nil)
}

func TestBufferPoolStats(t *testing.T) {
	// Disabled - should return nil
	DisableBufferPool()
	if stats := GetBufferPoolStats(); stats != nil {
		t.Error("Stats should be nil when buffer pool disabled")
	}
	
	// Enabled - should return stats
	EnableBufferPool()
	defer DisableBufferPool()
	
	// Clear stats (for test isolation)
	atomic.StoreUint64(&globalBufferPool.gets512, 0)
	atomic.StoreUint64(&globalBufferPool.puts512, 0)
	
	// Perform some operations
	buf := globalBufferPool.GetBuffer(512)
	globalBufferPool.PutBuffer(buf)
	
	stats := GetBufferPoolStats()
	if stats == nil {
		t.Fatal("Stats should not be nil when buffer pool enabled")
	}
	
	if stats.Gets512 == 0 {
		t.Error("Expected Gets512 > 0")
	}
	
	if stats.Puts512 == 0 {
		t.Error("Expected Puts512 > 0")
	}
}

func TestBufferPoolConcurrency(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				// Randomly access different size classes
				size := []int{512, 1024, 4096, 16384}[j%4]
				buf := globalBufferPool.GetBuffer(size)
				buf = append(buf, byte(j))
				globalBufferPool.PutBuffer(buf)
			}
		}()
	}
	
	wg.Wait()
	
	stats := GetBufferPoolStats()
	if stats == nil {
		t.Fatal("Stats should not be nil")
	}
	
	totalGets := stats.Gets512 + stats.Gets1K + stats.Gets4K + stats.Gets16K
	expectedGets := uint64(numGoroutines * numOperations)
	
	if totalGets < expectedGets || totalGets > expectedGets+uint64(numGoroutines) {
		t.Errorf("Expected %d total gets, got %d", expectedGets, totalGets)
	}
}

func TestBufferPoolToggleConcurrency(t *testing.T) {
	var wg sync.WaitGroup
	
	// Concurrent enable/disable operations
	for i := 0; i < 50; i++ {
		wg.Add(2)
		
		go func() {
			defer wg.Done()
			EnableBufferPool()
		}()
		
		go func() {
			defer wg.Done()
			DisableBufferPool()
		}()
	}
	
	wg.Wait()
	
	// No crash = success
}

func TestBufferPoolNonStandardCapacity(t *testing.T) {
	EnableBufferPool()
	defer DisableBufferPool()
	
	// Create buffer with non-standard capacity
	buf := make([]byte, 0, 2000) // Between 1024 and 4096
	
	// Put should handle this gracefully (ignore it)
	globalBufferPool.PutBuffer(buf)
	
	// Should not crash or cause issues
}
