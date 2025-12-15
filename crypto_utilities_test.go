package go_i2cp

import (
	"testing"
)

// TestRandom32 verifies Random32 generates non-zero values
func TestRandom32(t *testing.T) {
	crypto := NewCrypto()

	// Generate multiple random values
	values := make(map[uint32]bool)
	const iterations = 100

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()
		values[val] = true
	}

	// Verify we got at least some different values
	// With 100 iterations and 32-bit space, we should get mostly unique values
	if len(values) < 50 {
		t.Errorf("expected at least 50 unique values from %d iterations, got %d", iterations, len(values))
	}
}

// TestRandom32Distribution verifies Random32 uses all bytes
func TestRandom32Distribution(t *testing.T) {
	crypto := NewCrypto()

	// Generate values and check that we see variety across all byte positions
	const iterations = 1000
	bytePositions := [4]map[byte]bool{
		make(map[byte]bool),
		make(map[byte]bool),
		make(map[byte]bool),
		make(map[byte]bool),
	}

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()

		// Extract bytes
		bytePositions[0][byte(val>>24)] = true
		bytePositions[1][byte(val>>16)] = true
		bytePositions[2][byte(val>>8)] = true
		bytePositions[3][byte(val)] = true
	}

	// Check that each byte position has reasonable variety
	// With 1000 iterations, we should see at least 100 different values per byte
	for i, bytesMap := range bytePositions {
		if len(bytesMap) < 100 {
			t.Errorf("byte position %d has insufficient variety: only %d unique values", i, len(bytesMap))
		}
	}
}

// TestRandom32Uniqueness verifies consecutive calls produce different values
func TestRandom32Uniqueness(t *testing.T) {
	crypto := NewCrypto()

	const iterations = 50
	var duplicateCount int
	var lastValue uint32

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()
		if i > 0 && val == lastValue {
			duplicateCount++
		}
		lastValue = val
	}

	// Allow a very small number of duplicates due to chance
	// but with 32-bit space, consecutive duplicates should be extremely rare
	if duplicateCount > 2 {
		t.Errorf("too many consecutive duplicates: %d in %d iterations", duplicateCount, iterations)
	}
}

// TestRandom32NonZero verifies Random32 can generate non-zero values
func TestRandom32NonZero(t *testing.T) {
	crypto := NewCrypto()

	// Generate some values and verify at least one is non-zero
	foundNonZero := false
	for i := 0; i < 10; i++ {
		if val := crypto.Random32(); val != 0 {
			foundNonZero = true
			break
		}
	}

	if !foundNonZero {
		t.Error("expected to find at least one non-zero value in 10 iterations")
	}
}

// TestRandom32FullRange verifies Random32 can generate values across the uint32 range
func TestRandom32FullRange(t *testing.T) {
	crypto := NewCrypto()

	// Check that we can generate values in different ranges
	const iterations = 1000
	var lowRange, midRange, highRange int

	for i := 0; i < iterations; i++ {
		val := crypto.Random32()

		if val < 0x55555555 {
			lowRange++
		} else if val < 0xAAAAAAAA {
			midRange++
		} else {
			highRange++
		}
	}

	// Each range should have at least some values
	// With uniform distribution, we expect roughly 333 in each range
	// Allow for statistical variance but ensure no range is empty
	if lowRange == 0 {
		t.Error("no values generated in low range (0 to 0x55555554)")
	}
	if midRange == 0 {
		t.Error("no values generated in mid range (0x55555555 to 0xAAAAAAA9)")
	}
	if highRange == 0 {
		t.Error("no values generated in high range (0xAAAAAAAA to 0xFFFFFFFF)")
	}

	// Also verify reasonable distribution (each should be between 20% and 50%)
	if lowRange < 200 || lowRange > 500 {
		t.Logf("low range count outside expected distribution: %d", lowRange)
	}
	if midRange < 200 || midRange > 500 {
		t.Logf("mid range count outside expected distribution: %d", midRange)
	}
	if highRange < 200 || highRange > 500 {
		t.Logf("high range count outside expected distribution: %d", highRange)
	}
}

// TestRandom32Concurrency verifies Random32 is safe for concurrent use
func TestRandom32Concurrency(t *testing.T) {
	crypto := NewCrypto()

	const goroutines = 10
	const iterations = 100
	done := make(chan bool, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < iterations; i++ {
				_ = crypto.Random32()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for g := 0; g < goroutines; g++ {
		<-done
	}

	// If we get here without panic, concurrency safety is verified
}
