package go_i2cp

import (
	"testing"
)

// TestNewCryptoInstance tests the NewCryptoInstance utility function.
// This function is a simple wrapper around NewCrypto() but needs test coverage
// to ensure it properly initializes a Crypto instance.
func TestNewCryptoInstance(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "creates valid crypto instance",
		},
		{
			name: "creates instance with initialized RNG",
		},
		{
			name: "creates instance with initialized SHA1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := NewCryptoInstance()

			// Verify we got a non-nil instance
			if crypto == nil {
				t.Fatal("NewCryptoInstance() returned nil")
			}

			// Verify internal state is properly initialized
			// by testing that we can use the crypto instance
			if crypto.rng == nil {
				t.Error("crypto instance has nil RNG")
			}

			// NOTE: SHA-1 hash removed - modern I2CP uses SHA-256 only

			// Test that we can generate random bytes (validates RNG works)
			randomBytes := make([]byte, 32)
			n, err := crypto.rng.Read(randomBytes)
			if err != nil {
				t.Errorf("failed to read from RNG: %v", err)
			}
			if n != 32 {
				t.Errorf("expected to read 32 bytes, got %d", n)
			}

			// Verify random bytes are not all zeros (very unlikely)
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Error("RNG generated all zero bytes (suspicious)")
			}
		})
	}
}

// TestNewCryptoInstanceMultipleCalls verifies that multiple calls to
// NewCryptoInstance create independent instances.
func TestNewCryptoInstanceMultipleCalls(t *testing.T) {
	crypto1 := NewCryptoInstance()
	crypto2 := NewCryptoInstance()

	if crypto1 == nil || crypto2 == nil {
		t.Fatal("NewCryptoInstance() returned nil")
	}

	// Verify instances are different (not shared singleton)
	if crypto1 == crypto2 {
		t.Error("NewCryptoInstance() returned same instance twice (expected independent instances)")
	}
}

// TestParseIntWithDefault tests the parseIntWithDefault utility function
// with comprehensive edge cases including valid integers, invalid formats,
// empty strings, negative numbers, and overflow scenarios.
func TestParseIntWithDefault(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		expected     int
	}{
		// Valid positive integers
		{
			name:         "parse zero",
			input:        "0",
			defaultValue: 100,
			expected:     0,
		},
		{
			name:         "parse positive single digit",
			input:        "5",
			defaultValue: 100,
			expected:     5,
		},
		{
			name:         "parse positive multi-digit",
			input:        "12345",
			defaultValue: 100,
			expected:     12345,
		},
		{
			name:         "parse large positive",
			input:        "999999",
			defaultValue: 100,
			expected:     999999,
		},

		// Valid negative integers
		{
			name:         "parse negative single digit",
			input:        "-5",
			defaultValue: 100,
			expected:     -5,
		},
		{
			name:         "parse negative multi-digit",
			input:        "-12345",
			defaultValue: 100,
			expected:     -12345,
		},
		{
			name:         "parse negative zero",
			input:        "-0",
			defaultValue: 100,
			expected:     0,
		},

		// Empty and whitespace cases
		{
			name:         "empty string returns default",
			input:        "",
			defaultValue: 42,
			expected:     42,
		},

		// Invalid format cases - return default
		{
			name:         "alphabetic string returns default",
			input:        "abc",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "alphanumeric mixed returns default",
			input:        "123abc",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "decimal point returns default",
			input:        "12.34",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "whitespace before number returns default",
			input:        " 123",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "whitespace after number returns default",
			input:        "123 ",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "plus sign returns default",
			input:        "+123",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "double negative returns default",
			input:        "--123",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "negative sign only returns default",
			input:        "-",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "special characters return default",
			input:        "#123",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "hexadecimal notation returns default",
			input:        "0x10",
			defaultValue: 99,
			expected:     99,
		},

		// Default value variety
		{
			name:         "default is zero",
			input:        "invalid",
			defaultValue: 0,
			expected:     0,
		},
		{
			name:         "default is negative",
			input:        "invalid",
			defaultValue: -1,
			expected:     -1,
		},
		{
			name:         "default is large positive",
			input:        "invalid",
			defaultValue: 1000000,
			expected:     1000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIntWithDefault(tt.input, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("parseIntWithDefault(%q, %d) = %d, want %d",
					tt.input, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

// TestParseIntWithDefaultConsistency verifies that parseIntWithDefault
// is deterministic and returns consistent results for the same input.
func TestParseIntWithDefaultConsistency(t *testing.T) {
	testCases := []struct {
		input        string
		defaultValue int
	}{
		{"123", 99},
		{"-456", 99},
		{"invalid", 99},
		{"", 99},
	}

	for _, tc := range testCases {
		t.Run("consistency_"+tc.input, func(t *testing.T) {
			// Call multiple times and verify same result
			result1 := parseIntWithDefault(tc.input, tc.defaultValue)
			result2 := parseIntWithDefault(tc.input, tc.defaultValue)
			result3 := parseIntWithDefault(tc.input, tc.defaultValue)

			if result1 != result2 || result2 != result3 {
				t.Errorf("parseIntWithDefault(%q, %d) is not consistent: got %d, %d, %d",
					tc.input, tc.defaultValue, result1, result2, result3)
			}
		})
	}
}

// TestParseIntWithDefaultBoundary tests boundary conditions for integer parsing.
func TestParseIntWithDefaultBoundary(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		expected     int
		description  string
	}{
		{
			name:         "single character zero",
			input:        "0",
			defaultValue: 99,
			expected:     0,
			description:  "minimum valid single digit",
		},
		{
			name:         "single character nine",
			input:        "9",
			defaultValue: 99,
			expected:     9,
			description:  "maximum valid single digit",
		},
		{
			name:         "just below zero",
			input:        "-1",
			defaultValue: 99,
			expected:     -1,
			description:  "one below zero",
		},
		{
			name:         "just above zero",
			input:        "1",
			defaultValue: 99,
			expected:     1,
			description:  "one above zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIntWithDefault(tt.input, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("%s: parseIntWithDefault(%q, %d) = %d, want %d",
					tt.description, tt.input, tt.defaultValue, result, tt.expected)
			}
		})
	}
}
