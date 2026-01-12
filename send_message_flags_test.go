package go_i2cp

import (
	"testing"
)

// TestBuildSendMessageFlags verifies flag construction per I2CP spec
func TestBuildSendMessageFlags(t *testing.T) {
	tests := []struct {
		name         string
		tagThreshold uint8
		tagCount     uint8
		expectedHex  uint16
	}{
		{
			name:         "Zero flags (default)",
			tagThreshold: 0,
			tagCount:     0,
			expectedHex:  0x0000,
		},
		{
			name:         "Threshold only (bits 7-4)",
			tagThreshold: 5,
			tagCount:     0,
			expectedHex:  0x0050, // 0101 0000
		},
		{
			name:         "Count only (bits 3-0)",
			tagThreshold: 0,
			tagCount:     8,
			expectedHex:  0x0008,
		},
		{
			name:         "Both threshold and count",
			tagThreshold: 7,
			tagCount:     3,
			expectedHex:  0x0073, // 0111 0011
		},
		{
			name:         "Max values (15 for each)",
			tagThreshold: 15,
			tagCount:     15,
			expectedHex:  0x00FF, // 1111 1111
		},
		{
			name:         "Clamp threshold overflow",
			tagThreshold: 20, // > 15, should clamp to 0
			tagCount:     5,
			expectedHex:  0x0005,
		},
		{
			name:         "Clamp count overflow",
			tagThreshold: 3,
			tagCount:     18, // > 15, should clamp to 0
			expectedHex:  0x0030,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildSendMessageFlags(tt.tagThreshold, tt.tagCount)
			if result != tt.expectedHex {
				t.Errorf("BuildSendMessageFlags(%d, %d) = 0x%04x, want 0x%04x",
					tt.tagThreshold, tt.tagCount, result, tt.expectedHex)
			}
		})
	}
}

// TestParseSendMessageFlags verifies flag parsing per I2CP spec
func TestParseSendMessageFlags(t *testing.T) {
	tests := []struct {
		name          string
		flags         uint16
		wantNoLS      bool
		wantThreshold uint8
		wantCount     uint8
		wantErr       bool
	}{
		{
			name:          "Zero flags",
			flags:         0x0000,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       false,
		},
		{
			name:          "No LeaseSet flag set (bit 8)",
			flags:         SEND_MSG_FLAG_NO_LEASESET,
			wantNoLS:      true,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       false,
		},
		{
			name:          "Threshold and count without NoLS",
			flags:         0x0073, // threshold=7, count=3
			wantNoLS:      false,
			wantThreshold: 7,
			wantCount:     3,
			wantErr:       false,
		},
		{
			name:          "All valid bits set",
			flags:         0x01FF, // NoLS + max threshold + max count
			wantNoLS:      true,
			wantThreshold: 15,
			wantCount:     15,
			wantErr:       false,
		},
		{
			name:          "Reserved bits set (bit 15)",
			flags:         0x8000,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       true,
		},
		{
			name:          "Reserved bits set (bit 11)",
			flags:         0x0800,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       true,
		},
		{
			name:          "Deprecated reliability bit 9 set",
			flags:         0x0200,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       true,
		},
		{
			name:          "Deprecated reliability bit 10 set",
			flags:         0x0400,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       true,
		},
		{
			name:          "Both reliability bits set",
			flags:         0x0600,
			wantNoLS:      false,
			wantThreshold: 0,
			wantCount:     0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noLS, threshold, count, err := ParseSendMessageFlags(tt.flags)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSendMessageFlags(0x%04x) error = %v, wantErr %v",
					tt.flags, err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if noLS != tt.wantNoLS {
					t.Errorf("noLeaseSet = %v, want %v", noLS, tt.wantNoLS)
				}
				if threshold != tt.wantThreshold {
					t.Errorf("threshold = %d, want %d", threshold, tt.wantThreshold)
				}
				if count != tt.wantCount {
					t.Errorf("count = %d, want %d", count, tt.wantCount)
				}
			}
		})
	}
}

// TestValidateSendMessageFlags verifies flag validation per I2CP spec
func TestValidateSendMessageFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   uint16
		wantErr bool
	}{
		{
			name:    "Valid: zero flags",
			flags:   0x0000,
			wantErr: false,
		},
		{
			name:    "Valid: NoLeaseSet only",
			flags:   SEND_MSG_FLAG_NO_LEASESET,
			wantErr: false,
		},
		{
			name:    "Valid: threshold and count",
			flags:   BuildSendMessageFlags(5, 3),
			wantErr: false,
		},
		{
			name:    "Valid: all allowed bits",
			flags:   SEND_MSG_FLAG_NO_LEASESET | BuildSendMessageFlags(15, 15),
			wantErr: false,
		},
		{
			name:    "Invalid: reserved bit 15",
			flags:   0x8000,
			wantErr: true,
		},
		{
			name:    "Invalid: reserved bits 15-11",
			flags:   0xF800,
			wantErr: true,
		},
		{
			name:    "Invalid: reliability override bit 9",
			flags:   0x0200,
			wantErr: true,
		},
		{
			name:    "Invalid: reliability override bit 10",
			flags:   0x0400,
			wantErr: true,
		},
		{
			name:    "Invalid: both reliability bits",
			flags:   0x0600,
			wantErr: true,
		},
		{
			name:    "Invalid: reserved + valid flags",
			flags:   0x8100, // reserved bit 15 + NoLeaseSet
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSendMessageFlags(tt.flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSendMessageFlags(0x%04x) error = %v, wantErr %v",
					tt.flags, err, tt.wantErr)
			}
		})
	}
}

// TestSendMessageFlagsConstants verifies constant values match spec
func TestSendMessageFlagsConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint16
		expected uint16
	}{
		{"SEND_MSG_FLAGS_RESERVED_MASK", SEND_MSG_FLAGS_RESERVED_MASK, 0xF800},
		{"SEND_MSG_FLAGS_RELIABILITY_MASK", SEND_MSG_FLAGS_RELIABILITY_MASK, 0x0600},
		{"SEND_MSG_FLAGS_TAG_THRESHOLD", SEND_MSG_FLAGS_TAG_THRESHOLD, 0x00F0},
		{"SEND_MSG_FLAGS_TAG_COUNT", SEND_MSG_FLAGS_TAG_COUNT, 0x000F},
		{"SEND_MSG_FLAG_NO_LEASESET", SEND_MSG_FLAG_NO_LEASESET, 0x0100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = 0x%04x, want 0x%04x", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestSendMessageFlagsRoundTrip verifies build -> parse -> build consistency
func TestSendMessageFlagsRoundTrip(t *testing.T) {
	testCases := []struct {
		threshold uint8
		count     uint8
	}{
		{0, 0},
		{5, 3},
		{15, 15},
		{7, 0},
		{0, 8},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// Build flags
			flags := BuildSendMessageFlags(tc.threshold, tc.count)

			// Parse flags
			_, parsedThreshold, parsedCount, err := ParseSendMessageFlags(flags)
			if err != nil {
				t.Fatalf("ParseSendMessageFlags failed: %v", err)
			}

			// Verify round-trip consistency
			if parsedThreshold != tc.threshold {
				t.Errorf("threshold roundtrip: got %d, want %d", parsedThreshold, tc.threshold)
			}
			if parsedCount != tc.count {
				t.Errorf("count roundtrip: got %d, want %d", parsedCount, tc.count)
			}

			// Rebuild and compare
			rebuiltFlags := BuildSendMessageFlags(parsedThreshold, parsedCount)
			if rebuiltFlags != flags {
				t.Errorf("flags roundtrip: got 0x%04x, want 0x%04x", rebuiltFlags, flags)
			}
		})
	}
}

// TestSendMessageFlagsNoLeaseSetCombination tests combining NoLeaseSet with tag flags
func TestSendMessageFlagsNoLeaseSetCombination(t *testing.T) {
	// Build flags with threshold and count
	baseFlags := BuildSendMessageFlags(5, 3)

	// Add NoLeaseSet flag
	combinedFlags := baseFlags | SEND_MSG_FLAG_NO_LEASESET

	// Validate
	if err := ValidateSendMessageFlags(combinedFlags); err != nil {
		t.Fatalf("ValidateSendMessageFlags failed: %v", err)
	}

	// Parse and verify all components
	noLS, threshold, count, err := ParseSendMessageFlags(combinedFlags)
	if err != nil {
		t.Fatalf("ParseSendMessageFlags failed: %v", err)
	}

	if !noLS {
		t.Error("noLeaseSet should be true")
	}
	if threshold != 5 {
		t.Errorf("threshold = %d, want 5", threshold)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

// TestSendMessageTagThresholdConstants verifies tag threshold constant values
func TestSendMessageTagThresholdConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"SEND_MSG_TAG_THRESHOLD_DEFAULT", SEND_MSG_TAG_THRESHOLD_DEFAULT, 0},
		{"SEND_MSG_TAG_THRESHOLD_2", SEND_MSG_TAG_THRESHOLD_2, 1},
		{"SEND_MSG_TAG_THRESHOLD_3", SEND_MSG_TAG_THRESHOLD_3, 2},
		{"SEND_MSG_TAG_THRESHOLD_192", SEND_MSG_TAG_THRESHOLD_192, 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestSendMessageTagCountConstants verifies tag count constant values
func TestSendMessageTagCountConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"SEND_MSG_TAG_COUNT_DEFAULT", SEND_MSG_TAG_COUNT_DEFAULT, 0},
		{"SEND_MSG_TAG_COUNT_2", SEND_MSG_TAG_COUNT_2, 1},
		{"SEND_MSG_TAG_COUNT_4", SEND_MSG_TAG_COUNT_4, 2},
		{"SEND_MSG_TAG_COUNT_160", SEND_MSG_TAG_COUNT_160, 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}
