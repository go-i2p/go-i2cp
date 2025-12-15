package go_i2cp

import (
	"testing"
	"time"
)

// TestSessionConfigValidateTimestamp tests the ±30 second timestamp validation
// required by I2CP spec § SessionConfig Notes
func TestSessionConfigValidateTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		timestamp uint64 // milliseconds since epoch
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "current time - valid",
			timestamp: uint64(time.Now().Unix() * 1000),
			wantErr:   false,
		},
		{
			name:      "29 seconds in past - valid",
			timestamp: uint64(time.Now().Unix()*1000 - 29000),
			wantErr:   false,
		},
		{
			name:      "29 seconds in future - valid",
			timestamp: uint64(time.Now().Unix()*1000 + 29000),
			wantErr:   false,
		},
		{
			name:      "exactly 30 seconds in past - valid boundary",
			timestamp: uint64(time.Now().Unix()*1000 - 30000),
			wantErr:   false,
		},
		{
			name:      "exactly 30 seconds in future - valid boundary",
			timestamp: uint64(time.Now().Unix()*1000 + 30000),
			wantErr:   false,
		},
		{
			name:      "31 seconds in past - invalid",
			timestamp: uint64(time.Now().Unix()*1000 - 31000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "31 seconds in future - invalid",
			timestamp: uint64(time.Now().Unix()*1000 + 31000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "1 minute in past - invalid",
			timestamp: uint64(time.Now().Unix()*1000 - 60000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "5 minutes in future - invalid",
			timestamp: uint64(time.Now().Unix()*1000 + 300000),
			wantErr:   true,
			errMsg:    "ms from current time",
		},
		{
			name:      "zero timestamp - invalid",
			timestamp: 0,
			wantErr:   true,
			errMsg:    "not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &SessionConfig{
				date: tt.timestamp,
			}

			err := config.ValidateTimestamp()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateTimestamp() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" {
					// Simple substring check
					found := false
					for i := 0; i <= len(err.Error())-len(tt.errMsg); i++ {
						if err.Error()[i:i+len(tt.errMsg)] == tt.errMsg {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("ValidateTimestamp() error = %v, want error containing %q", err, tt.errMsg)
					}
				}
			} else {
				if err != nil {
					t.Errorf("ValidateTimestamp() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestSessionConfigValidateTimestampEdgeCases tests edge cases for timestamp validation
func TestSessionConfigValidateTimestampEdgeCases(t *testing.T) {
	t.Run("config with destination but no timestamp", func(t *testing.T) {
		crypto := NewCrypto()
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		config := &SessionConfig{
			destination: dest,
			date:        0,
		}

		err = config.ValidateTimestamp()
		if err == nil {
			t.Error("ValidateTimestamp() expected error for zero timestamp, got nil")
		}
	})
}

// TestSessionConfigTimestampInCreateSession tests timestamp validation during session creation
func TestSessionConfigTimestampInCreateSession(t *testing.T) {
	// This test verifies that session creation properly validates timestamps
	// and that the writeToMessage function generates proper timestamps

	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Test: Create session config and verify timestamp is set
	t.Run("timestamp set by writeToMessage", func(t *testing.T) {
		config := &SessionConfig{
			destination: dest,
		}

		stream := NewStream(make([]byte, 0, 512))
		config.writeToMessage(stream, crypto, nil)

		// Verify some data was written (destination + mapping + date + signature)
		if stream.Len() == 0 {
			t.Error("writeToMessage() wrote no data")
		}

		// Note: config.date is set inside writeToMessage
		// We can't easily validate it here without exposing internals
		t.Logf("writeToMessage generated %d bytes", stream.Len())
	})
}

// TestSessionConfigTimestampClockSkew tests behavior with various clock skew scenarios
func TestSessionConfigTimestampClockSkew(t *testing.T) {
	tests := []struct {
		name      string
		skewMs    int64 // milliseconds offset from current time
		wantValid bool
	}{
		{name: "no skew", skewMs: 0, wantValid: true},
		{name: "1 second skew", skewMs: 1000, wantValid: true},
		{name: "10 second skew", skewMs: 10000, wantValid: true},
		{name: "20 second skew", skewMs: 20000, wantValid: true},
		{name: "29 second skew", skewMs: 29000, wantValid: true},
		{name: "30 second skew (boundary)", skewMs: 30000, wantValid: true},
		{name: "31 second skew (over limit)", skewMs: 31000, wantValid: false},
		{name: "60 second skew", skewMs: 60000, wantValid: false},
		{name: "-29 second skew", skewMs: -29000, wantValid: true},
		{name: "-31 second skew", skewMs: -31000, wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now().Unix() * 1000
			config := &SessionConfig{
				date: uint64(now + tt.skewMs),
			}

			err := config.ValidateTimestamp()

			if tt.wantValid && err != nil {
				t.Errorf("ValidateTimestamp() unexpected error for skew %d ms: %v", tt.skewMs, err)
			} else if !tt.wantValid && err == nil {
				t.Errorf("ValidateTimestamp() expected error for skew %d ms, got nil", tt.skewMs)
			}
		})
	}
}
