package go_i2cp

import "testing"

// TestProtocolConstants verifies that protocol number constants match the I2P specification.
// These values are defined in the Java I2PSession interface and must remain consistent.
func TestProtocolConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"ProtoStreaming", ProtoStreaming, 6},
		{"ProtoDatagram", ProtoDatagram, 17},
		{"ProtoDatagramRaw", ProtoDatagramRaw, 18},
		{"ProtoDatagram2", ProtoDatagram2, 19},
		{"ProtoDatagram3", ProtoDatagram3, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestProtocolConstantsDocumentation verifies that the protocol constants
// follow expected patterns for I2P datagram protocols.
func TestProtocolConstantsDocumentation(t *testing.T) {
	// Streaming protocol should be less than datagram protocols
	if ProtoStreaming >= ProtoDatagram {
		t.Errorf("ProtoStreaming (%d) should be less than ProtoDatagram (%d)",
			ProtoStreaming, ProtoDatagram)
	}

	// Datagram protocols should be sequential
	if ProtoDatagram+1 != ProtoDatagramRaw {
		t.Errorf("ProtoDatagramRaw (%d) should be ProtoDatagram+1 (%d)",
			ProtoDatagramRaw, ProtoDatagram+1)
	}

	if ProtoDatagramRaw+1 != ProtoDatagram2 {
		t.Errorf("ProtoDatagram2 (%d) should be ProtoDatagramRaw+1 (%d)",
			ProtoDatagram2, ProtoDatagramRaw+1)
	}

	if ProtoDatagram2+1 != ProtoDatagram3 {
		t.Errorf("ProtoDatagram3 (%d) should be ProtoDatagram2+1 (%d)",
			ProtoDatagram3, ProtoDatagram2+1)
	}
}
