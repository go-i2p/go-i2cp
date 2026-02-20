package go_i2cp

import (
	"encoding/binary"
	"fmt"

	"github.com/go-i2p/common/lease"
)

// Lease is a type alias for lease.Lease from the common package.
// All lease operations (TunnelGateway, TunnelID, Time, Date, Bytes) are provided
// by the common package. I2CP-specific stream helpers are defined as package functions.
type Lease = lease.Lease

// NewLeaseFromStream reads a Lease from an I2CP Stream.
// Uses common/lease.ReadLease for parsing after reading the 44-byte lease data.
func NewLeaseFromStream(stream *Stream) (*Lease, error) {
	var leaseBytes [44]byte

	// Read tunnel gateway (32 bytes)
	n, err := stream.Read(leaseBytes[:32])
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, fmt.Errorf("failed to read complete tunnel gateway hash: got %d bytes, expected 32", n)
	}

	// Read tunnel ID (4 bytes)
	tunnelId, err := stream.ReadUint32()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(leaseBytes[32:36], tunnelId)

	// Read end date (8 bytes)
	endDate, err := stream.ReadUint64()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(leaseBytes[36:44], endDate)

	commonLease, _, err := lease.ReadLease(leaseBytes[:])
	if err != nil {
		return nil, err
	}
	return &commonLease, nil
}

// WriteLeaseToMessage writes a Lease to an I2CP Stream (44-byte format).
func WriteLeaseToMessage(l *Lease, stream *Stream) error {
	n, err := stream.Write(l[:])
	if err != nil {
		return err
	}
	if n != 44 {
		return fmt.Errorf("failed to write complete lease: wrote %d bytes, expected 44", n)
	}
	return nil
}

// WriteLeaseToLeaseSet2 writes a Lease in Lease2 format (40 bytes) for LeaseSet2.
// Lease2 format: gateway (32 bytes) + tunnel_id (4 bytes) + end_date (4 bytes, seconds)
// This differs from the I2CP Lease format which uses 8-byte millisecond timestamps.
func WriteLeaseToLeaseSet2(l *Lease, stream *Stream) error {
	// Write tunnel gateway (32 bytes)
	if _, err := stream.Write(l[:32]); err != nil {
		return err
	}

	// Write tunnel ID (4 bytes)
	if _, err := stream.Write(l[32:36]); err != nil {
		return err
	}

	// Write end date as 4 bytes (seconds since epoch, not milliseconds)
	// Read the 8-byte millisecond timestamp and convert to seconds
	endDateMs := binary.BigEndian.Uint64(l[36:44])
	endDateSeconds := uint32(endDateMs / 1000)
	return stream.WriteUint32(endDateSeconds)
}
