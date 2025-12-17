package go_i2cp

import (
	"fmt"

	"github.com/go-i2p/common/lease"
)

// Lease wraps common/lease.Lease to provide I2CP-specific Stream integration
// while delegating core lease functionality to the common package.
type Lease struct {
	lease *lease.Lease
	// Legacy fields preserved for backward compatibility
	tunnelGateway [32]byte // sha256 of the RouterIdentity of the tunnel gateway
	tunnelId      uint32
	endDate       uint64
}

// readLeaseFields reads the tunnel gateway, tunnel ID, and end date from stream.
// Returns the data and any error encountered.
func readLeaseFields(stream *Stream) ([32]byte, uint32, uint64, error) {
	var tunnelGateway [32]byte

	n, err := stream.Read(tunnelGateway[:])
	if err != nil {
		return tunnelGateway, 0, 0, err
	}
	if n != 32 {
		return tunnelGateway, 0, 0, fmt.Errorf("failed to read complete tunnel gateway hash: got %d bytes, expected 32", n)
	}

	tunnelId, err := stream.ReadUint32()
	if err != nil {
		return tunnelGateway, 0, 0, err
	}

	endDate, err := stream.ReadUint64()
	if err != nil {
		return tunnelGateway, 0, 0, err
	}

	return tunnelGateway, tunnelId, endDate, nil
}

// constructLeaseBytes creates a 44-byte lease array from lease components.
func constructLeaseBytes(tunnelGateway [32]byte, tunnelId uint32, endDate uint64) [44]byte {
	var leaseBytes [44]byte
	copy(leaseBytes[0:32], tunnelGateway[:])
	leaseBytes[32] = byte(tunnelId >> 24)
	leaseBytes[33] = byte(tunnelId >> 16)
	leaseBytes[34] = byte(tunnelId >> 8)
	leaseBytes[35] = byte(tunnelId)
	leaseBytes[36] = byte(endDate >> 56)
	leaseBytes[37] = byte(endDate >> 48)
	leaseBytes[38] = byte(endDate >> 40)
	leaseBytes[39] = byte(endDate >> 32)
	leaseBytes[40] = byte(endDate >> 24)
	leaseBytes[41] = byte(endDate >> 16)
	leaseBytes[42] = byte(endDate >> 8)
	leaseBytes[43] = byte(endDate)
	return leaseBytes
}

// NewLeaseFromStream reads a Lease from an I2CP Stream
func NewLeaseFromStream(stream *Stream) (l *Lease, err error) {
	l = &Lease{}

	tunnelGateway, tunnelId, endDate, err := readLeaseFields(stream)
	if err != nil {
		return nil, err
	}

	l.tunnelGateway = tunnelGateway
	l.tunnelId = tunnelId
	l.endDate = endDate

	leaseBytes := constructLeaseBytes(tunnelGateway, tunnelId, endDate)

	commonLease, _, err := lease.ReadLease(leaseBytes[:])
	if err != nil {
		return nil, err
	}
	l.lease = &commonLease

	return
}

// writeCommonLease writes a common/lease byte representation to the stream.
// Returns error if write fails or incomplete.
func (l *Lease) writeCommonLease(stream *Stream) error {
	n, err := stream.Write(l.lease[:])
	if err != nil {
		return err
	}
	if n != 44 {
		return fmt.Errorf("failed to write complete lease: wrote %d bytes, expected 44", n)
	}
	return nil
}

// writeLegacyLeaseFields writes legacy lease fields to the stream.
// Used when common lease is not initialized.
func (l *Lease) writeLegacyLeaseFields(stream *Stream) error {
	if _, err := stream.Write(l.tunnelGateway[:]); err != nil {
		return err
	}
	if err := stream.WriteUint32(l.tunnelId); err != nil {
		return err
	}
	return stream.WriteUint64(l.endDate)
}

// WriteToMessage writes the Lease to an I2CP Stream (44-byte format)
func (l *Lease) WriteToMessage(stream *Stream) (err error) {
	if l.lease != nil {
		return l.writeCommonLease(stream)
	}
	return l.writeLegacyLeaseFields(stream)
}

// WriteToLeaseSet2 writes the Lease in Lease2 format (40 bytes) for LeaseSet2.
// Lease2 format: gateway (32 bytes) + tunnel_id (4 bytes) + end_date (4 bytes, seconds)
// This differs from the I2CP Lease format which uses 8-byte millisecond timestamps.
func (l *Lease) WriteToLeaseSet2(stream *Stream) error {
	// Write tunnel gateway (32 bytes)
	if _, err := stream.Write(l.tunnelGateway[:]); err != nil {
		return err
	}

	// Write tunnel ID (4 bytes)
	if err := stream.WriteUint32(l.tunnelId); err != nil {
		return err
	}

	// Write end date as 4 bytes (seconds since epoch, not milliseconds)
	// Convert from milliseconds to seconds
	endDateSeconds := uint32(l.endDate / 1000)
	return stream.WriteUint32(endDateSeconds)
}
