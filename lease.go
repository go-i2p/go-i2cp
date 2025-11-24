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

// NewLeaseFromStream reads a Lease from an I2CP Stream
func NewLeaseFromStream(stream *Stream) (l *Lease, err error) {
	l = &Lease{}

	// Read tunnel gateway hash (32 bytes)
	n, err := stream.Read(l.tunnelGateway[:])
	if err != nil {
		return nil, err
	}
	if n != 32 {
		return nil, fmt.Errorf("failed to read complete tunnel gateway hash: got %d bytes, expected 32", n)
	}

	// Read tunnel ID (4 bytes)
	l.tunnelId, err = stream.ReadUint32()
	if err != nil {
		return nil, err
	}

	// Read end date (8 bytes - milliseconds since epoch)
	l.endDate, err = stream.ReadUint64()
	if err != nil {
		return nil, err
	}

	// Construct the common/lease from the read data
	// The lease format is: [32 bytes gateway][4 bytes tunnel ID][8 bytes end date]
	var leaseBytes [44]byte
	copy(leaseBytes[0:32], l.tunnelGateway[:])
	leaseBytes[32] = byte(l.tunnelId >> 24)
	leaseBytes[33] = byte(l.tunnelId >> 16)
	leaseBytes[34] = byte(l.tunnelId >> 8)
	leaseBytes[35] = byte(l.tunnelId)
	leaseBytes[36] = byte(l.endDate >> 56)
	leaseBytes[37] = byte(l.endDate >> 48)
	leaseBytes[38] = byte(l.endDate >> 40)
	leaseBytes[39] = byte(l.endDate >> 32)
	leaseBytes[40] = byte(l.endDate >> 24)
	leaseBytes[41] = byte(l.endDate >> 16)
	leaseBytes[42] = byte(l.endDate >> 8)
	leaseBytes[43] = byte(l.endDate)

	commonLease, _, err := lease.ReadLease(leaseBytes[:])
	if err != nil {
		return nil, err
	}
	l.lease = &commonLease

	return
}

// WriteToMessage writes the Lease to an I2CP Stream
func (l *Lease) WriteToMessage(stream *Stream) (err error) {
	if l.lease != nil {
		// Use the common/lease's byte representation
		// Lease is a [44]byte array type, so we can write it directly
		n, err := stream.Write(l.lease[:])
		if err != nil {
			return err
		}
		if n != 44 {
			return fmt.Errorf("failed to write complete lease: wrote %d bytes, expected 44", n)
		}
		return nil
	}

	// Fallback to legacy fields if common lease not initialized
	_, err = stream.Write(l.tunnelGateway[:])
	if err != nil {
		return err
	}
	err = stream.WriteUint32(l.tunnelId)
	if err != nil {
		return err
	}
	err = stream.WriteUint64(l.endDate)
	return
}
