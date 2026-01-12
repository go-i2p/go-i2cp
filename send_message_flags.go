package go_i2cp

import "fmt"

// BuildSendMessageFlags constructs the flags field for SendMessageExpiresMessage
// per I2CP specification § SendMessageExpiresMessage (I2CP 0.8.4+)
//
// IMPORTANT: Tag threshold and tag count are OBSOLETE parameters.
// They are only relevant for ElGamal encryption (deprecated). Modern I2P uses
// ECIES-Ratchet encryption which does not use session tags. These parameters
// are kept for backward compatibility but have no effect with ECIES-Ratchet.
//
// Modern usage should use:
//
//	flags := BuildSendMessageFlags(0, 0)  // Use defaults (tag params ignored)
//	flags |= SEND_MSG_FLAG_NO_LEASESET    // Optionally prevent LeaseSet bundling
//
// Parameters:
//   - tagThreshold: Low tag threshold (0-15), ElGamal only. Use 0 for default.
//   - tagCount: Tags to send (0-15), ElGamal only. Use 0 for default.
//
// Returns the flags value suitable for use with Session.SendMessageExpires()
func BuildSendMessageFlags(tagThreshold, tagCount uint8) uint16 {
	// Validate inputs (4-bit values: 0-15)
	if tagThreshold > 15 {
		tagThreshold = 0 // Clamp to default
	}
	if tagCount > 15 {
		tagCount = 0 // Clamp to default
	}

	// Build flags: bits 7-4 = tagThreshold, bits 3-0 = tagCount
	flags := (uint16(tagThreshold) << 4) | uint16(tagCount)
	return flags
}

// ParseSendMessageFlags extracts flag components from a SendMessageExpires flags field
// per I2CP specification § SendMessageExpiresMessage (I2CP 0.8.4+)
//
// Returns:
//   - noLeaseSet: true if LeaseSet bundling is disabled (bit 8)
//   - tagThreshold: ElGamal tag threshold value (bits 7-4) - OBSOLETE
//   - tagCount: ElGamal tags to send value (bits 3-0) - OBSOLETE
//   - err: error if reserved or deprecated bits are set
func ParseSendMessageFlags(flags uint16) (noLeaseSet bool, tagThreshold, tagCount uint8, err error) {
	// Check reserved bits (15-11)
	if flags&SEND_MSG_FLAGS_RESERVED_MASK != 0 {
		return false, 0, 0, fmt.Errorf("invalid flags: reserved bits set (0x%04x)", flags)
	}

	// Check deprecated reliability override bits (10-9)
	if flags&SEND_MSG_FLAGS_RELIABILITY_MASK != 0 {
		return false, 0, 0, fmt.Errorf("deprecated reliability override flags (bits 10-9) no longer supported")
	}

	// Extract flag components
	noLeaseSet = (flags & SEND_MSG_FLAG_NO_LEASESET) != 0
	tagThreshold = uint8((flags & SEND_MSG_FLAGS_TAG_THRESHOLD) >> 4)
	tagCount = uint8(flags & SEND_MSG_FLAGS_TAG_COUNT)

	return noLeaseSet, tagThreshold, tagCount, nil
}

// ValidateSendMessageFlags validates SendMessageExpires flags per I2CP specification
// per I2CP specification § SendMessageExpiresMessage (I2CP 0.8.4+)
//
// This function checks that:
//   - Reserved bits (15-11) are not set
//   - Deprecated reliability override bits (10-9) are not set
//   - Tag threshold and count are in valid range (0-15)
//
// Returns an error if validation fails.
func ValidateSendMessageFlags(flags uint16) error {
	_, _, _, err := ParseSendMessageFlags(flags)
	return err
}
