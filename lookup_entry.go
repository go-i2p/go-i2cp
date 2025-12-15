package go_i2cp

// LookupEntry represents a destination lookup request entry.
// Stores the original lookup parameters to support processing the HostReply response.
//
// I2CP Specification:
//   - Basic lookups (types 0-1): Only address/session tracked
//   - Service record lookups (types 2-4): Also tracks lookupType for parsing optional Mapping
//
// I2CP 0.9.66+ Proposal 167: Service Record Support
type LookupEntry struct {
	address    string            // Hostname or hash being looked up
	session    *Session          // Session that initiated the lookup
	lookupType uint8             // Lookup type (0-4) - determines if Mapping is present in HostReply
	options    map[string]string // Service record options from HostReply Mapping (types 2-4 only)
}
