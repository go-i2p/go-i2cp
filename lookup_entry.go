package go_i2cp

// LookupEntry represents a destination lookup request entry.
// Moved from: client.go
type LookupEntry struct {
	address string
	session *Session
}
