// Crypto struct definition
// Moved from: crypto.go
package go_i2cp

import (
	"crypto/dsa"
	"hash"
	"io"
)

// Crypto provides cryptographic operations for I2CP
// Note: Base32/Base64 encoding migrated to github.com/go-i2p/common
// SHA256 hashing now uses stdlib crypto/sha256 directly
type Crypto struct {
	rng    io.Reader
	params dsa.Parameters
	sh1    hash.Hash // SHA1 still used for legacy DSA operations
}
