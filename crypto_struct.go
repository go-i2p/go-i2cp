// Crypto struct definition
// Moved from: crypto.go
package go_i2cp

import (
	"crypto/dsa"
	"encoding/base32"
	"encoding/base64"
	"hash"
	"io"
)

// Crypto provides cryptographic operations for I2CP
type Crypto struct {
	b64    *base64.Encoding
	b32    *base32.Encoding
	rng    io.Reader
	params dsa.Parameters
	sh1    hash.Hash
	sh256  hash.Hash
}
