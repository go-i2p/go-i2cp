// SignatureKeyPair struct definition
// Moved from: crypto.go
package go_i2cp

import (
	"crypto/dsa"
)

// SignatureKeyPair represents a DSA signature key pair
type SignatureKeyPair struct {
	algorithmType uint32
	pub           dsa.PublicKey
	priv          dsa.PrivateKey
}
