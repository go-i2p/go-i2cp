// SignatureKeyPair struct definition
// Moved from: crypto.go
package go_i2cp

import (
	"crypto/dsa"
)

// SignatureKeyPair represents a DSA signature key pair
// This is a legacy struct maintained for backward compatibility.
// New code should use DSAKeyPair directly from dsa.go
type SignatureKeyPair struct {
	algorithmType uint32
	pub           dsa.PublicKey
	priv          dsa.PrivateKey
	dsaKeyPair    *DSAKeyPair // New wrapper from crypto package
}
