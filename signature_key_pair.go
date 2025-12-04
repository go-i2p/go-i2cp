// SignatureKeyPair struct definition
// Moved from: crypto.go
package go_i2cp

import (
	"crypto/dsa"
)

// SignatureKeyPair represents a signature key pair (DSA or Ed25519)
// This is a legacy struct maintained for backward compatibility.
// New code should use DSAKeyPair or Ed25519KeyPair directly
type SignatureKeyPair struct {
	algorithmType  uint32
	pub            dsa.PublicKey
	priv           dsa.PrivateKey
	dsaKeyPair     *DSAKeyPair     // New DSA wrapper from crypto package
	ed25519KeyPair *Ed25519KeyPair // Ed25519 keypair for modern signatures
}
