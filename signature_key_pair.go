// SignatureKeyPair struct definition
// Moved from: crypto.go
package go_i2cp

// SignatureKeyPair represents an Ed25519 signature key pair.
// This struct is maintained for backward compatibility.
// New code should use Ed25519KeyPair directly.
type SignatureKeyPair struct {
	algorithmType  uint32
	ed25519KeyPair *Ed25519KeyPair // Ed25519 keypair for modern signatures
}
