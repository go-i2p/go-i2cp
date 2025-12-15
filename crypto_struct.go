// Crypto struct definition
//
// This file defines the Crypto type which serves as an I2CP protocol adapter
// for coordinating cryptographic operations in I2CP message handling.
//
// IMPORTANT: This is NOT a cryptographic implementation. It is protocol glue code.
//
// Purpose:
// The Crypto type coordinates various cryptographic operations required by the
// I2CP protocol, including:
//   - Random number generation for protocol operations
//   - Ed25519 signature operations
//   - X25519 key exchange
//   - ChaCha20-Poly1305 AEAD encryption
//
// Design Philosophy:
// This struct exists to maintain state needed for I2CP protocol operations,
// NOT to implement cryptography. All actual cryptographic work is delegated to:
//   - Standard library (crypto/rand)
//   - github.com/go-i2p/crypto for modern operations (Ed25519, X25519, ChaCha20-Poly1305)
//
// Migration Status:
//  Base32/Base64 methods removed (migrated to github.com/go-i2p/common)
//  SHA256 operations migrated to direct stdlib usage (crypto/sha256)
//  DSA support removed (legacy algorithm deprecated)
//
// Related Files:
//   - crypto.go: I2CP-specific signing/verification functions
//   - ed25519.go: Ed25519 wrapper delegating to github.com/go-i2p/crypto/ed25519
//   - x25519.go: X25519 wrapper delegating to github.com/go-i2p/crypto/curve25519
//   - chacha20poly1305.go: AEAD wrapper delegating to github.com/go-i2p/crypto/chacha20poly1305

package go_i2cp

import (
	"io"
)

// Crypto provides cryptographic operations for I2CP protocol message handling.
//
// This type is an I2CP protocol adapter that coordinates cryptographic operations
// for I2CP messages. It maintains state required for protocol operations but
// delegates all actual cryptographic work to specialized packages.
//
// Fields:
//   - rng: Random number generator (crypto/rand.Reader) for protocol operations
//
// Usage Example:
//
//	crypto := NewCrypto()
//	keyPair, err := crypto.Ed25519SignatureKeygen()
//
// See Also:
//   - NewCrypto(): Constructor function in crypto.go
//   - Ed25519SignatureKeygen(): Ed25519 key generation
//   - X25519KeyExchangeKeygen(): X25519 key exchange
type Crypto struct {
	rng io.Reader // Random number generator (crypto/rand.Reader)
}
