// Blinding Crypto Implementation for I2CP
//
// This file implements blinding key derivation and cryptographic operations
// for accessing encrypted LeaseSets via I2CP BlindingInfoMessage.
//
// The implementation delegates to github.com/go-i2p/crypto/kdf and ed25519 packages
// which provide I2P-compliant blinding operations per Proposal 123.
//
// Blinding workflow:
//  1. Service publishes encrypted LeaseSet with blinded destination
//  2. Client derives blinding factor from secret + date
//  3. Client blinds destination's public key with the factor
//  4. Router uses blinded key to locate encrypted LeaseSet
//  5. Client decrypts LeaseSet using derived keys
//
// Since: I2CP 0.9.43+
// Reference: I2P Proposal 123 - Encrypted LeaseSet
package go_i2cp

import (
	"fmt"
	"time"

	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/kdf"
)

// BlindingKeyDerivation holds derived blinding keys for accessing encrypted LeaseSets.
// This structure contains all the cryptographic material needed to access a blinded destination.
type BlindingKeyDerivation struct {
	// Alpha is the 32-byte blinding factor derived from secret + date
	Alpha [32]byte

	// BlindedPublicKey is the destination's public key after blinding
	BlindedPublicKey [32]byte

	// BlindedPrivateKey is the private key after blinding (if available)
	// This is only populated when calling DeriveBlindingKeysWithPrivate
	BlindedPrivateKey [64]byte

	// Date is the date used for derivation (for verification/debugging)
	Date string

	// HasPrivateKey indicates whether BlindedPrivateKey is populated
	HasPrivateKey bool
}

// DeriveBlindingFactor derives a blinding factor (alpha) from a secret and date.
// This creates a unique per-day blinding factor for EncryptedLeaseSet rotation.
//
// The derivation uses HKDF-SHA256 with the date as salt, producing a 32-byte
// canonical Ed25519 scalar suitable for key blinding.
//
// Parameters:
//   - secret: Secret key material (at least 32 bytes, typically from private key seed)
//   - date: Date in "YYYY-MM-DD" format (use kdf.GetCurrentBlindingDate() for today)
//
// Returns:
//   - alpha: 32-byte blinding factor
//   - error: If secret is too short or date format is invalid
//
// Example:
//
//	secret := privateKey.Seed()
//	alpha, err := DeriveBlindingFactor(secret, "2025-11-24")
//	if err != nil {
//	    return err
//	}
func DeriveBlindingFactor(secret []byte, date string) ([32]byte, error) {
	return kdf.DeriveBlindingFactor(secret, date)
}

// DeriveBlindingFactorForToday derives a blinding factor for the current UTC date.
// This is a convenience wrapper for DeriveBlindingFactor with today's date.
func DeriveBlindingFactorForToday(secret []byte) ([32]byte, error) {
	return kdf.DeriveBlindingFactor(secret, kdf.GetCurrentBlindingDate())
}

// DeriveBlindingFactorWithTimestamp derives a blinding factor from a Unix timestamp.
// The timestamp is converted to a UTC date in YYYY-MM-DD format.
func DeriveBlindingFactorWithTimestamp(secret []byte, unixTimestamp int64) ([32]byte, error) {
	return kdf.DeriveBlindingFactorWithTimestamp(secret, unixTimestamp)
}

// BlindPublicKey blinds an Ed25519 public key using a blinding factor.
// The blinding operation: P' = P + [alpha]B
//
// This is used to create unlinkable blinded destinations for EncryptedLeaseSet.
// The same alpha applied to different public keys produces different blinded keys,
// ensuring destinations cannot be correlated.
//
// Parameters:
//   - publicKey: 32-byte Ed25519 public key to blind
//   - alpha: 32-byte blinding factor from DeriveBlindingFactor
//
// Returns:
//   - Blinded 32-byte public key
//   - Error if public key is invalid or alpha is invalid
func BlindPublicKey(publicKey, alpha [32]byte) ([32]byte, error) {
	return cryptoed25519.BlindPublicKey(publicKey, alpha)
}

// BlindPrivateKey blinds an Ed25519 private key using a blinding factor.
// The blinding operation: d' = d + alpha (mod L)
//
// The blinded private key can sign on behalf of the blinded public key.
// Both the public and private key must be blinded with the same alpha.
//
// Parameters:
//   - privateKey: 64-byte Ed25519 private key to blind
//   - alpha: 32-byte blinding factor from DeriveBlindingFactor
//
// Returns:
//   - Blinded 64-byte value [scalar][pubkey]
//   - Error if private key is invalid or alpha is invalid
func BlindPrivateKey(privateKey [64]byte, alpha [32]byte) ([64]byte, error) {
	return cryptoed25519.BlindPrivateKey(privateKey, alpha)
}

// UnblindPublicKey reverses the blinding operation on a public key.
// The operation: P = P' - [alpha]B
//
// This is used for verification: given a blinded key P' and alpha, recover P.
//
// Parameters:
//   - blindedPublicKey: 32-byte blinded Ed25519 public key
//   - alpha: 32-byte blinding factor used to create the blinded key
//
// Returns:
//   - Original unblinded 32-byte public key
//   - Error if inputs are invalid
func UnblindPublicKey(blindedPublicKey, alpha [32]byte) ([32]byte, error) {
	return cryptoed25519.UnblindPublicKey(blindedPublicKey, alpha)
}

// DeriveBlindingKeys derives blinding factor and blinds a public key.
// This is a convenience function that combines DeriveBlindingFactor and BlindPublicKey.
//
// Parameters:
//   - secret: Secret key material (at least 32 bytes)
//   - publicKey: 32-byte Ed25519 public key to blind
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation containing alpha and blinded public key
//   - Error if derivation fails
func DeriveBlindingKeys(secret []byte, publicKey [32]byte, date string) (*BlindingKeyDerivation, error) {
	if date == "" {
		date = kdf.GetCurrentBlindingDate()
	}

	alpha, err := kdf.DeriveBlindingFactor(secret, date)
	if err != nil {
		return nil, fmt.Errorf("failed to derive blinding factor: %w", err)
	}

	blindedPubKey, err := cryptoed25519.BlindPublicKey(publicKey, alpha)
	if err != nil {
		return nil, fmt.Errorf("failed to blind public key: %w", err)
	}

	return &BlindingKeyDerivation{
		Alpha:            alpha,
		BlindedPublicKey: blindedPubKey,
		Date:             date,
		HasPrivateKey:    false,
	}, nil
}

// DeriveBlindingKeysWithPrivate derives blinding keys including the blinded private key.
// This is used by services that need to sign with blinded keys.
//
// Parameters:
//   - secret: Secret key material (at least 32 bytes)
//   - publicKey: 32-byte Ed25519 public key
//   - privateKey: 64-byte Ed25519 private key
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation containing alpha, blinded public and private keys
//   - Error if derivation fails
func DeriveBlindingKeysWithPrivate(secret []byte, publicKey [32]byte, privateKey [64]byte, date string) (*BlindingKeyDerivation, error) {
	if date == "" {
		date = kdf.GetCurrentBlindingDate()
	}

	alpha, err := kdf.DeriveBlindingFactor(secret, date)
	if err != nil {
		return nil, fmt.Errorf("failed to derive blinding factor: %w", err)
	}

	blindedPubKey, err := cryptoed25519.BlindPublicKey(publicKey, alpha)
	if err != nil {
		return nil, fmt.Errorf("failed to blind public key: %w", err)
	}

	blindedPrivKey, err := cryptoed25519.BlindPrivateKey(privateKey, alpha)
	if err != nil {
		return nil, fmt.Errorf("failed to blind private key: %w", err)
	}

	return &BlindingKeyDerivation{
		Alpha:             alpha,
		BlindedPublicKey:  blindedPubKey,
		BlindedPrivateKey: blindedPrivKey,
		Date:              date,
		HasPrivateKey:     true,
	}, nil
}

// GetCurrentBlindingDate returns today's date in UTC formatted for blinding (YYYY-MM-DD).
func GetCurrentBlindingDate() string {
	return kdf.GetCurrentBlindingDate()
}

// FormatDateForBlinding formats a time.Time as YYYY-MM-DD for blinding factor derivation.
func FormatDateForBlinding(t time.Time) string {
	return kdf.FormatDateForBlinding(t)
}

// Session methods for blinding key derivation

// DeriveBlindingKeysForDestination derives blinding keys for this session's destination.
// This is used by services to create blinded versions of their destination for publication.
//
// The secret is derived from the session's signing key pair seed.
//
// Parameters:
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation with alpha and blinded keys
//   - Error if session has no destination or derivation fails
func (s *Session) DeriveBlindingKeysForDestination(date string) (*BlindingKeyDerivation, error) {
	if err := s.ensureInitialized(); err != nil {
		return nil, err
	}

	dest := s.Destination()
	if dest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Get the signing key pair for secret derivation
	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	// Get the keys via accessor methods
	privKey := keyPair.PrivateKey()
	pubKey := keyPair.PublicKey()

	// Use the private key seed as the secret for blinding factor derivation
	secret := privKey[:32] // Ed25519 seed is first 32 bytes

	// Get the public key
	var publicKey [32]byte
	copy(publicKey[:], pubKey[:])

	// Derive blinding keys with private key for signing
	var privateKey [64]byte
	copy(privateKey[:], privKey[:])

	return DeriveBlindingKeysWithPrivate(secret, publicKey, privateKey, date)
}

// StoreBlindingInfo stores received blinding parameters in the session.
// This is called when the router sends BlindingInfoMessage to provide
// parameters for accessing an encrypted LeaseSet.
//
// The stored parameters can be retrieved with BlindingParams() and used
// for key derivation with DeriveBlindingFactor.
func (s *Session) StoreBlindingInfo(scheme, flags uint16, params []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blindingScheme = scheme
	s.blindingFlags = flags
	if params != nil {
		s.blindingParams = make([]byte, len(params))
		copy(s.blindingParams, params)
	} else {
		s.blindingParams = nil
	}

	Debug("Stored blinding info: scheme=%d, flags=%d, params=%d bytes",
		scheme, flags, len(params))
}

// VerifyBlindedDestination verifies that a blinded public key matches
// the expected unblinded public key when the same alpha is applied.
//
// This is useful for verifying that a router-provided blinded destination
// corresponds to a known destination.
//
// Parameters:
//   - blindedPubKey: The blinded public key to verify
//   - expectedPubKey: The expected unblinded public key
//   - alpha: The blinding factor that was used
//
// Returns:
//   - true if the blinded key corresponds to the expected key
//   - false otherwise
func VerifyBlindedDestination(blindedPubKey, expectedPubKey, alpha [32]byte) bool {
	unblinded, err := UnblindPublicKey(blindedPubKey, alpha)
	if err != nil {
		return false
	}
	return unblinded == expectedPubKey
}
