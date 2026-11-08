// Blinding Crypto Implementation for I2CP
//
// This file implements blinding key derivation and cryptographic operations
// for accessing encrypted LeaseSets via I2CP BlindingInfoMessage.
//
// The implementation delegates to github.com/go-i2p/crypto/kdf and ed25519 packages
// which provide I2P-compliant blinding operations per Proposal 123.
//
// The blinding factor (alpha) is derived with kdf.DeriveBlindingFactorI2P, the
// spec-conformant implementation of net.i2p.crypto.Blinding.generateAlpha. Note
// that alpha is bound to the destination's signing public key, so the same secret
// and date produce a different alpha for every destination.
//
// Blinding workflow:
//  1. Service publishes encrypted LeaseSet with blinded destination
//  2. Client derives blinding factor from the destination's signing public key,
//     the shared secret, the signing type and the date
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

const (
	// blindingDateFormat is the calendar-date layout accepted and produced by
	// the blinding helpers. The crypto layer derives its own yyyyMMdd value from
	// the time.Time these helpers build, so the two always agree.
	blindingDateFormat = "2006-01-02"
)

// Signature type codes accepted as the blinding KDF's "sigtype-in" value. Blinding
// always yields a RedDSA key, so the sigtype-out is fixed by the crypto layer and
// only the original destination's signing type needs to be supplied here.
const (
	// BlindingSigTypeEd25519 (7) is the standard Ed25519 signing type, which is
	// what every I2CP destination supported by this package uses.
	BlindingSigTypeEd25519 uint16 = kdf.SigTypeEdDSASha512Ed25519
	// BlindingSigTypeRedDSA (11) is the RedDSA signing type of an already-blinded
	// destination, used when re-blinding a blinded key.
	BlindingSigTypeRedDSA uint16 = kdf.SigTypeRedDSASha512Ed25519
)

// BlindingKeyDerivation holds derived blinding keys for accessing encrypted LeaseSets.
// This structure contains all the cryptographic material needed to access a blinded destination.
type BlindingKeyDerivation struct {
	// Alpha is the 32-byte blinding factor derived from the destination's signing
	// public key, the secret, the signing type and the date
	Alpha [32]byte

	// BlindedPublicKey is the destination's public key after blinding
	BlindedPublicKey [32]byte

	// BlindedPrivateKey is the private key after blinding (if available)
	// This is only populated when calling DeriveBlindingKeysWithPrivate
	BlindedPrivateKey [64]byte

	// Date is the date used for derivation (for verification/debugging)
	Date string

	// SigType is the signing type used as the blinding KDF's sigtype-in value.
	// It is recorded so callers can re-derive or verify the same alpha.
	SigType uint16

	// HasPrivateKey indicates whether BlindedPrivateKey is populated
	HasPrivateKey bool
}

// DeriveBlindingFactor derives a blinding factor (alpha) for a destination.
// This creates a unique per-day blinding factor for EncryptedLeaseSet rotation.
//
// The derivation is the I2P-conformant one performed by kdf.DeriveBlindingFactorI2P:
//
//	salt  = SHA256("I2PGenerateAlpha" || signingPubKey || sigType || 0x000b)
//	ikm   = yyyyMMdd(GMT) || secret
//	alpha = HKDF-SHA256(salt, ikm, "i2pblinding1", 64) reduced mod L
//
// Because the destination's signing public key is mixed into the salt, alpha is
// bound to that destination: the same secret and date yield a different alpha for
// a different key.
//
// Parameters:
//   - signingPubKey: the destination's 32-byte signing public key
//   - secret: shared secret (UTF-8 text in I2P; may be empty)
//   - sigType: signing type of the destination, BlindingSigTypeEd25519 or BlindingSigTypeRedDSA
//   - date: date in "YYYY-MM-DD" format (use GetCurrentBlindingDate() for today)
//
// Returns:
//   - alpha: 32-byte canonical little-endian blinding factor
//   - error: If signingPubKey is not 32 bytes, sigType is unsupported, or the
//     date format is invalid
//
// Example:
//
//	alpha, err := DeriveBlindingFactor(signingPubKey, "my secret", BlindingSigTypeEd25519, "2025-11-24")
//	if err != nil {
//	    return err
//	}
func DeriveBlindingFactor(signingPubKey []byte, secret string, sigType uint16, date string) ([32]byte, error) {
	t, err := parseBlindingDate(date)
	if err != nil {
		return [32]byte{}, err
	}
	return kdf.DeriveBlindingFactorI2P(signingPubKey, secret, sigType, t)
}

// DeriveBlindingFactorForToday derives a blinding factor for the current UTC date.
// This is a convenience wrapper for DeriveBlindingFactor with today's date.
func DeriveBlindingFactorForToday(signingPubKey []byte, secret string, sigType uint16) ([32]byte, error) {
	return DeriveBlindingFactor(signingPubKey, secret, sigType, GetCurrentBlindingDate())
}

// DeriveBlindingFactorWithTimestamp derives a blinding factor from a Unix timestamp.
// The timestamp is converted to a UTC date, which is the rotation period used by
// the derivation.
func DeriveBlindingFactorWithTimestamp(signingPubKey []byte, secret string, sigType uint16, unixTimestamp int64) ([32]byte, error) {
	return kdf.DeriveBlindingFactorI2P(signingPubKey, secret, sigType, time.Unix(unixTimestamp, 0).UTC())
}

// parseBlindingDate converts a "YYYY-MM-DD" blinding date into the UTC midnight
// time.Time the crypto layer derives its yyyyMMdd value from. It rejects dates
// that are malformed or out of calendar range so that callers keep getting an
// error rather than silently blinding with the wrong period.
func parseBlindingDate(date string) (time.Time, error) {
	t, err := time.Parse(blindingDateFormat, date)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid blinding date %q: %w", date, err)
	}
	return t.UTC(), nil
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

// DeriveBlindingKeys derives the blinding factor for a destination and blinds its
// signing public key. This is a convenience function that combines
// DeriveBlindingFactor and BlindPublicKey.
//
// Parameters:
//   - publicKey: the destination's 32-byte signing public key, which both binds
//     the derivation and is blinded
//   - secret: shared secret (may be empty)
//   - sigType: signing type of the destination, BlindingSigTypeEd25519 or BlindingSigTypeRedDSA
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation containing alpha and blinded public key
//   - Error if derivation fails
func DeriveBlindingKeys(publicKey [32]byte, secret string, sigType uint16, date string) (*BlindingKeyDerivation, error) {
	if date == "" {
		date = GetCurrentBlindingDate()
	}

	alpha, err := DeriveBlindingFactor(publicKey[:], secret, sigType, date)
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
		SigType:          sigType,
		HasPrivateKey:    false,
	}, nil
}

// DeriveBlindingKeysWithPrivate derives blinding keys including the blinded private key.
// This is used by services that need to sign with blinded keys.
//
// Parameters:
//   - publicKey: the destination's 32-byte signing public key, which binds the derivation
//   - privateKey: 64-byte Ed25519 private key
//   - secret: shared secret (may be empty)
//   - sigType: signing type of the destination, BlindingSigTypeEd25519 or BlindingSigTypeRedDSA
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation containing alpha, blinded public and private keys
//   - Error if derivation fails
func DeriveBlindingKeysWithPrivate(publicKey [32]byte, privateKey [64]byte, secret string, sigType uint16, date string) (*BlindingKeyDerivation, error) {
	if date == "" {
		date = GetCurrentBlindingDate()
	}

	alpha, err := DeriveBlindingFactor(publicKey[:], secret, sigType, date)
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
		SigType:           sigType,
		HasPrivateKey:     true,
	}, nil
}

// GetCurrentBlindingDate returns today's date in UTC formatted for blinding (YYYY-MM-DD).
func GetCurrentBlindingDate() string {
	return FormatDateForBlinding(time.Now().UTC())
}

// FormatDateForBlinding formats a time.Time as YYYY-MM-DD for blinding factor derivation.
// The value is converted to UTC first, since the I2P blinding rotation period is the
// GMT day.
func FormatDateForBlinding(t time.Time) string {
	return t.UTC().Format(blindingDateFormat)
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
	return s.DeriveBlindingKeysForDestinationWithSecret("", date)
}

// DeriveBlindingKeysForDestinationWithSecret derives blinding keys for this
// session's destination using a shared secret.
//
// The secret is the optional UTF-8 string mixed into the blinding KDF input (the
// "password" a service chooses for its blinded LeaseSet). It is not key material:
// a client can only reproduce the blinded destination if it knows the same secret,
// so pass an empty string for an unauthenticated blinded destination.
//
// Parameters:
//   - secret: shared secret mixed into the derivation (may be empty)
//   - date: Date in "YYYY-MM-DD" format (or empty for today)
//
// Returns:
//   - BlindingKeyDerivation with alpha and blinded keys
//   - Error if session has no destination or derivation fails
func (s *Session) DeriveBlindingKeysForDestinationWithSecret(secret, date string) (*BlindingKeyDerivation, error) {
	if err := s.ensureInitialized(); err != nil {
		return nil, err
	}

	dest := s.Destination()
	if dest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Get the signing key pair; its public key binds the derivation while its
	// private key is blinded alongside it so the service can sign as the
	// blinded destination.
	keyPair, err := dest.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	privKey := keyPair.PrivateKey()
	pubKey := keyPair.PublicKey()

	var publicKey [32]byte
	copy(publicKey[:], pubKey[:])

	var privateKey [64]byte
	copy(privateKey[:], privKey[:])

	// I2CP destinations always use the Ed25519 (7) signing type.
	return DeriveBlindingKeysWithPrivate(publicKey, privateKey, secret, BlindingSigTypeEd25519, date)
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
