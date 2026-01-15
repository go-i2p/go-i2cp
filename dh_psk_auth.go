// DH/PSK Authentication Implementation for I2CP Encrypted LeaseSets
//
// This file implements Diffie-Hellman and Pre-Shared Key authentication
// for accessing encrypted LeaseSets via I2CP BlindingInfoMessage.
//
// Per I2P Proposal 123 and 149, encrypted LeaseSets can require client
// authentication using either:
//   - DH (BLINDING_AUTH_SCHEME_DH = 0): X25519 Diffie-Hellman key exchange
//   - PSK (BLINDING_AUTH_SCHEME_PSK = 1): Pre-shared symmetric key
//
// The authentication produces a 32-byte decryption key that is sent in
// the BlindingInfoMessage to enable the router to decrypt the LeaseSet.
//
// Workflow for DH:
//  1. Client has X25519 private key (client identity)
//  2. Client knows server's X25519 public key (from blinded b32 address)
//  3. Client performs DH: sharedSecret = X25519(clientPrivKey, serverPubKey)
//  4. Client derives decryptionKey = HKDF(sharedSecret, salt, info)
//  5. Client sends decryptionKey in BlindingInfoMessage
//
// Workflow for PSK:
//  1. Client and server share a 32-byte pre-shared key
//  2. Client derives decryptionKey = HKDF(psk, salt, info)
//  3. Client sends decryptionKey in BlindingInfoMessage
//
// Since: I2CP 0.9.43+
// Reference: I2P Proposal 123 - Encrypted LeaseSet, Proposal 149 - Per-Client Auth
package go_i2cp

import (
	"crypto/sha256"
	"fmt"
	"io"

	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/hkdf"
)

// DHAuthenticator performs DH-based authentication for encrypted LeaseSets.
// It uses X25519 key exchange to derive a shared secret, then HKDF to
// derive the decryption key.
type DHAuthenticator struct {
	// ClientPrivateKey is the client's X25519 private key (32 bytes)
	ClientPrivateKey [32]byte

	// ServerPublicKey is the server's X25519 public key (32 bytes)
	// This is typically extracted from the blinded b32 address
	ServerPublicKey [32]byte

	// Salt is optional salt for HKDF derivation (can be nil)
	Salt []byte

	// Info is contextual info for HKDF (I2P uses "ELS2_L1K" for per-client auth)
	Info []byte
}

// PSKAuthenticator performs PSK-based authentication for encrypted LeaseSets.
// It uses HKDF to derive the decryption key from a pre-shared secret.
type PSKAuthenticator struct {
	// PreSharedKey is the 32-byte secret shared between client and server
	PreSharedKey [32]byte

	// Salt is optional salt for HKDF derivation (can be nil)
	Salt []byte

	// Info is contextual info for HKDF (I2P uses "ELS2_L1K" for per-client auth)
	Info []byte
}

// AuthResult holds the result of DH or PSK authentication.
type AuthResult struct {
	// DecryptionKey is the 32-byte key for BlindingInfoMessage
	DecryptionKey [32]byte

	// SharedSecret is the intermediate DH shared secret (DH only)
	// Empty for PSK authentication
	SharedSecret [32]byte

	// Scheme indicates which auth scheme was used (DH=0, PSK=1)
	Scheme uint8
}

// I2P context strings for HKDF derivation
const (
	// ELS2AuthInfo is the HKDF info string for Encrypted LeaseSet2 per-client auth
	// per I2P Proposal 149
	ELS2AuthInfo = "ELS2_L1K"

	// ELS2AuthSalt is the default salt for ELS2 auth derivation
	// (empty per specification - salt comes from blinding factor)
	ELS2AuthSalt = ""
)

// NewDHAuthenticator creates a new DH authenticator with the given keys.
// The clientPrivateKey is your X25519 private key.
// The serverPublicKey is extracted from the blinded destination.
func NewDHAuthenticator(clientPrivateKey, serverPublicKey [32]byte) *DHAuthenticator {
	return &DHAuthenticator{
		ClientPrivateKey: clientPrivateKey,
		ServerPublicKey:  serverPublicKey,
		Info:             []byte(ELS2AuthInfo),
	}
}

// NewPSKAuthenticator creates a new PSK authenticator with the given pre-shared key.
func NewPSKAuthenticator(preSharedKey [32]byte) *PSKAuthenticator {
	return &PSKAuthenticator{
		PreSharedKey: preSharedKey,
		Info:         []byte(ELS2AuthInfo),
	}
}

// WithSalt sets a custom salt for HKDF derivation.
func (d *DHAuthenticator) WithSalt(salt []byte) *DHAuthenticator {
	d.Salt = salt
	return d
}

// WithInfo sets custom info for HKDF derivation.
func (d *DHAuthenticator) WithInfo(info []byte) *DHAuthenticator {
	d.Info = info
	return d
}

// WithSalt sets a custom salt for HKDF derivation.
func (p *PSKAuthenticator) WithSalt(salt []byte) *PSKAuthenticator {
	p.Salt = salt
	return p
}

// WithInfo sets custom info for HKDF derivation.
func (p *PSKAuthenticator) WithInfo(info []byte) *PSKAuthenticator {
	p.Info = info
	return p
}

// Authenticate performs DH key exchange and derives the decryption key.
//
// The process:
//  1. Validate the server's public key
//  2. Perform X25519 DH: sharedSecret = X25519(clientPriv, serverPub)
//  3. Derive decryptionKey = HKDF-SHA256(sharedSecret, salt, info)
//
// Returns AuthResult containing the decryption key for BlindingInfoMessage.
func (d *DHAuthenticator) Authenticate() (*AuthResult, error) {
	// Validate server public key
	if !ValidateX25519PublicKey(d.ServerPublicKey) {
		return nil, fmt.Errorf("invalid server public key")
	}

	// Create key pair from client private key
	keyPair, err := X25519KeyPairFromPrivateKey(d.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Perform X25519 DH to get shared secret
	sharedSecret, err := keyPair.GenerateSharedSecret(d.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("DH key exchange failed: %w", err)
	}

	// Derive decryption key using HKDF
	decryptionKey, err := deriveAuthKey(sharedSecret[:], d.Salt, d.Info)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return &AuthResult{
		DecryptionKey: decryptionKey,
		SharedSecret:  sharedSecret,
		Scheme:        BLINDING_AUTH_SCHEME_DH,
	}, nil
}

// Authenticate derives the decryption key from the pre-shared key.
//
// The process:
//  1. Derive decryptionKey = HKDF-SHA256(psk, salt, info)
//
// Returns AuthResult containing the decryption key for BlindingInfoMessage.
func (p *PSKAuthenticator) Authenticate() (*AuthResult, error) {
	// Validate PSK is not all zeros
	var zero [32]byte
	if p.PreSharedKey == zero {
		return nil, fmt.Errorf("pre-shared key cannot be all zeros")
	}

	// Derive decryption key using HKDF
	decryptionKey, err := deriveAuthKey(p.PreSharedKey[:], p.Salt, p.Info)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return &AuthResult{
		DecryptionKey: decryptionKey,
		Scheme:        BLINDING_AUTH_SCHEME_PSK,
	}, nil
}

// deriveAuthKey derives a 32-byte authentication key using HKDF-SHA256.
func deriveAuthKey(ikm, salt, info []byte) ([32]byte, error) {
	var key [32]byte

	// Use HKDF-SHA256 to derive the key
	reader := hkdf.New(sha256.New, ikm, salt, info)

	_, err := io.ReadFull(reader, key[:])
	if err != nil {
		return key, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return key, nil
}

// X25519KeyPairFromPrivateKey creates an X25519KeyPair from just the private key.
// The public key is derived from the private key.
func X25519KeyPairFromPrivateKey(privateKey [32]byte) (*X25519KeyPair, error) {
	// Create the key pair
	keyPair := &X25519KeyPair{
		algorithmType: X25519,
	}

	// Copy private key
	keyPair.privateKey = make([]byte, 32)
	copy(keyPair.privateKey, privateKey[:])

	// Derive public key from private key using X25519 scalar base multiplication
	privKey := x25519.PrivateKey(privateKey[:])
	pubKeyInterface := privKey.Public()
	pubKey, ok := pubKeyInterface.(x25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to derive public key from private key")
	}

	keyPair.publicKey = make([]byte, 32)
	copy(keyPair.publicKey, pubKey)

	return keyPair, nil
}

// DerivePerClientAuthKey is a convenience function that derives the decryption key
// for per-client authentication. It handles both DH and PSK schemes.
//
// For DH: clientKey is your X25519 private key, serverKey is server's public key
// For PSK: clientKey is the pre-shared key, serverKey is ignored (can be zero)
//
// Returns the 32-byte decryption key to use in BlindingInfoMessage.
func DerivePerClientAuthKey(scheme uint8, clientKey, serverKey [32]byte) ([32]byte, error) {
	switch scheme {
	case BLINDING_AUTH_SCHEME_DH:
		auth := NewDHAuthenticator(clientKey, serverKey)
		result, err := auth.Authenticate()
		if err != nil {
			return [32]byte{}, err
		}
		return result.DecryptionKey, nil

	case BLINDING_AUTH_SCHEME_PSK:
		auth := NewPSKAuthenticator(clientKey)
		result, err := auth.Authenticate()
		if err != nil {
			return [32]byte{}, err
		}
		return result.DecryptionKey, nil

	default:
		return [32]byte{}, fmt.Errorf("unsupported auth scheme: %d", scheme)
	}
}

// DerivePerClientAuthKeyWithOptions derives the decryption key with custom HKDF parameters.
func DerivePerClientAuthKeyWithOptions(scheme uint8, clientKey, serverKey [32]byte, salt, info []byte) ([32]byte, error) {
	switch scheme {
	case BLINDING_AUTH_SCHEME_DH:
		auth := NewDHAuthenticator(clientKey, serverKey).WithSalt(salt).WithInfo(info)
		result, err := auth.Authenticate()
		if err != nil {
			return [32]byte{}, err
		}
		return result.DecryptionKey, nil

	case BLINDING_AUTH_SCHEME_PSK:
		auth := NewPSKAuthenticator(clientKey).WithSalt(salt).WithInfo(info)
		result, err := auth.Authenticate()
		if err != nil {
			return [32]byte{}, err
		}
		return result.DecryptionKey, nil

	default:
		return [32]byte{}, fmt.Errorf("unsupported auth scheme: %d", scheme)
	}
}

// Session methods for DH/PSK authentication

// AuthenticateForBlindedDestination performs per-client authentication for accessing
// a blinded destination and returns a configured PerClientAuthConfig.
//
// Parameters:
//   - scheme: BLINDING_AUTH_SCHEME_DH (0) or BLINDING_AUTH_SCHEME_PSK (1)
//   - clientKey: For DH: your X25519 private key. For PSK: the pre-shared key.
//   - serverPublicKey: For DH: server's X25519 public key. For PSK: ignored.
//
// Returns a PerClientAuthConfig ready to use with BlindingInfo.
func AuthenticateForBlindedDestination(scheme uint8, clientKey, serverPublicKey [32]byte) (*PerClientAuthConfig, error) {
	decryptionKey, err := DerivePerClientAuthKey(scheme, clientKey, serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	config := &PerClientAuthConfig{
		AuthScheme: scheme,
	}
	config.PrivateKey = decryptionKey // Store the derived key

	return config, nil
}

// CreateDHBlindingInfo creates a complete BlindingInfo with DH authentication
// for a hash-based endpoint.
//
// Parameters:
//   - destHash: 32-byte hash of the blinded destination
//   - clientPrivateKey: Your X25519 private key
//   - serverPublicKey: Server's X25519 public key (from b32 address)
//   - blindedSigType: Signature type used for blinding
//   - expiration: Expiration time (seconds since epoch)
//
// Returns BlindingInfo ready to send via Session.SendBlindingInfo().
func CreateDHBlindingInfo(
	destHash []byte,
	clientPrivateKey, serverPublicKey [32]byte,
	blindedSigType uint16,
	expiration uint32,
) (*BlindingInfo, error) {
	// Create blinding info
	info, err := NewBlindingInfoWithHash(destHash, blindedSigType, expiration)
	if err != nil {
		return nil, err
	}

	// Derive DH authentication key
	decryptionKey, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_DH, clientPrivateKey, serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("DH authentication failed: %w", err)
	}

	// Configure per-client auth
	info.PerClientAuth = true
	info.AuthScheme = BLINDING_AUTH_SCHEME_DH
	info.DecryptionKey = decryptionKey[:]

	return info, nil
}

// CreatePSKBlindingInfo creates a complete BlindingInfo with PSK authentication
// for a hash-based endpoint.
//
// Parameters:
//   - destHash: 32-byte hash of the blinded destination
//   - preSharedKey: The 32-byte pre-shared key
//   - blindedSigType: Signature type used for blinding
//   - expiration: Expiration time (seconds since epoch)
//
// Returns BlindingInfo ready to send via Session.SendBlindingInfo().
func CreatePSKBlindingInfo(
	destHash []byte,
	preSharedKey [32]byte,
	blindedSigType uint16,
	expiration uint32,
) (*BlindingInfo, error) {
	// Create blinding info
	info, err := NewBlindingInfoWithHash(destHash, blindedSigType, expiration)
	if err != nil {
		return nil, err
	}

	// Derive PSK authentication key
	decryptionKey, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_PSK, preSharedKey, [32]byte{})
	if err != nil {
		return nil, fmt.Errorf("PSK authentication failed: %w", err)
	}

	// Configure per-client auth
	info.PerClientAuth = true
	info.AuthScheme = BLINDING_AUTH_SCHEME_PSK
	info.DecryptionKey = decryptionKey[:]

	return info, nil
}

// CreateDHBlindingInfoForHostname creates BlindingInfo with DH auth for a hostname endpoint.
func CreateDHBlindingInfoForHostname(
	hostname string,
	clientPrivateKey, serverPublicKey [32]byte,
	blindedSigType uint16,
	expiration uint32,
) (*BlindingInfo, error) {
	info, err := NewBlindingInfoWithHostname(hostname, blindedSigType, expiration)
	if err != nil {
		return nil, err
	}

	decryptionKey, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_DH, clientPrivateKey, serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("DH authentication failed: %w", err)
	}

	info.PerClientAuth = true
	info.AuthScheme = BLINDING_AUTH_SCHEME_DH
	info.DecryptionKey = decryptionKey[:]

	return info, nil
}

// CreatePSKBlindingInfoForHostname creates BlindingInfo with PSK auth for a hostname endpoint.
func CreatePSKBlindingInfoForHostname(
	hostname string,
	preSharedKey [32]byte,
	blindedSigType uint16,
	expiration uint32,
) (*BlindingInfo, error) {
	info, err := NewBlindingInfoWithHostname(hostname, blindedSigType, expiration)
	if err != nil {
		return nil, err
	}

	decryptionKey, err := DerivePerClientAuthKey(BLINDING_AUTH_SCHEME_PSK, preSharedKey, [32]byte{})
	if err != nil {
		return nil, fmt.Errorf("PSK authentication failed: %w", err)
	}

	info.PerClientAuth = true
	info.AuthScheme = BLINDING_AUTH_SCHEME_PSK
	info.DecryptionKey = decryptionKey[:]

	return info, nil
}

// VerifyDHSharedSecret verifies that a DH shared secret can be derived from the given keys.
// This is useful for testing and debugging authentication issues.
func VerifyDHSharedSecret(clientPrivateKey, serverPublicKey [32]byte) (bool, error) {
	auth := NewDHAuthenticator(clientPrivateKey, serverPublicKey)
	result, err := auth.Authenticate()
	if err != nil {
		return false, err
	}

	// Check result is not zero
	var zero [32]byte
	if result.SharedSecret == zero {
		return false, fmt.Errorf("DH produced zero shared secret")
	}

	return true, nil
}

// VerifyPSKDerivation verifies that a PSK can be used to derive a decryption key.
func VerifyPSKDerivation(preSharedKey [32]byte) (bool, error) {
	auth := NewPSKAuthenticator(preSharedKey)
	result, err := auth.Authenticate()
	if err != nil {
		return false, err
	}

	// Check result is not zero
	var zero [32]byte
	if result.DecryptionKey == zero {
		return false, fmt.Errorf("PSK derivation produced zero key")
	}

	return true, nil
}
