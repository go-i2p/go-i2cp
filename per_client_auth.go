package go_i2cp

import (
	"crypto/rand"
	"fmt"
)

// Per-Client Authentication Support for Encrypted LeaseSets
//
// This file implements per-client authentication as defined in I2CP specification
// for BlindingInfoMessage (type 42). Per-client authentication allows specific clients
// to access encrypted LeaseSets using either Diffie-Hellman key exchange or
// Pre-Shared Keys.
//
// Per-client authentication is NOT an I2CP session authentication method.
// It is a mechanism for accessing encrypted LeaseSets that require client-specific
// credentials beyond just a lookup password.
//
// Supported authentication schemes:
//   - DH (BLINDING_AUTH_SCHEME_DH = 0): Client uses X25519 DH key derivation
//   - PSK (BLINDING_AUTH_SCHEME_PSK = 1): Client uses pre-shared key
//
// Workflow:
//  1. Client creates BlindingInfo with per-client auth enabled
//  2. Client provides 32-byte X25519 private key (DecryptionKey)
//  3. Client sends BlindingInfoMessage to router
//  4. Router uses the key to decrypt the encrypted LeaseSet
//  5. Router does NOT reply to this message
//
// Reference: I2CP spec § BlindingInfoMessage, Proposals 123 and 149
// Since: I2CP 0.9.43+

// PerClientAuthConfig holds configuration for per-client authentication
// when accessing encrypted LeaseSets via BlindingInfoMessage.
type PerClientAuthConfig struct {
	// AuthScheme specifies the authentication scheme to use.
	// Use BLINDING_AUTH_SCHEME_DH (0) for Diffie-Hellman or
	// BLINDING_AUTH_SCHEME_PSK (1) for Pre-Shared Key.
	AuthScheme uint8

	// PrivateKey is the 32-byte ECIES_X25519 private key (little-endian).
	// This key is used to derive the shared secret for decrypting the LeaseSet.
	// For DH scheme: This is your X25519 private key for DH exchange.
	// For PSK scheme: This is the pre-shared secret key.
	PrivateKey [32]byte

	// LookupPassword is an optional password for encrypted LeaseSet lookup.
	// Some destinations require both per-client auth AND a lookup password.
	LookupPassword string
}

// NewPerClientAuthDH creates a new per-client authentication config using
// Diffie-Hellman key exchange. The provided private key must be 32 bytes.
//
// Usage:
//
//	privKey := generateX25519PrivateKey() // Your X25519 private key
//	authConfig, err := NewPerClientAuthDH(privKey)
//	if err != nil {
//	    return err
//	}
//	blindingInfo := NewBlindingInfoWithAuth(endpoint, authConfig)
//	session.SendBlindingInfo(blindingInfo)
func NewPerClientAuthDH(privateKey []byte) (*PerClientAuthConfig, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("DH private key must be exactly 32 bytes, got %d", len(privateKey))
	}

	config := &PerClientAuthConfig{
		AuthScheme: BLINDING_AUTH_SCHEME_DH,
	}
	copy(config.PrivateKey[:], privateKey)
	return config, nil
}

// NewPerClientAuthPSK creates a new per-client authentication config using
// Pre-Shared Key. The provided key must be 32 bytes.
//
// Usage:
//
//	psk := getPresharedKey() // The pre-shared key from the destination owner
//	authConfig, err := NewPerClientAuthPSK(psk)
//	if err != nil {
//	    return err
//	}
//	blindingInfo := NewBlindingInfoWithAuth(endpoint, authConfig)
//	session.SendBlindingInfo(blindingInfo)
func NewPerClientAuthPSK(presharedKey []byte) (*PerClientAuthConfig, error) {
	if len(presharedKey) != 32 {
		return nil, fmt.Errorf("PSK must be exactly 32 bytes, got %d", len(presharedKey))
	}

	config := &PerClientAuthConfig{
		AuthScheme: BLINDING_AUTH_SCHEME_PSK,
	}
	copy(config.PrivateKey[:], presharedKey)
	return config, nil
}

// GenerateRandomPrivateKey generates a random 32-byte private key for DH authentication.
// This can be used to create a new client identity for accessing encrypted LeaseSets.
func GenerateRandomPrivateKey() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return key, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// WithLookupPassword sets the optional lookup password for the auth config.
// Some destinations require both per-client auth AND a lookup password.
func (c *PerClientAuthConfig) WithLookupPassword(password string) *PerClientAuthConfig {
	c.LookupPassword = password
	return c
}

// NewBlindingInfoWithHash creates BlindingInfo for a destination identified by its hash.
// The hash must be 32 bytes (SHA-256 of the destination).
func NewBlindingInfoWithHash(hash []byte, blindedSigType uint16, expiration uint32) (*BlindingInfo, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(hash))
	}

	info := &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_HASH,
		Endpoint:       make([]byte, 32),
		BlindedSigType: blindedSigType,
		Expiration:     expiration,
	}
	copy(info.Endpoint, hash)
	return info, nil
}

// NewBlindingInfoWithHostname creates BlindingInfo for a destination identified by hostname.
// The hostname must be non-empty and at most 255 bytes.
func NewBlindingInfoWithHostname(hostname string, blindedSigType uint16, expiration uint32) (*BlindingInfo, error) {
	if len(hostname) == 0 {
		return nil, fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 255 {
		return nil, fmt.Errorf("hostname too long: %d bytes (max 255)", len(hostname))
	}

	return &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_HOSTNAME,
		Endpoint:       []byte(hostname),
		BlindedSigType: blindedSigType,
		Expiration:     expiration,
	}, nil
}

// NewBlindingInfoWithDestination creates BlindingInfo for a full destination.
// The destination bytes must be at least 387 bytes.
func NewBlindingInfoWithDestination(destBytes []byte, blindedSigType uint16, expiration uint32) (*BlindingInfo, error) {
	if len(destBytes) < 387 {
		return nil, fmt.Errorf("destination too short: %d bytes (minimum 387)", len(destBytes))
	}

	info := &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_DESTINATION,
		Endpoint:       make([]byte, len(destBytes)),
		BlindedSigType: blindedSigType,
		Expiration:     expiration,
	}
	copy(info.Endpoint, destBytes)
	return info, nil
}

// NewBlindingInfoWithSigningKey creates BlindingInfo for a signing key.
// The sigKey bytes must include 2-byte sig type + SigningPublicKey.
func NewBlindingInfoWithSigningKey(sigType uint16, signingPublicKey []byte, blindedSigType uint16, expiration uint32) (*BlindingInfo, error) {
	if len(signingPublicKey) < 1 {
		return nil, fmt.Errorf("signing public key cannot be empty")
	}

	// Build endpoint: 2-byte sig type + SigningPublicKey
	endpoint := make([]byte, 2+len(signingPublicKey))
	endpoint[0] = byte(sigType >> 8)
	endpoint[1] = byte(sigType & 0xFF)
	copy(endpoint[2:], signingPublicKey)

	return &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_SIGKEY,
		Endpoint:       endpoint,
		BlindedSigType: blindedSigType,
		Expiration:     expiration,
	}, nil
}

// SetPerClientAuth configures per-client authentication on BlindingInfo.
// This enables DH or PSK authentication for accessing the encrypted LeaseSet.
func (info *BlindingInfo) SetPerClientAuth(config *PerClientAuthConfig) error {
	if config == nil {
		return fmt.Errorf("auth config cannot be nil")
	}

	if config.AuthScheme > BLINDING_AUTH_SCHEME_PSK {
		return fmt.Errorf("invalid auth scheme %d (must be 0 for DH or 1 for PSK)", config.AuthScheme)
	}

	info.PerClientAuth = true
	info.AuthScheme = config.AuthScheme
	info.DecryptionKey = config.PrivateKey[:]
	info.LookupPassword = config.LookupPassword

	return nil
}

// SetLookupPassword sets the lookup password for accessing encrypted LeaseSets.
// This can be used independently of per-client auth.
func (info *BlindingInfo) SetLookupPassword(password string) {
	info.LookupPassword = password
}

// ClearPerClientAuth removes per-client authentication from BlindingInfo.
func (info *BlindingInfo) ClearPerClientAuth() {
	info.PerClientAuth = false
	info.AuthScheme = 0
	info.DecryptionKey = nil
}

// IsPerClientAuthEnabled returns true if per-client authentication is configured.
func (info *BlindingInfo) IsPerClientAuthEnabled() bool {
	return info.PerClientAuth && len(info.DecryptionKey) == 32
}

// GetAuthSchemeName returns a human-readable name for the auth scheme.
func (info *BlindingInfo) GetAuthSchemeName() string {
	if !info.PerClientAuth {
		return "none"
	}
	switch info.AuthScheme {
	case BLINDING_AUTH_SCHEME_DH:
		return "DH (Diffie-Hellman)"
	case BLINDING_AUTH_SCHEME_PSK:
		return "PSK (Pre-Shared Key)"
	default:
		return fmt.Sprintf("unknown (%d)", info.AuthScheme)
	}
}

// String returns a human-readable representation of the BlindingInfo.
func (info *BlindingInfo) String() string {
	endpointTypeName := "unknown"
	switch info.EndpointType {
	case BLINDING_ENDPOINT_HASH:
		endpointTypeName = "hash"
	case BLINDING_ENDPOINT_HOSTNAME:
		endpointTypeName = "hostname"
	case BLINDING_ENDPOINT_DESTINATION:
		endpointTypeName = "destination"
	case BLINDING_ENDPOINT_SIGKEY:
		endpointTypeName = "sigkey"
	}

	authInfo := "no auth"
	if info.PerClientAuth {
		authInfo = fmt.Sprintf("%s auth", info.GetAuthSchemeName())
	}
	if info.LookupPassword != "" {
		authInfo += " + password"
	}

	return fmt.Sprintf("BlindingInfo{endpoint=%s, sigType=%d, expiration=%d, %s}",
		endpointTypeName, info.BlindedSigType, info.Expiration, authInfo)
}

// SendBlindingInfoWithAuth is a convenience method to send BlindingInfo with per-client auth.
// It creates the BlindingInfo, configures auth, and sends it to the router.
//
// Parameters:
//   - endpointType: BLINDING_ENDPOINT_HASH, BLINDING_ENDPOINT_HOSTNAME, etc.
//   - endpoint: The endpoint data (hash, hostname, destination bytes, or sigkey)
//   - blindedSigType: The signature type used for blinding
//   - expiration: Expiration time in seconds since epoch
//   - authConfig: Per-client authentication configuration (can be nil)
func (s *Session) SendBlindingInfoWithAuth(
	endpointType uint8,
	endpoint []byte,
	blindedSigType uint16,
	expiration uint32,
	authConfig *PerClientAuthConfig,
) error {
	info := &BlindingInfo{
		EndpointType:   endpointType,
		Endpoint:       endpoint,
		BlindedSigType: blindedSigType,
		Expiration:     expiration,
	}

	if authConfig != nil {
		if err := info.SetPerClientAuth(authConfig); err != nil {
			return fmt.Errorf("failed to set per-client auth: %w", err)
		}
	}

	return s.SendBlindingInfo(info)
}

// SendBlindingInfoForHash is a convenience method to send BlindingInfo for a hash endpoint.
func (s *Session) SendBlindingInfoForHash(
	hash []byte,
	blindedSigType uint16,
	expiration uint32,
	authConfig *PerClientAuthConfig,
) error {
	info, err := NewBlindingInfoWithHash(hash, blindedSigType, expiration)
	if err != nil {
		return err
	}

	if authConfig != nil {
		if err := info.SetPerClientAuth(authConfig); err != nil {
			return fmt.Errorf("failed to set per-client auth: %w", err)
		}
	}

	return s.SendBlindingInfo(info)
}

// SendBlindingInfoForHostname is a convenience method to send BlindingInfo for a hostname.
func (s *Session) SendBlindingInfoForHostname(
	hostname string,
	blindedSigType uint16,
	expiration uint32,
	authConfig *PerClientAuthConfig,
) error {
	info, err := NewBlindingInfoWithHostname(hostname, blindedSigType, expiration)
	if err != nil {
		return err
	}

	if authConfig != nil {
		if err := info.SetPerClientAuth(authConfig); err != nil {
			return fmt.Errorf("failed to set per-client auth: %w", err)
		}
	}

	return s.SendBlindingInfo(info)
}

// HandleHostReplyAuthError processes HostReply error codes related to authentication.
// Returns a descriptive error message and suggested action based on the error code.
//
// Error codes 2-5 indicate authentication requirements for encrypted LeaseSets:
//   - Code 2: Lookup password required
//   - Code 3: Private key required (per-client auth)
//   - Code 4: Both password and private key required
//   - Code 5: Decryption failure (credentials may be incorrect)
func HandleHostReplyAuthError(errorCode uint8) (message, action string) {
	switch errorCode {
	case HOST_REPLY_PASSWORD_REQUIRED:
		return "Encrypted LeaseSet requires lookup password",
			"Set LookupPassword in BlindingInfo before sending"

	case HOST_REPLY_PRIVATE_KEY_REQUIRED:
		return "Per-client authentication required",
			"Use NewPerClientAuthDH() or NewPerClientAuthPSK() to configure auth"

	case HOST_REPLY_PASSWORD_AND_KEY_REQUIRED:
		return "Both password and private key required",
			"Configure both LookupPassword and per-client auth in BlindingInfo"

	case HOST_REPLY_DECRYPTION_FAILURE:
		return "Failed to decrypt LeaseSet",
			"Verify credentials are correct and match the destination's configuration"

	default:
		return fmt.Sprintf("Unknown auth error code %d", errorCode),
			"Check I2CP specification for error details"
	}
}

// ValidatePerClientAuthSupport checks if the router supports per-client authentication.
// Per-client auth requires I2CP 0.9.43+ (BlindingInfoMessage support).
func (c *Client) ValidatePerClientAuthSupport() error {
	if !c.SupportsVersion(VersionBlindingInfo) {
		return fmt.Errorf("router version %s does not support per-client authentication (requires %s+ for BlindingInfoMessage)",
			c.router.version.String(), VersionBlindingInfo.String())
	}
	return nil
}
