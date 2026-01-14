package go_i2cp

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type SessionConfigProperty int

const (
	SESSION_CONFIG_PROP_CRYPTO_LOW_TAG_THRESHOLD SessionConfigProperty = iota
	SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND

	SESSION_CONFIG_PROP_I2CP_DONT_PUBLISH_LEASE_SET
	SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE
	SESSION_CONFIG_PROP_I2CP_GZIP
	SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE
	SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY
	SESSION_CONFIG_PROP_I2CP_PASSWORD
	SESSION_CONFIG_PROP_I2CP_USERNAME

	// Offline Signature Properties (I2CP § SessionConfig - Offline Signatures)
	// These three properties must ALL be set together if the Destination uses offline signing.
	// Per SPEC.md: "If the Destination is offline signed, the Mapping must contain:
	//   - i2cp.leaseSetOfflineExpiration
	//   - i2cp.leaseSetTransientPublicKey
	//   - i2cp.leaseSetOfflineSignature"
	SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION   // Unix timestamp in seconds when offline signature expires
	SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY // Base64-encoded transient signing public key
	SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE    // Base64-encoded offline signature

	SESSION_CONFIG_PROP_INBOUND_ALLOW_ZERO_HOP
	SESSION_CONFIG_PROP_INBOUND_BACKUP_QUANTITY
	SESSION_CONFIG_PROP_INBOUND_IP_RESTRICTION
	SESSION_CONFIG_PROP_INBOUND_LENGTH
	SESSION_CONFIG_PROP_INBOUND_LENGTH_VARIANCE
	SESSION_CONFIG_PROP_INBOUND_NICKNAME
	SESSION_CONFIG_PROP_INBOUND_QUANTITY

	SESSION_CONFIG_PROP_OUTBOUND_ALLOW_ZERO_HOP
	SESSION_CONFIG_PROP_OUTBOUND_BACKUP_QUANTITY
	SESSION_CONFIG_PROP_OUTBOUND_IP_RESTRICTION
	SESSION_CONFIG_PROP_OUTBOUND_LENGTH
	SESSION_CONFIG_PROP_OUTBOUND_LENGTH_VARIANCE
	SESSION_CONFIG_PROP_OUTBOUND_NICKNAME
	SESSION_CONFIG_PROP_OUTBOUND_PRIORITY
	SESSION_CONFIG_PROP_OUTBOUND_QUANTITY

	NR_OF_SESSION_CONFIG_PROPERTIES
)

var sessionOptions = [NR_OF_SESSION_CONFIG_PROPERTIES]string{
	"crypto.lowTagThreshold",
	"crypto.tagsToSend",
	"i2cp.dontPublishLeaseSet",
	"i2cp.fastReceive",
	"i2cp.gzip",
	"i2cp.leaseSetEncType",
	"i2cp.messageReliability",
	"i2cp.password",
	"i2cp.username",
	"i2cp.leaseSetOfflineExpiration",
	"i2cp.leaseSetTransientPublicKey",
	"i2cp.leaseSetOfflineSignature",
	"inbound.allowZeroHop",
	"inbound.backupQuantity",
	"inbound.IPRestriction",
	"inbound.length",
	"inbound.lengthVariance",
	"inbound.nickname",
	"inbound.quantity",
	"outbound.allowZeroHop",
	"outbound.backupQuantity",
	"outbound.IPRestriction",
	"outbound.length",
	"outbound.lengthVariance",
	"outbound.nickname",
	"outbound.priority",
	"outbound.quantity",
}

type SessionConfig struct {
	properties  [NR_OF_SESSION_CONFIG_PROPERTIES]string
	date        uint64
	destination *Destination
}

// NewSessionConfig creates a new SessionConfig with auto-generated destination.
// This is the simplest way to create a session configuration without loading from a file.
// The destination is created using standard cryptography (currently Ed25519 by default).
//
// Example:
//
//	config := NewSessionConfig()
//	// config is ready to use with default settings
//
// If you need to load a destination from a file, use NewSessionConfigFromDestinationFile instead.
func NewSessionConfig() (*SessionConfig, error) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination: %w", err)
	}

	config := &SessionConfig{
		destination: dest,
	}

	// Set default encryption type to ECIES-X25519 (type 4)
	// Per I2CP spec, i2cp.leaseSetEncType declares the encryption type the router should use
	// Default is 0 (ElGamal), but modern I2P uses X25519 (type 4)
	// The Destination cert says ElGamal (legacy compatibility), but actual encryption via this option
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, "4")

	return config, nil
}

func NewSessionConfigFromDestinationFile(filename string, crypto *Crypto) (config SessionConfig) {
	config.destination = loadOrCreateDestination(filename, crypto)
	loadUserConfigFile(&config)

	// Set default encryption type to ECIES-X25519 (type 4) if not already configured
	if config.properties[SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE] == "" {
		config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_ENC_TYPE, "4")
	}

	return config
}

// loadOrCreateDestination loads a destination from file or creates a new one if loading fails.
func loadOrCreateDestination(filename string, crypto *Crypto) *Destination {
	if file, err := os.Open(filename); err == nil {
		dest, err := NewDestinationFromFile(file, crypto)
		if err == nil {
			return dest
		}
		Warning("Failed to load destination from file '%s', a new destination will be generated.", filename)
	}

	dest, _ := NewDestination(crypto)
	if len(filename) > 0 {
		dest.WriteToFile(filename)
	}
	return dest
}

// loadUserConfigFile loads user configuration from ~/.i2cp.conf if HOME is set.
func loadUserConfigFile(config *SessionConfig) {
	home := os.Getenv("HOME")
	if len(home) == 0 {
		return
	}

	configFile := home + "/.i2cp.conf"
	ParseConfig(configFile, func(name, value string) {
		if prop := config.propFromString(name); prop >= 0 {
			config.SetProperty(prop, value)
		}
	})
}

func (config *SessionConfig) writeToMessage(stream *Stream, crypto *Crypto, client *Client) {
	// I2CP CreateSessionMessage format (per Java I2P SessionConfig.java):
	// WIRE FORMAT: Destination(full 384 bytes) + Properties + Date + Signature
	// SIGNATURE DATA: Destination(truncated) + Properties + Date
	//
	// CRITICAL: The wire format and signature data use DIFFERENT Destination serializations!
	// - Wire format: 256-byte pubKey + 128-byte paddedSignKey + certificate
	// - Signature format: 256-byte pubKey + 32-byte truncatedSignKey + certificate
	// This is because Java reads the wire format, extracts keys per certificate, then re-serializes
	// with extracted key sizes for signature verification.

	dataToSign := buildSessionDataToSign(config)
	configTimestamp := getSessionTimestamp(config, client)
	config.date = configTimestamp

	signature, err := buildSessionSignature(config, dataToSign, configTimestamp, crypto)
	if err != nil {
		return
	}

	wireMessage := buildSessionWireMessage(config, configTimestamp)
	stream.Write(wireMessage.Bytes())
	stream.Write(signature)

	Debug("Complete CreateSession message: %d bytes", stream.Len())
}

// buildSessionDataToSign constructs the data to be signed for session config.
func buildSessionDataToSign(config *SessionConfig) *Stream {
	dataToSign := NewStream(make([]byte, 0, 512))
	Debug("dataToSign initial length: %d", dataToSign.Len())

	if err := config.destination.WriteToMessage(dataToSign); err != nil {
		Fatal("Failed to write destination to dataToSign: %v", err)
		return dataToSign
	}
	Debug("dataToSign after destination: %d bytes (first 32: %x)", dataToSign.Len(), dataToSign.Bytes()[:min(32, dataToSign.Len())])

	if err := config.writeMappingToMessage(dataToSign); err != nil {
		Fatal("Failed to write mapping to dataToSign: %v", err)
		return dataToSign
	}
	Debug("dataToSign after mapping: %d bytes", dataToSign.Len())

	return dataToSign
}

// getSessionTimestamp retrieves the session timestamp, synchronized with router time if available.
func getSessionTimestamp(config *SessionConfig, client *Client) uint64 {
	if client != nil {
		client.routerTimeMu.RLock()
		defer client.routerTimeMu.RUnlock()
		configTimestamp := uint64(time.Now().Unix()*1000 + client.routerTimeDelta)
		Debug("Using router-synchronized timestamp: %d (delta: %d ms)", configTimestamp, client.routerTimeDelta)
		return configTimestamp
	}
	Warning("No client provided, using unsynchronized local time")
	return uint64(time.Now().Unix() * 1000)
}

// buildSessionSignature creates and returns the signature for session config data.
func buildSessionSignature(config *SessionConfig, dataToSign *Stream, timestamp uint64, crypto *Crypto) ([]byte, error) {
	signatureData := NewStream(make([]byte, 0, 512))
	signatureData.Write(dataToSign.Bytes())
	signatureData.WriteUint64(timestamp)

	Debug("Session config data to sign: %d bytes", signatureData.Len())
	if signatureData.Len() > 0 {
		Debug("Data to sign (first 64 bytes): %x", signatureData.Bytes()[:min(64, signatureData.Len())])
		Debug("Data to sign (last 64 bytes): %x", signatureData.Bytes()[max(0, signatureData.Len()-64):])
		Debug("FULL data to sign (%d bytes): %x", signatureData.Len(), signatureData.Bytes())
	}

	signature, err := config.signSessionConfig(signatureData.Bytes(), crypto)
	if err != nil {
		Fatal("Failed to sign session config: %v", err)
		return nil, err
	}
	Debug("Generated signature: %d bytes, hex: %x", len(signature), signature)

	// Log the public key for debugging
	if config.destination.sgk.ed25519KeyPair != nil {
		pubKey := config.destination.sgk.ed25519KeyPair.PublicKey()
		Debug("Signing public key (%d bytes): %x", len(pubKey), pubKey[:])
	}

	return signature, nil
}

// buildSessionWireMessage constructs the wire message for the router with destination, mapping, and timestamp.
func buildSessionWireMessage(config *SessionConfig, timestamp uint64) *Stream {
	wireMessage := NewStream(make([]byte, 0, 512))
	if err := config.destination.WriteToMessage(wireMessage); err != nil {
		Fatal("Failed to write destination to wire message: %v", err)
		return wireMessage
	}

	if err := config.writeMappingToMessage(wireMessage); err != nil {
		Fatal("Failed to write mapping to wire message: %v", err)
		return wireMessage
	}

	wireMessage.WriteUint64(timestamp)

	Debug("Wire message for router (%d bytes): %x", wireMessage.Len(), wireMessage.Bytes())
	Debug("Wire message first 32 bytes: %x", wireMessage.Bytes()[:min(32, wireMessage.Len())])
	Debug("Wire message last 32 bytes: %x", wireMessage.Bytes()[max(0, wireMessage.Len()-32):])

	return wireMessage
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// signSessionConfig generates a signature over session config data
// per I2CP specification - uses Ed25519 signatures exclusively
func (config *SessionConfig) signSessionConfig(data []byte, crypto *Crypto) ([]byte, error) {
	if config.destination.sgk.ed25519KeyPair == nil {
		return nil, fmt.Errorf("Ed25519 keypair not available (legacy DSA not supported)")
	}

	Debug("Signing with Ed25519 keypair")
	pubKey := config.destination.sgk.ed25519KeyPair.PublicKey()
	Debug("[SIGN] Public key in destination.sgk.ed25519KeyPair: %x", pubKey[:])
	return config.destination.sgk.ed25519KeyPair.Sign(data)
}

func (config *SessionConfig) writeMappingToMessage(stream *Stream) (err error) {
	m := make(map[string]string)
	for i := 0; i < int(NR_OF_SESSION_CONFIG_PROPERTIES); i++ {
		var option string
		if config.properties[i] == "" {
			continue
		}
		option = config.configOptLookup(SessionConfigProperty(i))
		if option == "" {
			continue
		}
		m[option] = config.properties[i]
		Debug("  Option: %s = %s", option, config.properties[i])
	}
	Debug("Writing %d options to mapping table", len(m))
	return stream.WriteMapping(m)
}

func (config *SessionConfig) configOptLookup(property SessionConfigProperty) string {
	return sessionOptions[property]
}

func (config *SessionConfig) propFromString(name string) SessionConfigProperty {
	for i := 0; SessionConfigProperty(i) < NR_OF_SESSION_CONFIG_PROPERTIES; i++ {
		if sessionOptions[i] == name {
			return SessionConfigProperty(i)
		}
	}
	return SessionConfigProperty(-1)
}

func (config *SessionConfig) SetProperty(prop SessionConfigProperty, value string) {
	config.properties[prop] = value
}

func (config *SessionConfig) GetProperty(prop SessionConfigProperty) string {
	return config.properties[prop]
}

// ValidateTimestamp validates that the session config timestamp is within ±30 seconds
// of the current time, as required by the I2CP specification.
//
// Per I2CP § SessionConfig Notes:
// "The creation date must be within +/- 30 seconds of the current time when processed
// by the router, or the config will be rejected."
//
// This validation should be called before sending CreateSessionMessage to ensure
// early detection of clock synchronization issues.
func (config *SessionConfig) ValidateTimestamp() error {
	if config.date == 0 {
		return fmt.Errorf("session config timestamp not set")
	}

	now := uint64(time.Now().Unix() * 1000)
	delta := int64(now) - int64(config.date)

	// I2CP spec requires ±30 seconds (30000 milliseconds)
	const maxDeltaMs = 30000
	if delta < -maxDeltaMs || delta > maxDeltaMs {
		return fmt.Errorf("session config timestamp %d is %d ms from current time (max ±%d ms allowed per I2CP spec)",
			config.date, delta, maxDeltaMs)
	}

	Debug("Session config timestamp validation passed: delta=%d ms (within ±%d ms)", delta, maxDeltaMs)
	return nil
}

// SetOfflineSignature configures the session for offline-signed destination operation.
// Per I2CP § SessionConfig - Offline Signatures:
// "If the Destination is offline signed, the Mapping must contain:
//   - i2cp.leaseSetOfflineExpiration
//   - i2cp.leaseSetTransientPublicKey
//   - i2cp.leaseSetOfflineSignature"
//
// Parameters:
//   - expiration: Unix timestamp in seconds when the offline signature expires
//   - transientPublicKey: The transient signing public key (raw bytes, will be base64 encoded)
//   - signature: The offline signature (raw bytes, will be base64 encoded)
//
// The signature is generated by signing [signingKeyType||signingKey||expires||transientKeyType||transientKey]
// with the long-term signing private key. The session then uses the transient private key for
// all subsequent signatures (e.g., LeaseSet signing).
//
// This enables enhanced security by keeping the long-term private key offline and only using
// a time-limited transient key for active operations.
func (config *SessionConfig) SetOfflineSignature(expiration uint32, transientPublicKey, signature []byte) error {
	if transientPublicKey == nil || len(transientPublicKey) == 0 {
		return fmt.Errorf("transient public key cannot be empty")
	}
	if signature == nil || len(signature) == 0 {
		return fmt.Errorf("offline signature cannot be empty")
	}
	if expiration == 0 {
		return fmt.Errorf("expiration timestamp cannot be zero")
	}

	// Check if expiration is in the past
	now := uint32(time.Now().Unix())
	if expiration <= now {
		return fmt.Errorf("offline signature expiration %d is in the past (current time: %d)", expiration, now)
	}

	// Set all three required properties
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION, strconv.FormatUint(uint64(expiration), 10))
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY, base64.StdEncoding.EncodeToString(transientPublicKey))
	config.SetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE, base64.StdEncoding.EncodeToString(signature))

	Debug("Offline signature configured: expiration=%d, transientKey=%d bytes, signature=%d bytes",
		expiration, len(transientPublicKey), len(signature))

	return nil
}

// HasOfflineSignature returns true if the session is configured for offline-signed operation.
// Per I2CP § SessionConfig - Offline Signatures, all three properties must be set.
func (config *SessionConfig) HasOfflineSignature() bool {
	return config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION) != "" &&
		config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY) != "" &&
		config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE) != ""
}

// ValidateOfflineSignature validates the offline signature configuration.
// Per I2CP § SessionConfig - Offline Signatures, all three properties must be set together.
//
// This function validates:
//   - All three properties are set (or none are set)
//   - The expiration timestamp is not in the past
//   - The transient public key and signature are valid base64
//
// Returns nil if the configuration is valid or if offline signing is not configured.
func (config *SessionConfig) ValidateOfflineSignature() error {
	exp, key, sig := config.getOfflineSignatureProperties()

	if err := config.validateOfflinePropertiesPresence(exp, key, sig); err != nil {
		return err
	}

	if exp == "" {
		return nil // Offline signing not configured - valid
	}

	return config.validateOfflinePropertyValues(exp, key, sig)
}

// getOfflineSignatureProperties retrieves all offline signature related properties.
func (config *SessionConfig) getOfflineSignatureProperties() (exp, key, sig string) {
	exp = config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION)
	key = config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY)
	sig = config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE)
	return
}

// validateOfflinePropertiesPresence ensures all or none of the offline properties are set.
func (config *SessionConfig) validateOfflinePropertiesPresence(exp, key, sig string) error {
	hasExp, hasKey, hasSig := exp != "", key != "", sig != ""

	if !hasExp && !hasKey && !hasSig {
		return nil
	}

	if !(hasExp && hasKey && hasSig) {
		return fmt.Errorf("incomplete offline signature configuration: all three properties " +
			"(i2cp.leaseSetOfflineExpiration, i2cp.leaseSetTransientPublicKey, " +
			"i2cp.leaseSetOfflineSignature) must be set together")
	}
	return nil
}

// validateOfflinePropertyValues validates the format and values of offline signature properties.
func (config *SessionConfig) validateOfflinePropertyValues(exp, key, sig string) error {
	expTimestamp, err := config.validateExpirationTimestamp(exp)
	if err != nil {
		return err
	}

	if err := validateBase64Property(key, "transient public key"); err != nil {
		return err
	}

	if err := validateBase64Property(sig, "offline signature"); err != nil {
		return err
	}

	now := uint32(time.Now().Unix())
	Debug("Offline signature validation passed: expires=%d, %d seconds remaining",
		expTimestamp, expTimestamp-now)

	return nil
}

// validateExpirationTimestamp parses and validates the expiration timestamp.
func (config *SessionConfig) validateExpirationTimestamp(exp string) (uint32, error) {
	expTimestamp, err := strconv.ParseUint(exp, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid offline expiration timestamp: %w", err)
	}

	now := uint32(time.Now().Unix())
	if uint32(expTimestamp) <= now {
		return 0, fmt.Errorf("offline signature expired: expiration %d <= current time %d", expTimestamp, now)
	}
	return uint32(expTimestamp), nil
}

// validateBase64Property validates that a property value is valid base64 encoding.
func validateBase64Property(value, propertyName string) error {
	if _, err := base64.StdEncoding.DecodeString(value); err != nil {
		return fmt.Errorf("invalid base64 encoding for %s: %w", propertyName, err)
	}
	return nil
}

// GetOfflineSignatureExpiration returns the offline signature expiration timestamp.
// Returns 0 if offline signing is not configured.
func (config *SessionConfig) GetOfflineSignatureExpiration() uint32 {
	exp := config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_EXPIRATION)
	if exp == "" {
		return 0
	}
	timestamp, err := strconv.ParseUint(exp, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(timestamp)
}

// GetOfflineSignatureTransientKey returns the transient public key for offline signing.
// Returns nil if offline signing is not configured or the key is invalid.
func (config *SessionConfig) GetOfflineSignatureTransientKey() []byte {
	key := config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_TRANSIENT_PUBLIC_KEY)
	if key == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil
	}
	return decoded
}

// GetOfflineSignatureBytes returns the offline signature bytes.
// Returns nil if offline signing is not configured or the signature is invalid.
func (config *SessionConfig) GetOfflineSignatureBytes() []byte {
	sig := config.GetProperty(SESSION_CONFIG_PROP_I2CP_LEASESET_OFFLINE_SIGNATURE)
	if sig == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil
	}
	return decoded
}
