package go_i2cp

import (
	"fmt"
	"os"
	"time"
)

type SessionConfigProperty int

const (
	SESSION_CONFIG_PROP_CRYPTO_LOW_TAG_THRESHOLD SessionConfigProperty = iota
	SESSION_CONFIG_PROP_CRYPTO_TAGS_TO_SEND

	SESSION_CONFIG_PROP_I2CP_DONT_PUBLISH_LEASE_SET
	SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE
	SESSION_CONFIG_PROP_I2CP_GZIP
	SESSION_CONFIG_PROP_I2CP_MESSAGE_RELIABILITY
	SESSION_CONFIG_PROP_I2CP_PASSWORD
	SESSION_CONFIG_PROP_I2CP_USERNAME

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
	"i2cp.messageReliability",
	"i2cp.password",
	"i2cp.username",

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

	return &SessionConfig{
		destination: dest,
	}, nil
}

func NewSessionConfigFromDestinationFile(filename string, crypto *Crypto) (config SessionConfig) {
	var home string
	if file, err := os.Open(filename); err == nil {
		config.destination, err = NewDestinationFromFile(file, crypto)
		if err != nil {
			Warning("Failed to load destination from file '%s', a new destination will be generated.", filename)
		}
	}
	if config.destination == nil {
		config.destination, _ = NewDestination(crypto)
	}
	if len(filename) > 0 {
		config.destination.WriteToFile(filename)
	}
	home = os.Getenv("HOME")
	if len(home) > 0 {
		configFile := home + "/.i2cp.conf"
		ParseConfig(configFile, func(name, value string) {
			if prop := config.propFromString(name); prop >= 0 {
				config.SetProperty(prop, value)
			}
		})
	}
	return config
}

func (config *SessionConfig) writeToMessage(stream *Stream, crypto *Crypto, client *Client) {
	// I2CP CreateSessionMessage format (per Java I2P SessionConfig.java):
	// 1. Destination bytes
	// 2. Properties mapping
	// 3. Creation date (8 bytes - milliseconds since epoch)
	// 4. Signature over fields 1-3

	// Build data to sign - everything BEFORE the signature
	dataToSign := NewStream(make([]byte, 0, 512))
	Debug("dataToSign initial length: %d", dataToSign.Len())

	if err := config.destination.WriteToMessage(dataToSign); err != nil {
		Fatal("Failed to write destination to dataToSign: %v", err)
		return
	}
	Debug("dataToSign after destination: %d bytes (first 32: %x)", dataToSign.Len(), dataToSign.Bytes()[:min(32, dataToSign.Len())])

	if err := config.writeMappingToMessage(dataToSign); err != nil {
		Fatal("Failed to write mapping to dataToSign: %v", err)
		return
	}
	Debug("dataToSign after mapping: %d bytes", dataToSign.Len())

	// CRITICAL FIX: Use router-synchronized time for session config
	// Per I2CP spec: timestamp must be within ±30 seconds of router time
	var configTimestamp uint64
	if client != nil {
		client.routerTimeMu.RLock()
		configTimestamp = uint64(time.Now().Unix()*1000 + client.routerTimeDelta)
		client.routerTimeMu.RUnlock()
		Debug("Using router-synchronized timestamp: %d (delta: %d ms)", configTimestamp, client.routerTimeDelta)
	} else {
		configTimestamp = uint64(time.Now().Unix() * 1000)
		Warning("No client provided, using unsynchronized local time")
	}

	// Store timestamp in config for validation
	config.date = configTimestamp
	dataToSign.WriteUint64(configTimestamp)

	Debug("Session config data to sign: %d bytes", dataToSign.Len())
	if dataToSign.Len() > 0 {
		Debug("Data to sign (first 64 bytes): %x", dataToSign.Bytes()[:min(64, dataToSign.Len())])
	}

	// Generate signature over the data
	signature, err := config.signSessionConfig(dataToSign.Bytes(), crypto)
	if err != nil {
		Fatal("Failed to sign session config: %v", err)
		return
	}

	Debug("Generated signature: %d bytes, hex: %x", len(signature), signature)

	// Write the complete message: data + signature type + signature
	// Per Java I2P Signature.java: signatures are prefixed with type (uint16)
	stream.Write(dataToSign.Bytes())
	
	// Write Ed25519 signature type (7) and signature bytes
	signatureType := uint16(ED25519_SHA256)
	stream.WriteUint16(signatureType)
	stream.Write(signature)
	Debug("Complete CreateSession message: %d bytes (signature type: %d)", stream.Len(), signatureType)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
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
