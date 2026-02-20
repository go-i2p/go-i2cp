package go_i2cp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/certificate"
	cryptoed25519 "github.com/go-i2p/crypto/ed25519"
)

type Destination struct {
	cert   *Certificate
	sgk    SignatureKeyPair
	pubKey [PUB_KEY_SIZE]byte
	digest [DIGEST_SIZE]byte
	b32    string
	b64    string
	crypto *Crypto
}

func NewDestination(crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}

	// I2CP requires ElGamal encryption type (0) in Destination certificate
	// Per Java I2P router ClientMessageEventListener.java: only ELGAMAL_2048 is supported via I2CP
	// Modern encryption (X25519) is specified separately via i2cp.leaseSetEncType session option
	// Certificate format: [type=5][length=4][sigType=7][cryptoType=0]
	keyCertPayload := []byte{
		0, 7, // Signing key type: Ed25519 (7)
		0, 0, // Encryption key type: ElGamal (0) - required for I2CP compatibility
	}
	commonCert, err := certificate.NewCertificateWithType(CERTIFICATE_KEY, keyCertPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEY certificate: %w", err)
	}
	dest.cert = commonCert

	// Generate Ed25519 signing keypair (fast, modern)
	dest.sgk, err = crypto.SignatureKeygen(ED25519_SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 signature keypair: %w", err)
	}

	// Destination pubKey field: must be 256 bytes (ElGamal size) even though unused
	// Fill with zeros - field deprecated since 2005, actual encryption via LeaseSet
	// Modern encryption (X25519) configured via i2cp.leaseSetEncType=4 session option

	dest.generateB32()
	dest.generateB64()
	return
}

// readDestinationKeys reads the public key and signing key from a message stream.
// Returns the public key array, signing key padded bytes, and any error.
func readDestinationKeys(stream *Stream) ([256]byte, []byte, error) {
	var pubKey [256]byte

	_, err := stream.Read(pubKey[:])
	if err != nil {
		return pubKey, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	signingKeyPadded := make([]byte, 128)
	_, err = stream.Read(signingKeyPadded)
	if err != nil {
		return pubKey, nil, fmt.Errorf("failed to read signing key: %w", err)
	}

	return pubKey, signingKeyPadded, nil
}

// createEd25519SigningKeyPair creates a SignatureKeyPair from Ed25519 public key bytes.
// Extracts the 32-byte Ed25519 public key from the right-aligned 128-byte field.
func createEd25519SigningKeyPair(signingKeyPadded []byte) (SignatureKeyPair, error) {
	ed25519PubKeyBytes := signingKeyPadded[96:128]

	ed25519PubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(ed25519PubKeyBytes)
	if err != nil {
		return SignatureKeyPair{}, fmt.Errorf("failed to create Ed25519 public key: %w", err)
	}

	return SignatureKeyPair{
		algorithmType: ED25519_SHA256,
		ed25519KeyPair: &Ed25519KeyPair{
			algorithmType: ED25519_SHA256,
			publicKey:     ed25519PubKey,
		},
	}, nil
}

// NewDestinationFromMessage reads a destination from an I2CP message stream.
// NOTE: This function supports Ed25519 destinations with KEY certificates only.
// Legacy DSA destinations are no longer supported.
func NewDestinationFromMessage(stream *Stream, crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}

	pubKey, signingKeyPadded, err := readDestinationKeys(stream)
	if err != nil {
		return nil, err
	}
	dest.pubKey = pubKey

	cert, err := NewCertificateFromMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	dest.cert = cert

	if CertType(cert) != CERTIFICATE_KEY {
		return nil, fmt.Errorf("unsupported certificate type: %d (only KEY certificates with Ed25519 supported)", CertType(cert))
	}

	dest.sgk, err = createEd25519SigningKeyPair(signingKeyPadded)
	if err != nil {
		return nil, err
	}

	dest.generateB32()
	dest.generateB64()
	return dest, nil
}

// NewDestinationFromStream reads a destination from a configuration stream.
// This format includes the full keypair, not just public keys.
// NOTE: Only Ed25519 destinations with KEY certificates are supported.
func NewDestinationFromStream(stream *Stream, crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}

	cert, err := readDestinationCertificate(stream)
	if err != nil {
		return nil, err
	}
	dest.cert = cert

	if err := validateDestinationAlgorithm(stream); err != nil {
		return nil, err
	}

	sgk, err := readDestinationEd25519KeyPair(stream)
	if err != nil {
		return nil, err
	}
	dest.sgk = sgk

	if err := readDestinationEncryptionKey(stream, dest); err != nil {
		return nil, err
	}

	dest.generateB32()
	dest.generateB64()
	return dest, nil
}

// readDestinationCertificate reads and validates the certificate from the stream.
// Returns the certificate or an error if reading fails.
func readDestinationCertificate(stream *Stream) (*Certificate, error) {
	cert, err := NewCertificateFromStream(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	return cert, nil
}

// validateDestinationAlgorithm reads and validates the signature algorithm type.
// Returns an error if the algorithm is not Ed25519.
func validateDestinationAlgorithm(stream *Stream) error {
	algType, err := stream.ReadUint32()
	if err != nil {
		return fmt.Errorf("failed to read algorithm type: %w", err)
	}

	if algType != ED25519_SHA256 {
		return fmt.Errorf("unsupported signature algorithm: %d (only Ed25519 supported)", algType)
	}

	return nil
}

// readDestinationEd25519KeyPair reads the Ed25519 keypair from the stream.
// Returns the SignatureKeyPair or an error if reading or key creation fails.
func readDestinationEd25519KeyPair(stream *Stream) (SignatureKeyPair, error) {
	// Read Ed25519 keypair (64 bytes private + 32 bytes public for stdlib format)
	// The crypto package uses 64-byte private keys (includes 32-byte seed + 32-byte public key)
	privateKeyBytes := make([]byte, 64)
	_, err := stream.Read(privateKeyBytes)
	if err != nil {
		return SignatureKeyPair{}, fmt.Errorf("failed to read Ed25519 private key: %w", err)
	}

	publicKeyBytes := make([]byte, 32)
	_, err = stream.Read(publicKeyBytes)
	if err != nil {
		return SignatureKeyPair{}, fmt.Errorf("failed to read Ed25519 public key: %w", err)
	}

	// Create Ed25519 keypair using crypto package
	privKey, err := cryptoed25519.CreateEd25519PrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return SignatureKeyPair{}, fmt.Errorf("failed to create Ed25519 private key: %w", err)
	}

	pubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return SignatureKeyPair{}, fmt.Errorf("failed to create Ed25519 public key: %w", err)
	}

	return SignatureKeyPair{
		algorithmType: ED25519_SHA256,
		ed25519KeyPair: &Ed25519KeyPair{
			algorithmType: ED25519_SHA256,
			privateKey:    privKey,
			publicKey:     pubKey,
		},
	}, nil
}

// readDestinationEncryptionKey reads and validates the encryption public key.
// Updates the destination with the encryption key or returns an error.
func readDestinationEncryptionKey(stream *Stream, dest *Destination) error {
	// Read encryption public key length
	pubKeyLen, err := stream.ReadUint16()
	if err != nil {
		return fmt.Errorf("failed to read public key length: %w", err)
	}
	if pubKeyLen != PUB_KEY_SIZE {
		return fmt.Errorf("invalid public key length: got %d, expected %d", pubKeyLen, PUB_KEY_SIZE)
	}

	// Read encryption public key
	_, err = stream.Read(dest.pubKey[:])
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	return nil
}

func NewDestinationFromBase64(base64Str string, crypto *Crypto) (dest *Destination, err error) {
	/* Same as decode, except from a filesystem / URL friendly set of characters,
	*  replacing / with ~, and + with -
	 */
	// see https://javadoc.freenetproject.org/freenet/support/Base64.html
	if len(base64Str) == 0 {
		err = errors.New("empty string")
		return
	}
	// The base64 string uses freenet format (~ for /, - for +)
	// common/base64 already uses I2P format which is the same as freenet
	// So we can decode directly without replacement
	var decoded []byte
	decoded, err = base64.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 destination: %w", err)
	}
	stream := NewStream(decoded)
	return NewDestinationFromMessage(stream, crypto)
}

func NewDestinationFromFile(file *os.File, crypto *Crypto) (*Destination, error) {
	// Read all data from file
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read destination file: %w", err)
	}

	// Create stream from file data
	stream := NewStream(data)
	return NewDestinationFromStream(stream, crypto)
}

func (dest *Destination) Copy() (newDest Destination) {
	newDest.cert = dest.cert
	newDest.pubKey = dest.pubKey
	newDest.sgk = dest.sgk
	newDest.b32 = dest.b32
	newDest.b64 = dest.b64
	newDest.digest = dest.digest
	newDest.crypto = dest.crypto
	return
}

func (dest *Destination) WriteToFile(filename string) (err error) {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	if err = dest.WriteToStream(stream); err != nil {
		return fmt.Errorf("failed to write destination to stream: %w", err)
	}
	var file *os.File
	file, err = os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close destination file: %w", closeErr)
		}
	}()

	if _, err = stream.WriteTo(file); err != nil {
		return fmt.Errorf("failed to write stream to file: %w", err)
	}
	return nil
}

// WriteToMessage writes the destination in I2CP/I2NP WIRE FORMAT.
// This is the format used for transmitting destinations over the network and in datagram envelopes.
//
// WIRE FORMAT (391+ bytes for Ed25519):
//   - pubKey: 256 bytes (encryption public key, zeros for modern crypto)
//   - signingPubKey: 128 bytes (Ed25519 key right-aligned at bytes 96-127)
//   - certificate: 7+ bytes (KEY certificate with sig/crypto type)
//
// USE THIS METHOD FOR:
//   - Building datagram envelopes (sender destination in Datagram1/2/3)
//   - Any I2CP message that transmits a destination over the wire
//   - Hash computation for replay prevention (Datagram2)
//
// The I2P specification says destinations are "387+ bytes" for DSA, but for Ed25519
// with KEY certificates, the wire format is 391+ bytes (256 + 128 + 7).
// The apparent discrepancy is because DSA-SHA1 keys fit exactly in the legacy fields
// while Ed25519 requires padding and a KEY certificate.
//
// See also:
//   - WriteForSignature: for signature computation (different signing key format)
//   - WriteToStream: for file storage (compact format, not wire-compatible)
//   - NewDestinationFromMessage: reads this format
func (dest *Destination) WriteToMessage(stream *Stream) (err error) {
	// Wire format: pubKey(256 bytes) + signingPubKey(128 bytes) + certificate
	// The router will read this, extract the actual key sizes from the certificate,
	// and store the keys in their native sizes (32 bytes for Ed25519)

	// Always write 256 bytes for encryption key
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Write 128-byte signing key field with Ed25519 key right-aligned at bytes 96-127
	paddedSignKey := make([]byte, 128)
	if dest.sgk.ed25519KeyPair != nil {
		ed25519PubKey := dest.sgk.ed25519KeyPair.PublicKey()
		copy(paddedSignKey[96:], ed25519PubKey[:]) // Right-align 32-byte key in 128-byte field
		Debug("[WriteToMessage] WROTE public key: %x", ed25519PubKey[:])
	} else {
		return fmt.Errorf("no Ed25519 keypair available")
	}

	if _, err = stream.Write(paddedSignKey); err != nil {
		return fmt.Errorf("failed to write signing public key: %w", err)
	}

	// Write certificate
	if err = WriteCertificateToMessage(dest.cert, stream); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

// WriteForSignature writes the destination in the format used by Java I2P for SIGNATURE COMPUTATION.
//
// SIGNATURE FORMAT (295 bytes for Ed25519):
//   - pubKey: 256 bytes (same as wire format)
//   - signingPubKey: 32 bytes (TRUNCATED, not padded to 128 bytes)
//   - certificate: 7+ bytes (same as wire format)
//
// CRITICAL DIFFERENCE FROM WriteToMessage:
// When Java reads a Destination from the wire (128-byte signing key field), it extracts
// the actual key based on the certificate's declared sizes. When re-serializing for
// signature verification, Java writes the EXTRACTED key sizes, not the padded wire format.
//
// For Ed25519:
//   - Wire format (WriteToMessage): 128-byte field with 32-byte key at bytes 96-127
//   - Signature format (WriteForSignature): just 32 bytes
//
// USE THIS METHOD FOR:
//   - Computing data-to-sign for datagram authentication
//   - Signature verification (must match sender's computation)
//
// DO NOT USE FOR:
//   - Transmitting destinations over the network (use WriteToMessage)
//   - Building datagram envelopes (use WriteToMessage)
//
// See Java I2P: SigningPublicKey.writeTruncatedBytes() for reference implementation.
func (dest *Destination) WriteForSignature(stream *Stream) (err error) {
	// Write 256 bytes for encryption key (same as wire format)
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Write TRUNCATED signing key (not padded!) - this matches Java's writeTruncatedBytes()
	// For Ed25519 (32 bytes), write just the 32 bytes (NOT right-aligned in 128-byte field)
	if dest.sgk.ed25519KeyPair != nil {
		ed25519PubKey := dest.sgk.ed25519KeyPair.PublicKey()
		if _, err = stream.Write(ed25519PubKey[:]); err != nil {
			return fmt.Errorf("failed to write signing public key: %w", err)
		}
		Debug("[WriteForSignature] WROTE public key: %x", ed25519PubKey[:])
	} else {
		return fmt.Errorf("no Ed25519 keypair available")
	}

	// Write certificate (same as wire format)
	if err = WriteCertificateToMessage(dest.cert, stream); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

// WriteToStream writes the destination in a COMPACT STORAGE FORMAT.
// This format is used for saving destinations to files (e.g., .dat files).
//
// STORAGE FORMAT (varies):
//   - certificate: 3+ bytes
//   - algorithmType: 4 bytes
//   - signingKeyPair: algorithm-specific size
//   - encryptionPubKey: 256 bytes
//
// This format differs from the wire format (WriteToMessage) and is NOT compatible
// with I2CP/I2NP message parsing. Use WriteToFile() for file operations.
//
// USE THIS METHOD FOR:
//   - Saving destinations to disk for later loading
//   - Internal storage operations
//
// DO NOT USE FOR:
//   - Network transmission (use WriteToMessage)
//   - Datagram envelopes (use WriteToMessage)
//   - Signature computation (use WriteForSignature)
//
// See also:
//   - WriteToFile: convenience wrapper for file I/O
//   - NewDestinationFromFile: reads this format
func (dest *Destination) WriteToStream(stream *Stream) (err error) {
	if err = dest.writeCertificateToStream(stream); err != nil {
		return err
	}

	if err = dest.writeAlgorithmType(stream); err != nil {
		return err
	}

	if err = dest.writeEd25519KeyPair(stream); err != nil {
		return err
	}

	if err = dest.writeEncryptionPublicKey(stream); err != nil {
		return err
	}

	return nil
}

// writeCertificateToStream writes the destination certificate to the stream.
func (dest *Destination) writeCertificateToStream(stream *Stream) error {
	if err := WriteCertificateToStream(dest.cert, stream); err != nil {
		return fmt.Errorf("failed to write certificate to stream: %w", err)
	}
	return nil
}

// writeAlgorithmType writes the signature algorithm type to the stream.
func (dest *Destination) writeAlgorithmType(stream *Stream) error {
	if err := stream.WriteUint32(ED25519_SHA256); err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}
	return nil
}

// writeEd25519KeyPair writes the Ed25519 private and public keys to the stream.
func (dest *Destination) writeEd25519KeyPair(stream *Stream) error {
	if dest.sgk.ed25519KeyPair == nil {
		return fmt.Errorf("no Ed25519 keypair available")
	}

	privKey := dest.sgk.ed25519KeyPair.PrivateKey()
	pubKey := dest.sgk.ed25519KeyPair.PublicKey()

	if _, err := stream.Write(privKey[:]); err != nil {
		return fmt.Errorf("failed to write Ed25519 private key: %w", err)
	}
	if _, err := stream.Write(pubKey[:]); err != nil {
		return fmt.Errorf("failed to write Ed25519 public key: %w", err)
	}

	return nil
}

// writeEncryptionPublicKey writes the encryption public key length and data to the stream.
func (dest *Destination) writeEncryptionPublicKey(stream *Stream) error {
	if err := stream.WriteUint16(PUB_KEY_SIZE); err != nil {
		return fmt.Errorf("failed to write public key size: %w", err)
	}

	if _, err := stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// Verify - DEPRECATED AND REMOVED
// This method relied on legacy DSA VerifyStream functionality.
// Ed25519 signature verification should be done directly using the Ed25519KeyPair.Verify() method.
// This method was never used in the codebase and has been removed.

func (dest *Destination) generateB32() {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	// WriteToMessage errors are not expected in normal operation since we're writing to a memory buffer
	// If it fails, the b32 address will be incomplete, but this is logged for debugging
	if err := dest.WriteToMessage(stream); err != nil {
		Error("Failed to generate b32 address: %v", err)
		return
	}
	// Use stdlib crypto/sha256 for hashing
	hash := sha256.Sum256(stream.Bytes())
	// Use common/base32 for I2P-specific base32 encoding
	b32Encoded := base32.EncodeToString(hash[:])
	dest.b32 = b32Encoded + ".b32.i2p"
	Debug("New destination %s", dest.b32)
}

func (dest *Destination) generateB64() {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	// WriteToMessage errors are not expected in normal operation since we're writing to a memory buffer
	// If it fails, the b64 address will be incomplete, but this is logged for debugging
	if err := dest.WriteToMessage(stream); err != nil {
		Error("Failed to generate b64 address: %v", err)
		return
	}
	if stream.Len() > 0 {
		fmt.Printf("Stream len %d \n", stream.Len())
	}
	// Use common/base64 for I2P-specific base64 encoding (already uses - and ~ chars)
	dest.b64 = base64.EncodeToString(stream.Bytes())
}

// Base32 returns the Base32 address of the destination (e.g., "abc123....xyz.b32.i2p")
func (dest *Destination) Base32() string {
	return dest.b32
}

// Base64 returns the Base64 address of the destination
func (dest *Destination) Base64() string {
	return dest.b64
}

// SigningKeyPair returns the Ed25519 signing key pair for this destination.
// This provides access to both signing (with private key) and verification (with public key).
// For verification-only use cases (without private key access), use SigningPublicKey() instead.
//
// Returns error if the destination has no Ed25519 keypair available.
func (dest *Destination) SigningKeyPair() (*Ed25519KeyPair, error) {
	if dest.sgk.ed25519KeyPair == nil {
		return nil, fmt.Errorf("destination has no Ed25519 keypair")
	}
	return dest.sgk.ed25519KeyPair, nil
}

// SigningPublicKey returns the Ed25519 public key for signature verification.
// This allows verification of signatures without needing the private key.
// Returns nil if no Ed25519 keypair is available.
func (dest *Destination) SigningPublicKey() *Ed25519KeyPair {
	if dest.sgk.ed25519KeyPair != nil {
		// Return a copy with only the public key (no private key)
		return &Ed25519KeyPair{
			algorithmType: dest.sgk.ed25519KeyPair.algorithmType,
			publicKey:     dest.sgk.ed25519KeyPair.publicKey,
			// privateKey is intentionally nil for verification-only use
		}
	}
	return nil
}

// VerifySignature verifies a signature against the given message using this destination's
// signing public key. This is useful for offline signature verification without access
// to the private key.
//
// Returns true if the signature is valid, false otherwise.
func (dest *Destination) VerifySignature(message, signature []byte) bool {
	signingKey := dest.SigningPublicKey()
	if signingKey == nil {
		return false
	}
	return signingKey.Verify(message, signature)
}

// Hash returns the SHA-256 hash of the destination's canonical wire format serialization.
// This matches Java I2P's Destination.calculateHash() method.
//
// The hash is computed over the wire format (WriteToMessage):
//   - pubKey: 256 bytes (encryption public key)
//   - signingPubKey: 128 bytes (Ed25519 key right-aligned at bytes 96-127)
//   - certificate: 7+ bytes (KEY certificate with sig/crypto type)
//
// USE CASES:
//   - Datagram2: Target destination hash for replay prevention
//   - Datagram3: Sender's fromhash for repliability
//   - LeaseSet addressing and lookup
//   - Any protocol requiring canonical destination identification
//
// INTEROPERABILITY: This produces the same hash as Java I2P's calculateHash(),
// enabling cross-implementation compatibility for datagram protocols.
//
// Returns the 32-byte SHA-256 hash, or a zero hash if serialization fails.
func (dest *Destination) Hash() [32]byte {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	if err := dest.WriteToMessage(stream); err != nil {
		Error("Failed to serialize destination for hash: %v", err)
		return [32]byte{}
	}
	return sha256.Sum256(stream.Bytes())
}
