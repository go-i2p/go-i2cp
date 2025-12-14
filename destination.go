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

	// Modern I2CP uses KEY certificates with Ed25519 (signing) + X25519 (encryption)
	// Certificate format: [type=5][length=4][sigType=7 (2 bytes)][cryptoType=4 (2 bytes)]
	// KEY certificate payload: signingKeyType (2 bytes) + encryptionKeyType (2 bytes)
	keyCertPayload := []byte{
		0, 7, // Signing key type: Ed25519 (7)
		0, 4, // Encryption key type: ECIES-X25519 (4)
	}
	commonCert, err := certificate.NewCertificateWithType(CERTIFICATE_KEY, keyCertPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEY certificate: %w", err)
	}
	keyCert := Certificate{cert: commonCert, certType: CERTIFICATE_KEY, length: 4, data: keyCertPayload}
	dest.cert = &keyCert

	// Generate Ed25519 signing keypair (fast, modern)
	dest.sgk, err = crypto.SignatureKeygen(ED25519_SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 signature keypair: %w", err)
	}

	// Generate X25519 encryption keypair (ECIES)
	x25519Kp, err := crypto.X25519KeyExchangeKeygen()
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 encryption keypair: %w", err)
	}

	// For KEY certificates, pubKey contains X25519 public key (32 bytes)
	// Copy to first 32 bytes, rest stays zero for compatibility
	x25519PubKey := x25519Kp.PublicKey()
	copy(dest.pubKey[:32], x25519PubKey[:])

	dest.generateB32()
	dest.generateB64()
	return
}

// NewDestinationFromMessage reads a destination from an I2CP message stream.
// NOTE: This function supports Ed25519 destinations with KEY certificates only.
// Legacy DSA destinations are no longer supported.
func NewDestinationFromMessage(stream *Stream, crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}

	// Read encryption public key (256 bytes, first 32 are X25519)
	_, err = stream.Read(dest.pubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	// Read signing public key (128 bytes for I2CP compatibility, but Ed25519 is only 32)
	// The Ed25519 public key is right-aligned in the 128-byte field
	signingKeyPadded := make([]byte, 128)
	_, err = stream.Read(signingKeyPadded)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key: %w", err)
	}

	// Read certificate
	var cert Certificate
	cert, err = NewCertificateFromMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	dest.cert = &cert

	// For Ed25519 (in KEY certificates), extract the 32-byte public key from right side
	// Create a Ed25519KeyPair with just the public key for verification
	if cert.certType == CERTIFICATE_KEY {
		// Extract Ed25519 public key (last 32 bytes of the 128-byte field)
		ed25519PubKeyBytes := signingKeyPadded[96:128]

		// Create public key using crypto package
		ed25519PubKey, err := cryptoed25519.CreateEd25519PublicKeyFromBytes(ed25519PubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to create Ed25519 public key: %w", err)
		}

		dest.sgk = SignatureKeyPair{
			algorithmType: ED25519_SHA256,
			ed25519KeyPair: &Ed25519KeyPair{
				algorithmType: ED25519_SHA256,
				publicKey:     ed25519PubKey,
			},
		}
	} else {
		return nil, fmt.Errorf("unsupported certificate type: %d (only KEY certificates with Ed25519 supported)", cert.certType)
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
	return &cert, nil
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

func (dest *Destination) WriteToMessage(stream *Stream) (err error) {
	// Write encryption public key (256 bytes)
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// I2CP Destination format ALWAYS uses 128-byte signing key field
	// Per Java I2P Destination.java: pubKey(256) + signingPubKey(128) + certificate
	// Even for Ed25519 (32 bytes), we must pad to 128 bytes for I2CP compatibility
	// Ed25519 public key is right-aligned in the 128-byte field
	paddedSignKey := make([]byte, 128)
	if dest.sgk.ed25519KeyPair != nil {
		ed25519PubKey := dest.sgk.ed25519KeyPair.PublicKey()
		copy(paddedSignKey[96:], ed25519PubKey[:]) // Right-align 32-byte key in 128-byte field
	} else {
		return fmt.Errorf("no Ed25519 keypair available")
	}

	if _, err = stream.Write(paddedSignKey); err != nil {
		return fmt.Errorf("failed to write signing public key: %w", err)
	}

	// Write certificate
	if err = dest.cert.WriteToMessage(stream); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

func (dest *Destination) WriteToStream(stream *Stream) (err error) {
	// Write certificate
	if err = dest.cert.WriteToStream(stream); err != nil {
		return fmt.Errorf("failed to write certificate to stream: %w", err)
	}

	// Write algorithm type
	if err = stream.WriteUint32(ED25519_SHA256); err != nil {
		return fmt.Errorf("failed to write algorithm type: %w", err)
	}

	// Write Ed25519 keypair (32 bytes private + 32 bytes public)
	if dest.sgk.ed25519KeyPair != nil {
		privKey := dest.sgk.ed25519KeyPair.PrivateKey()
		pubKey := dest.sgk.ed25519KeyPair.PublicKey()
		if _, err = stream.Write(privKey[:]); err != nil {
			return fmt.Errorf("failed to write Ed25519 private key: %w", err)
		}
		if _, err = stream.Write(pubKey[:]); err != nil {
			return fmt.Errorf("failed to write Ed25519 public key: %w", err)
		}
	} else {
		return fmt.Errorf("no Ed25519 keypair available")
	}

	// Write encryption public key length
	if err = stream.WriteUint16(PUB_KEY_SIZE); err != nil {
		return fmt.Errorf("failed to write public key size: %w", err)
	}

	// Write encryption public key
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
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
