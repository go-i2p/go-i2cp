package go_i2cp

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type Destination struct {
	cert       *Certificate
	sgk        SignatureKeyPair
	signPubKey *big.Int
	pubKey     [PUB_KEY_SIZE]byte
	digest     [DIGEST_SIZE]byte
	b32        string
	b64        string
	crypto     *Crypto
}

func NewDestination(crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}
	nullCert := NewCertificate(CERTIFICATE_NULL)
	dest.cert = &nullCert
	dest.sgk, err = crypto.SignatureKeygen(DSA_SHA1)
	dest.signPubKey = dest.sgk.pub.Y
	dest.generateB32()
	dest.generateB64()
	return
}

func NewDestinationFromMessage(stream *Stream, crypto *Crypto) (dest *Destination, err error) {
	dest = &Destination{crypto: crypto}
	_, err = stream.Read(dest.pubKey[:])
	if err != nil {
		return
	}
	dest.signPubKey, err = crypto.PublicKeyFromStream(DSA_SHA1, stream)
	if err != nil {
		return
	}
	dest.sgk = SignatureKeyPair{}
	dest.sgk.priv.Y = dest.signPubKey
	dest.sgk.pub.Y = dest.signPubKey
	var cert Certificate
	cert, err = NewCertificateFromMessage(stream)
	if err != nil {
		return
	}
	dest.cert = &cert
	dest.generateB32()
	dest.generateB64()
	return dest, err
}

func NewDestinationFromStream(stream *Stream, crypto *Crypto) (dest *Destination, err error) {
	var cert Certificate
	var pubKeyLen uint16
	dest = &Destination{crypto: crypto}
	cert, err = NewCertificateFromStream(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	dest.cert = &cert
	dest.sgk, err = crypto.SignatureKeyPairFromStream(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature keypair: %w", err)
	}
	dest.signPubKey = dest.sgk.pub.Y
	pubKeyLen, err = stream.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read public key length: %w", err)
	}
	if pubKeyLen != PUB_KEY_SIZE {
		return nil, fmt.Errorf("invalid public key length: got %d, expected %d", pubKeyLen, PUB_KEY_SIZE)
	}
	_, err = stream.Read(dest.pubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}
	dest.generateB32()
	dest.generateB64()
	return
}

func NewDestinationFromBase64(base64 string, crypto *Crypto) (dest *Destination, err error) {
	/* Same as decode, except from a filesystem / URL friendly set of characters,
	*  replacing / with ~, and + with -
	 */
	// see https://javadoc.freenetproject.org/freenet/support/Base64.html
	if len(base64) == 0 {
		err = errors.New("empty string")
		return
	}
	var replaced string
	// Convert from freenet to standard
	replaced = strings.Replace(base64, "~", "/", -1)
	replaced = strings.Replace(replaced, "-", "+", -1)
	stream := NewStream([]byte(replaced))
	var decoded *Stream
	decoded, err = crypto.DecodeStream(CODEC_BASE64, stream)
	return NewDestinationFromMessage(decoded, crypto)
}

func NewDestinationFromFile(file *os.File, crypto *Crypto) (*Destination, error) {
	var stream Stream
	stream.loadFile(file)
	return NewDestinationFromStream(&stream, crypto)
}

func (dest *Destination) Copy() (newDest Destination) {
	newDest.cert = dest.cert
	newDest.signPubKey = dest.signPubKey
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
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	// Pad signing public key to exactly 128 bytes (DSA_SHA1_PUB_KEY_SIZE)
	// big.Int.Bytes() returns minimal representation without leading zeros
	signKeyBytes := dest.signPubKey.Bytes()
	paddedSignKey := make([]byte, DSA_SHA1_PUB_KEY_SIZE)
	copy(paddedSignKey[DSA_SHA1_PUB_KEY_SIZE-len(signKeyBytes):], signKeyBytes)
	if _, err = stream.Write(paddedSignKey); err != nil {
		return fmt.Errorf("failed to write signing public key: %w", err)
	}
	if err = dest.cert.WriteToMessage(stream); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	return nil
}

func (dest *Destination) WriteToStream(stream *Stream) (err error) {
	if err = dest.cert.WriteToStream(stream); err != nil {
		return fmt.Errorf("failed to write certificate to stream: %w", err)
	}
	if err = dest.crypto.WriteSignatureToStream(&dest.sgk, stream); err != nil {
		return fmt.Errorf("failed to write signature to stream: %w", err)
	}
	if err = stream.WriteUint16(PUB_KEY_SIZE); err != nil {
		return fmt.Errorf("failed to write public key size: %w", err)
	}
	if _, err = stream.Write(dest.pubKey[:]); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	return nil
}

// Doesn't seem to be used anywhere??
func (dest *Destination) Verify() (verified bool, err error) {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	if err = dest.WriteToMessage(stream); err != nil {
		return false, fmt.Errorf("failed to write destination to message: %w", err)
	}
	if _, err = stream.Write(dest.digest[:]); err != nil {
		return false, fmt.Errorf("failed to write digest: %w", err)
	}
	return dest.crypto.VerifyStream(&dest.sgk, stream)
}

func (dest *Destination) generateB32() {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	// WriteToMessage errors are not expected in normal operation since we're writing to a memory buffer
	// If it fails, the b32 address will be incomplete, but this is logged for debugging
	if err := dest.WriteToMessage(stream); err != nil {
		Error(tag, "Failed to generate b32 address: %v", err)
		return
	}
	hash := dest.crypto.HashStream(HASH_SHA256, stream)
	b32 := dest.crypto.EncodeStream(CODEC_BASE32, hash)
	dest.b32 = b32.String()
	dest.b32 += ".b32.i2p"
	Debug(tag, "New destination %s", dest.b32)
}

func (dest *Destination) generateB64() {
	stream := NewStream(make([]byte, 0, DEST_SIZE))
	// WriteToMessage errors are not expected in normal operation since we're writing to a memory buffer
	// If it fails, the b64 address will be incomplete, but this is logged for debugging
	if err := dest.WriteToMessage(stream); err != nil {
		Error(tag, "Failed to generate b64 address: %v", err)
		return
	}
	if stream.Len() > 0 {
		fmt.Printf("Stream len %d \n", stream.Len())
	}
	b64B := dest.crypto.EncodeStream(CODEC_BASE64, stream)
	replaced := strings.Replace(b64B.String(), "/", "~", -1)
	replaced = strings.Replace(replaced, "/", "~", -1)
	dest.b64 = replaced
}
