package go_i2cp

import (
	"github.com/go-i2p/common/certificate"
)

// Certificate is a type alias for certificate.Certificate from the common package.
// All certificate operations (Type, Length, Data, Bytes, IsValid) are provided
// by the common package. I2CP-specific stream helpers are defined as package functions.
type Certificate = certificate.Certificate

// NewCertificate creates a new Certificate with the specified type using the common package.
func NewCertificate(typ uint8) *Certificate {
	commonCert, err := certificate.NewCertificateWithType(typ, nil)
	if err != nil {
		Error("Failed to create certificate: %v", err)
		return certificate.NewCertificate() // fallback to null
	}
	return commonCert
}

// NewCertificateFromMessage reads a Certificate from an I2CP message stream.
// Uses common/certificate.ReadCertificate for parsing.
func NewCertificateFromMessage(stream *Stream) (*Certificate, error) {
	certType, length, err := readCertificateHeader(stream)
	if err != nil {
		return nil, err
	}

	if err = validateCertificateFormat(certType, length); err != nil {
		return nil, err
	}

	certBytes, err := buildCertificateBytes(stream, certType, length)
	if err != nil {
		return nil, err
	}

	commonCert, _, err := certificate.ReadCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return commonCert, nil
}

// readCertificateHeader reads the certificate type and length from the stream.
// Certificate format: [type:1][length:2][data:length]
func readCertificateHeader(stream *Stream) (certType uint8, length uint16, err error) {
	certType, err = stream.ReadByte()
	if err != nil {
		return
	}
	length, err = stream.ReadUint16()
	return
}

// validateCertificateFormat ensures non-null certificates have non-zero length.
func validateCertificateFormat(certType uint8, length uint16) error {
	if (certType != CERTIFICATE_NULL) && (length == 0) {
		Fatal("Non-null certificates must have non-zero length.")
		return ErrMessageParsing
	}
	return nil
}

// buildCertificateBytes constructs the complete certificate byte array for parsing.
func buildCertificateBytes(stream *Stream, certType uint8, length uint16) ([]byte, error) {
	certBytes := make([]byte, 3+length)
	certBytes[0] = certType
	certBytes[1] = byte(length >> 8)
	certBytes[2] = byte(length)

	if length > 0 {
		_, err := stream.Read(certBytes[3:])
		if err != nil {
			return nil, err
		}
	}
	return certBytes, nil
}

// NewCertificateFromStream is an alias for NewCertificateFromMessage.
func NewCertificateFromStream(stream *Stream) (*Certificate, error) {
	return NewCertificateFromMessage(stream)
}

// CopyCertificate creates a deep copy of a Certificate by re-parsing its bytes.
func CopyCertificate(cert *Certificate) *Certificate {
	if cert == nil {
		return nil
	}
	certBytes := cert.Bytes()
	copied, _, err := certificate.ReadCertificate(certBytes)
	if err != nil {
		return nil
	}
	return copied
}

// WriteCertificateToMessage writes a Certificate to an I2CP message stream.
func WriteCertificateToMessage(cert *Certificate, stream *Stream) error {
	if cert == nil {
		if err := stream.WriteByte(CERTIFICATE_NULL); err != nil {
			return err
		}
		return stream.WriteUint16(0)
	}
	certBytes := cert.Bytes()
	_, err := stream.Write(certBytes)
	return err
}

// WriteCertificateToStream is an alias for WriteCertificateToMessage.
func WriteCertificateToStream(cert *Certificate, stream *Stream) error {
	return WriteCertificateToMessage(cert, stream)
}

// CertType is a helper that returns the certificate type as uint8.
// Returns 0 (CERTIFICATE_NULL) if type extraction fails.
func CertType(cert *Certificate) uint8 {
	if cert == nil {
		return CERTIFICATE_NULL
	}
	t, err := cert.Type()
	if err != nil {
		return CERTIFICATE_NULL
	}
	return uint8(t)
}

// CertLength is a helper that returns the certificate data length as uint16.
// Returns 0 if length extraction fails.
func CertLength(cert *Certificate) uint16 {
	if cert == nil {
		return 0
	}
	l, err := cert.Length()
	if err != nil {
		return 0
	}
	return uint16(l)
}
