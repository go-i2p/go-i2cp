package go_i2cp

import (
	"fmt"

	"github.com/go-i2p/common/certificate"
)

// Certificate wraps the common/certificate.Certificate type to maintain
// backward compatibility with existing I2CP code while delegating
// certificate operations to the shared common package.
type Certificate struct {
	// Embed the common certificate for delegation
	cert *certificate.Certificate
	// Legacy fields for backward compatibility (deprecated)
	certType uint8
	data     []byte
	length   uint16
}

// NewCertificate creates a new Certificate with the specified type.
// This maintains backward compatibility with the old API.
func NewCertificate(typ uint8) (cert Certificate) {
	// Create certificate using common package
	commonCert, err := certificate.NewCertificateWithType(typ, nil)
	if err != nil {
		// For null certificates, this should never error
		// but we handle it gracefully
		Error(fmt.Sprintf("%08x", tag), "Failed to create certificate: %v", err)
		return Certificate{}
	}
	cert.cert = commonCert
	// Populate legacy fields for backward compatibility
	cert.certType = typ
	cert.length = 0
	return
}

// NewCertificateFromMessage reads a Certificate from an I2CP message stream.
// This maintains backward compatibility while using common/certificate internally.
func NewCertificateFromMessage(stream *Stream) (cert Certificate, err error) {
	// Read the certificate bytes from the stream
	// Certificate format: [type:1][length:2][data:length]
	var certType uint8
	var length uint16

	certType, err = stream.ReadByte()
	if err != nil {
		return
	}
	length, err = stream.ReadUint16()
	if err != nil {
		return
	}

	// Validation: null certificates must have zero length
	if (certType != CERTIFICATE_NULL) && (length == 0) {
		Fatal(fmt.Sprintf("%08x", CERTIFICATE|PROTOCOL), "Non-null certificates must have non-zero length.")
		return
	}

	// Build the complete certificate bytes for common package
	certBytes := make([]byte, 3+length)
	certBytes[0] = certType
	certBytes[1] = byte(length >> 8)
	certBytes[2] = byte(length)

	if length > 0 {
		_, err = stream.Read(certBytes[3:])
		if err != nil {
			return
		}
	}

	// Parse using common/certificate
	commonCert, _, err := certificate.ReadCertificate(certBytes)
	if err != nil {
		return
	}

	cert.cert = &commonCert
	// Populate legacy fields for backward compatibility
	cert.certType = certType
	cert.length = length
	if length > 0 {
		cert.data = certBytes[3:]
	}
	return
}

// NewCertificateFromStream is an alias for NewCertificateFromMessage.
func NewCertificateFromStream(stream *Stream) (Certificate, error) {
	return NewCertificateFromMessage(stream)
}

// Copy creates a deep copy of the Certificate.
func (cert *Certificate) Copy() (newCert Certificate) {
	if cert.cert != nil {
		// Copy using common certificate's bytes
		certBytes := cert.cert.Bytes()
		commonCert, _, _ := certificate.ReadCertificate(certBytes)
		newCert.cert = &commonCert
	}
	// Copy legacy fields
	newCert.certType = cert.certType
	newCert.length = cert.length
	if len(cert.data) > 0 {
		newCert.data = make([]byte, len(cert.data))
		copy(newCert.data, cert.data)
	}
	return
}

// WriteToMessage writes the Certificate to an I2CP message stream.
func (cert *Certificate) WriteToMessage(stream *Stream) (err error) {
	if cert.cert != nil {
		// Use common certificate's Bytes() method
		certBytes := cert.cert.Bytes()
		_, err = stream.Write(certBytes)
		return
	}
	// Fallback to legacy fields if common cert is not set
	err = stream.WriteByte(cert.certType)
	if err != nil {
		return
	}
	err = stream.WriteUint16(cert.length)
	if err != nil {
		return
	}
	if cert.length > 0 {
		_, err = stream.Write(cert.data)
	}
	return
}

// WriteToStream is an alias for WriteToMessage.
func (cert *Certificate) WriteToStream(stream *Stream) error {
	return cert.WriteToMessage(stream)
}
