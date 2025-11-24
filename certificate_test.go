package go_i2cp

import (
	"testing"

	"github.com/go-i2p/common/certificate"
)

// TestCertificateMigration tests that the migrated Certificate wrapper
// correctly delegates to common/certificate while maintaining backward compatibility
func TestCertificateMigration(t *testing.T) {
	t.Run("NewCertificate creates null certificate", func(t *testing.T) {
		cert := NewCertificate(CERTIFICATE_NULL)

		if cert.cert == nil {
			t.Fatal("Expected cert.cert to be initialized")
		}

		// Verify the certificate can be written to a stream
		stream := NewStream(make([]byte, 0, 100))
		if err := cert.WriteToMessage(stream); err != nil {
			t.Fatalf("Failed to write certificate: %v", err)
		}

		// Verify it wrote the correct format: [type:1][length:2]
		bytes := stream.Bytes()
		if len(bytes) < 3 {
			t.Fatalf("Expected at least 3 bytes, got %d", len(bytes))
		}
		if bytes[0] != CERTIFICATE_NULL {
			t.Errorf("Expected certificate type %d, got %d", CERTIFICATE_NULL, bytes[0])
		}
		// Length should be 0 for null certificate
		if bytes[1] != 0 || bytes[2] != 0 {
			t.Errorf("Expected length 0 for null certificate, got %d", int(bytes[1])<<8|int(bytes[2]))
		}
	})

	t.Run("NewCertificateFromMessage reads certificate", func(t *testing.T) {
		// Create a stream with a null certificate
		stream := NewStream([]byte{CERTIFICATE_NULL, 0x00, 0x00})

		cert, err := NewCertificateFromMessage(stream)
		if err != nil {
			t.Fatalf("Failed to read certificate: %v", err)
		}

		if cert.cert == nil {
			t.Fatal("Expected cert.cert to be initialized")
		}

		// Verify legacy fields are populated
		if cert.certType != CERTIFICATE_NULL {
			t.Errorf("Expected certType %d, got %d", CERTIFICATE_NULL, cert.certType)
		}
		if cert.length != 0 {
			t.Errorf("Expected length 0, got %d", cert.length)
		}
	})

	t.Run("Round-trip certificate through stream", func(t *testing.T) {
		// Create a certificate
		original := NewCertificate(CERTIFICATE_NULL)

		// Write to stream
		writeStream := NewStream(make([]byte, 0, 100))
		if err := original.WriteToMessage(writeStream); err != nil {
			t.Fatalf("Failed to write certificate: %v", err)
		}

		// Read it back
		readStream := NewStream(writeStream.Bytes())
		decoded, err := NewCertificateFromMessage(readStream)
		if err != nil {
			t.Fatalf("Failed to read certificate: %v", err)
		}

		// Verify they match
		if decoded.certType != original.certType {
			t.Errorf("Certificate type mismatch: got %d, want %d", decoded.certType, original.certType)
		}
		if decoded.length != original.length {
			t.Errorf("Certificate length mismatch: got %d, want %d", decoded.length, original.length)
		}
	})

	t.Run("Copy creates independent certificate", func(t *testing.T) {
		original := NewCertificate(CERTIFICATE_NULL)
		copied := original.Copy()

		if copied.cert == nil {
			t.Fatal("Expected copied cert.cert to be initialized")
		}

		// Verify they have the same values
		if copied.certType != original.certType {
			t.Errorf("Certificate type mismatch: got %d, want %d", copied.certType, original.certType)
		}

		// Verify they are independent by writing each to a stream
		origStream := NewStream(make([]byte, 0, 100))
		copiedStream := NewStream(make([]byte, 0, 100))

		if err := original.WriteToMessage(origStream); err != nil {
			t.Fatalf("Failed to write original: %v", err)
		}
		if err := copied.WriteToMessage(copiedStream); err != nil {
			t.Fatalf("Failed to write copied: %v", err)
		}

		// Verify the bytes are identical
		origBytes := origStream.Bytes()
		copiedBytes := copiedStream.Bytes()
		if len(origBytes) != len(copiedBytes) {
			t.Fatalf("Byte length mismatch: original %d, copied %d", len(origBytes), len(copiedBytes))
		}
		for i := range origBytes {
			if origBytes[i] != copiedBytes[i] {
				t.Errorf("Byte mismatch at index %d: original %d, copied %d", i, origBytes[i], copiedBytes[i])
			}
		}
	})

	t.Run("WriteToStream is alias for WriteToMessage", func(t *testing.T) {
		cert := NewCertificate(CERTIFICATE_NULL)

		stream1 := NewStream(make([]byte, 0, 100))
		stream2 := NewStream(make([]byte, 0, 100))

		if err := cert.WriteToMessage(stream1); err != nil {
			t.Fatalf("WriteToMessage failed: %v", err)
		}
		if err := cert.WriteToStream(stream2); err != nil {
			t.Fatalf("WriteToStream failed: %v", err)
		}

		bytes1 := stream1.Bytes()
		bytes2 := stream2.Bytes()

		if len(bytes1) != len(bytes2) {
			t.Fatalf("Length mismatch: WriteToMessage %d, WriteToStream %d", len(bytes1), len(bytes2))
		}
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				t.Errorf("Byte mismatch at index %d: WriteToMessage %d, WriteToStream %d", i, bytes1[i], bytes2[i])
			}
		}
	})

	t.Run("NewCertificateFromStream is alias for NewCertificateFromMessage", func(t *testing.T) {
		data := []byte{CERTIFICATE_NULL, 0x00, 0x00}

		stream1 := NewStream(data)
		stream2 := NewStream(data)

		cert1, err1 := NewCertificateFromMessage(stream1)
		cert2, err2 := NewCertificateFromStream(stream2)

		if err1 != nil {
			t.Fatalf("NewCertificateFromMessage failed: %v", err1)
		}
		if err2 != nil {
			t.Fatalf("NewCertificateFromStream failed: %v", err2)
		}

		if cert1.certType != cert2.certType {
			t.Errorf("Certificate type mismatch: FromMessage %d, FromStream %d", cert1.certType, cert2.certType)
		}
		if cert1.length != cert2.length {
			t.Errorf("Certificate length mismatch: FromMessage %d, FromStream %d", cert1.length, cert2.length)
		}
	})

	t.Run("Integration with common/certificate", func(t *testing.T) {
		// Create a certificate using the common package directly
		commonCert, err := certificate.NewCertificateWithType(CERTIFICATE_NULL, nil)
		if err != nil {
			t.Fatalf("Failed to create common certificate: %v", err)
		}

		// Get its bytes
		commonBytes := commonCert.Bytes()

		// Create our wrapper certificate
		wrapperCert := NewCertificate(CERTIFICATE_NULL)
		wrapperStream := NewStream(make([]byte, 0, 100))
		if err := wrapperCert.WriteToMessage(wrapperStream); err != nil {
			t.Fatalf("Failed to write wrapper certificate: %v", err)
		}
		wrapperBytes := wrapperStream.Bytes()

		// Verify they produce identical byte representations
		if len(commonBytes) != len(wrapperBytes) {
			t.Errorf("Byte length mismatch: common %d, wrapper %d", len(commonBytes), len(wrapperBytes))
		}
		for i := range commonBytes {
			if i < len(wrapperBytes) && commonBytes[i] != wrapperBytes[i] {
				t.Errorf("Byte mismatch at index %d: common %d, wrapper %d", i, commonBytes[i], wrapperBytes[i])
			}
		}
	})
}

// TestCertificateBackwardCompatibility ensures that existing code
// using the Certificate struct still works correctly
func TestCertificateBackwardCompatibility(t *testing.T) {
	t.Run("Destination still works with migrated Certificate", func(t *testing.T) {
		crypto := NewCrypto()
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		// Verify the destination has a valid certificate
		if dest.cert == nil {
			t.Fatal("Expected destination to have a certificate")
		}

		// Verify we can write the destination to a stream (which includes the certificate)
		stream := NewStream(make([]byte, 0, DEST_SIZE))
		if err := dest.WriteToMessage(stream); err != nil {
			t.Fatalf("Failed to write destination: %v", err)
		}

		// Verify we can read it back
		readStream := NewStream(stream.Bytes())
		destRead, err := NewDestinationFromMessage(readStream, crypto)
		if err != nil {
			t.Fatalf("Failed to read destination: %v", err)
		}

		// Verify the certificate survived the round-trip
		if destRead.cert == nil {
			t.Fatal("Expected read destination to have a certificate")
		}
		if destRead.cert.certType != CERTIFICATE_NULL {
			t.Errorf("Expected certificate type %d, got %d", CERTIFICATE_NULL, destRead.cert.certType)
		}
	})
}
