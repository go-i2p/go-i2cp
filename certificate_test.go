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

		if cert == nil {
			t.Fatal("Expected cert to be initialized")
		}

		// Verify the certificate can be written to a stream
		stream := NewStream(make([]byte, 0, 100))
		if err := WriteCertificateToMessage(cert, stream); err != nil {
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

		if cert == nil {
			t.Fatal("Expected cert to be initialized")
		}

		// Verify certificate fields
		if CertType(cert) != CERTIFICATE_NULL {
			t.Errorf("Expected certType %d, got %d", CERTIFICATE_NULL, CertType(cert))
		}
		if CertLength(cert) != 0 {
			t.Errorf("Expected length 0, got %d", CertLength(cert))
		}
	})

	t.Run("Round-trip certificate through stream", func(t *testing.T) {
		// Create a certificate
		original := NewCertificate(CERTIFICATE_NULL)

		// Write to stream
		writeStream := NewStream(make([]byte, 0, 100))
		if err := WriteCertificateToMessage(original, writeStream); err != nil {
			t.Fatalf("Failed to write certificate: %v", err)
		}

		// Read it back
		readStream := NewStream(writeStream.Bytes())
		decoded, err := NewCertificateFromMessage(readStream)
		if err != nil {
			t.Fatalf("Failed to read certificate: %v", err)
		}

		// Verify they match
		if CertType(decoded) != CertType(original) {
			t.Errorf("Certificate type mismatch: got %d, want %d", CertType(decoded), CertType(original))
		}
		if CertLength(decoded) != CertLength(original) {
			t.Errorf("Certificate length mismatch: got %d, want %d", CertLength(decoded), CertLength(original))
		}
	})

	t.Run("Copy creates independent certificate", func(t *testing.T) {
		original := NewCertificate(CERTIFICATE_NULL)
		copied := CopyCertificate(original)

		if copied == nil {
			t.Fatal("Expected copied cert to be initialized")
		}

		// Verify they have the same values
		if CertType(copied) != CertType(original) {
			t.Errorf("Certificate type mismatch: got %d, want %d", CertType(copied), CertType(original))
		}

		// Verify they are independent by writing each to a stream
		origStream := NewStream(make([]byte, 0, 100))
		copiedStream := NewStream(make([]byte, 0, 100))

		if err := WriteCertificateToMessage(original, origStream); err != nil {
			t.Fatalf("Failed to write original: %v", err)
		}
		if err := WriteCertificateToMessage(copied, copiedStream); err != nil {
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

		if err := WriteCertificateToMessage(cert, stream1); err != nil {
			t.Fatalf("WriteToMessage failed: %v", err)
		}
		if err := WriteCertificateToStream(cert, stream2); err != nil {
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

		if CertType(cert1) != CertType(cert2) {
			t.Errorf("Certificate type mismatch: FromMessage %d, FromStream %d", CertType(cert1), CertType(cert2))
		}
		if CertLength(cert1) != CertLength(cert2) {
			t.Errorf("Certificate length mismatch: FromMessage %d, FromStream %d", CertLength(cert1), CertLength(cert2))
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
		if err := WriteCertificateToMessage(wrapperCert, wrapperStream); err != nil {
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
		if CertType(destRead.cert) != CERTIFICATE_KEY {
			t.Errorf("Expected certificate type %d (KEY), got %d", CERTIFICATE_KEY, CertType(destRead.cert))
		}
	})
}

// TestCertificate_WriteCertificateToMessage tests the WriteCertificateToMessage helper function
func TestCertificate_WriteCertificateToMessage(t *testing.T) {
	t.Run("Null certificate", func(t *testing.T) {
		cert := NewCertificate(CERTIFICATE_NULL)

		stream := NewStream(make([]byte, 0, 100))
		if err := WriteCertificateToMessage(cert, stream); err != nil {
			t.Fatalf("WriteCertificateToMessage failed: %v", err)
		}

		bytes := stream.Bytes()
		if len(bytes) != 3 {
			t.Fatalf("Expected 3 bytes (type + length), got %d", len(bytes))
		}
		if bytes[0] != CERTIFICATE_NULL {
			t.Errorf("Expected type %d, got %d", CERTIFICATE_NULL, bytes[0])
		}
		length := uint16(bytes[1])<<8 | uint16(bytes[2])
		if length != 0 {
			t.Errorf("Expected length 0, got %d", length)
		}
	})

	t.Run("Certificate with data", func(t *testing.T) {
		testData := []byte{0x01, 0x02, 0x03, 0x04}
		cert, err := certificate.NewCertificateWithType(5, testData)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		stream := NewStream(make([]byte, 0, 100))
		if err := WriteCertificateToMessage(cert, stream); err != nil {
			t.Fatalf("WriteCertificateToMessage failed: %v", err)
		}

		bytes := stream.Bytes()
		expectedLen := 1 + 2 + len(testData)
		if len(bytes) != expectedLen {
			t.Fatalf("Expected %d bytes, got %d", expectedLen, len(bytes))
		}

		if bytes[0] != 5 {
			t.Errorf("Expected type 5, got %d", bytes[0])
		}

		length := uint16(bytes[1])<<8 | uint16(bytes[2])
		if length != uint16(len(testData)) {
			t.Errorf("Expected length %d, got %d", len(testData), length)
		}

		data := bytes[3:]
		for i := range testData {
			if data[i] != testData[i] {
				t.Errorf("Data mismatch at index %d: expected %d, got %d", i, testData[i], data[i])
			}
		}
	})

	t.Run("Nil certificate writes null", func(t *testing.T) {
		stream := NewStream(make([]byte, 0, 100))
		if err := WriteCertificateToMessage(nil, stream); err != nil {
			t.Fatalf("WriteCertificateToMessage failed: %v", err)
		}

		bytes := stream.Bytes()
		if len(bytes) != 3 {
			t.Fatalf("Expected 3 bytes, got %d", len(bytes))
		}
		if bytes[0] != CERTIFICATE_NULL {
			t.Errorf("Expected type %d, got %d", CERTIFICATE_NULL, bytes[0])
		}
	})

	t.Run("WriteCertificateToStream matches WriteCertificateToMessage", func(t *testing.T) {
		cert := NewCertificate(CERTIFICATE_NULL)

		stream1 := NewStream(make([]byte, 0, 100))
		stream2 := NewStream(make([]byte, 0, 100))

		if err := WriteCertificateToMessage(cert, stream1); err != nil {
			t.Fatalf("WriteCertificateToMessage failed: %v", err)
		}
		if err := WriteCertificateToStream(cert, stream2); err != nil {
			t.Fatalf("WriteCertificateToStream failed: %v", err)
		}

		bytes1 := stream1.Bytes()
		bytes2 := stream2.Bytes()

		if len(bytes1) != len(bytes2) {
			t.Fatalf("Length mismatch: %d vs %d", len(bytes1), len(bytes2))
		}
		for i := range bytes1 {
			if bytes1[i] != bytes2[i] {
				t.Errorf("Byte mismatch at index %d", i)
			}
		}
	})
}
