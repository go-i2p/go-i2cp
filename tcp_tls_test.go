package go_i2cp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSelfSignedCert generates a self-signed certificate for testing
// Returns certPEM, keyPEM, and any error encountered
func generateSelfSignedCert() ([]byte, []byte, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"I2CP Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// TestSetupTLS_BasicConfiguration tests basic TLS configuration without certificates
func TestSetupTLS_BasicConfiguration(t *testing.T) {
	tcp := &Tcp{}

	err := tcp.SetupTLS("", "", "", false)
	if err != nil {
		t.Fatalf("SetupTLS with no certificates failed: %v", err)
	}

	if tcp.tlsConfig == nil {
		t.Fatal("tlsConfig should not be nil after SetupTLS")
	}

	if tcp.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", tcp.tlsConfig.MinVersion, tls.VersionTLS12)
	}

	if tcp.tlsConfig.InsecureSkipVerify != false {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

// TestSetupTLS_InsecureMode tests that insecure mode can be enabled
func TestSetupTLS_InsecureMode(t *testing.T) {
	tcp := &Tcp{}

	err := tcp.SetupTLS("", "", "", true)
	if err != nil {
		t.Fatalf("SetupTLS with insecure mode failed: %v", err)
	}

	if tcp.tlsConfig.InsecureSkipVerify != true {
		t.Error("InsecureSkipVerify should be true when insecure=true")
	}
}

// TestSetupTLS_WithCertificates tests loading client certificates
func TestSetupTLS_WithCertificates(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create temporary files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Test SetupTLS with certificates
	tcp := &Tcp{}
	err = tcp.SetupTLS(certFile, keyFile, "", false)
	if err != nil {
		t.Fatalf("SetupTLS with certificates failed: %v", err)
	}

	if len(tcp.tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tcp.tlsConfig.Certificates))
	}
}

// TestSetupTLS_WithCAFile tests loading CA certificate
func TestSetupTLS_WithCAFile(t *testing.T) {
	// Generate test CA certificate
	certPEM, _, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate test CA certificate: %v", err)
	}

	// Create temporary CA file
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	// Test SetupTLS with CA file
	tcp := &Tcp{}
	err = tcp.SetupTLS("", "", caFile, false)
	if err != nil {
		t.Fatalf("SetupTLS with CA file failed: %v", err)
	}

	if tcp.tlsConfig.RootCAs == nil {
		t.Error("RootCAs should not be nil after loading CA file")
	}
}

// TestSetupTLS_InvalidCertFile tests error handling for invalid certificate files
func TestSetupTLS_InvalidCertFile(t *testing.T) {
	tcp := &Tcp{}

	// Test with non-existent files
	err := tcp.SetupTLS("/nonexistent/cert.pem", "/nonexistent/key.pem", "", false)
	if err == nil {
		t.Error("Expected error with non-existent certificate files, got nil")
	}
}

// TestSetupTLS_InvalidCAFile tests error handling for invalid CA files
func TestSetupTLS_InvalidCAFile(t *testing.T) {
	tcp := &Tcp{}

	// Test with non-existent CA file
	err := tcp.SetupTLS("", "", "/nonexistent/ca.pem", false)
	if err == nil {
		t.Error("Expected error with non-existent CA file, got nil")
	}
}

// TestSetupTLS_MismatchedCertAndKey tests error when cert and key don't match
func TestSetupTLS_MismatchedCertAndKey(t *testing.T) {
	// Generate two different certificates
	certPEM1, _, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate first certificate: %v", err)
	}
	_, keyPEM2, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	// Create temporary files with mismatched cert and key
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	if err := os.WriteFile(certFile, certPEM1, 0o600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM2, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Test SetupTLS - should fail due to mismatch
	tcp := &Tcp{}
	err = tcp.SetupTLS(certFile, keyFile, "", false)
	if err == nil {
		t.Error("Expected error with mismatched certificate and key, got nil")
	}
}

// TestSetupTLS_OnlyCertProvided tests that only cert without key is ignored
func TestSetupTLS_OnlyCertProvided(t *testing.T) {
	certPEM, _, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	// Test with only certFile, no keyFile - should be ignored (both must be provided)
	tcp := &Tcp{}
	err = tcp.SetupTLS(certFile, "", "", false)
	if err != nil {
		t.Fatalf("SetupTLS should not error when only cert provided (both required): %v", err)
	}

	// No certificates should be loaded since both cert AND key are required
	if len(tcp.tlsConfig.Certificates) != 0 {
		t.Error("No certificates should be loaded when key is missing")
	}
}

// TestSetupTLS_SystemCertPool tests that system cert pool is used as fallback
func TestSetupTLS_SystemCertPool(t *testing.T) {
	tcp := &Tcp{}

	err := tcp.SetupTLS("", "", "", false)
	if err != nil {
		t.Fatalf("SetupTLS failed: %v", err)
	}

	// RootCAs should be set to system pool (non-nil)
	if tcp.tlsConfig.RootCAs == nil {
		t.Error("RootCAs should not be nil (system pool should be loaded)")
	}
}

// TestConnect_TLSWithConfig tests that Connect uses configured TLS settings
func TestConnect_TLSWithConfig(t *testing.T) {
	// This test verifies that tlsConfig is used when set
	// We can't actually connect without a real server, so we just verify
	// the configuration is properly set up

	tcp := &Tcp{}
	tcp.Init("127.0.0.1:7654") // Use default I2CP port

	err := tcp.SetupTLS("", "", "", true) // insecure mode for testing
	if err != nil {
		t.Fatalf("SetupTLS failed: %v", err)
	}

	if tcp.tlsConfig == nil {
		t.Fatal("tlsConfig should be set after SetupTLS")
	}

	if !tcp.tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true as configured")
	}

	// We don't call Connect() here because it would fail without a real server
	// The important part is verifying the configuration is set up correctly
}

// TestConnect_PlainTCP tests that plain TCP still works when TLS is not configured
func TestConnect_PlainTCP(t *testing.T) {
	// This test verifies that plain TCP connection path still works
	// We can't actually connect without a real server, so we just verify
	// the configuration allows plain TCP

	tcp := &Tcp{}
	tcp.Init("127.0.0.1:7654")

	// Ensure TLS is not configured
	if tcp.tlsConfig != nil {
		t.Error("tlsConfig should be nil for plain TCP connections")
	}

	// We don't call Connect() here because it would fail without a real server
}

// TestSetupTLS_MultipleCalls tests that SetupTLS can be called multiple times
func TestSetupTLS_MultipleCalls(t *testing.T) {
	tcp := &Tcp{}

	// First call - no TLS
	err := tcp.SetupTLS("", "", "", false)
	if err != nil {
		t.Fatalf("First SetupTLS failed: %v", err)
	}

	if tcp.tlsConfig.InsecureSkipVerify {
		t.Error("First call should have InsecureSkipVerify=false")
	}

	// Second call - enable insecure mode
	err = tcp.SetupTLS("", "", "", true)
	if err != nil {
		t.Fatalf("Second SetupTLS failed: %v", err)
	}

	if !tcp.tlsConfig.InsecureSkipVerify {
		t.Error("Second call should have InsecureSkipVerify=true")
	}
}

// TestSetupTLS_MinTLSVersion tests that minimum TLS version is enforced
func TestSetupTLS_MinTLSVersion(t *testing.T) {
	tcp := &Tcp{}

	err := tcp.SetupTLS("", "", "", false)
	if err != nil {
		t.Fatalf("SetupTLS failed: %v", err)
	}

	// Verify minimum TLS version is 1.2 per I2CP security requirements
	if tcp.tlsConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion %d is less than TLS 1.2 (%d)",
			tcp.tlsConfig.MinVersion, tls.VersionTLS12)
	}
}

// TestTcpStruct_FieldsExist tests that Tcp struct has expected fields
func TestTcpStruct_FieldsExist(t *testing.T) {
	tcp := &Tcp{}

	// Verify struct can be initialized with all fields
	tcp.address = nil
	tcp.conn = nil
	tcp.tlsConfig = nil
	tcp.properties = [NR_OF_TCP_PROPERTIES]string{}

	// This test will fail to compile if fields are missing or renamed
}

// TestSetupTLS_EmptyCertAndKeyIgnored tests that empty cert/key strings are ignored
func TestSetupTLS_EmptyCertAndKeyIgnored(t *testing.T) {
	tcp := &Tcp{}

	// Empty strings should be treated as "not provided"
	err := tcp.SetupTLS("", "", "", false)
	if err != nil {
		t.Fatalf("SetupTLS with empty strings failed: %v", err)
	}

	if len(tcp.tlsConfig.Certificates) != 0 {
		t.Error("No certificates should be loaded when cert/key are empty strings")
	}
}
