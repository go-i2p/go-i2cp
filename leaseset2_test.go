package go_i2cp

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-i2p/common/lease"
)

// TestLeaseSet2Parsing_Standard tests parsing of a standard LeaseSet2 (type 3)
func TestLeaseSet2Parsing_Standard(t *testing.T) {
	crypto := NewCrypto()

	// Create a test destination
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Build a LeaseSet2 message in stream format
	stream := NewStream(make([]byte, 0, 1024))

	// Write LeaseSet type (3 = standard)
	stream.WriteByte(LEASESET_TYPE_STANDARD)

	// Write destination
	dest.WriteToStream(stream)

	// Write timestamps
	published := uint32(time.Now().Unix())
	expires := uint32(time.Now().Add(10 * time.Minute).Unix())
	stream.WriteUint32(published)
	stream.WriteUint32(expires)

	// Write flags (0 = no offline signature)
	stream.WriteUint16(0)

	// Write empty properties
	stream.WriteMapping(map[string]string{})

	// Write 2 leases
	stream.WriteByte(2)

	// Create test Lease2 structures
	for i := 0; i < 2; i++ {
		gateway := make([]byte, 32)
		for j := range gateway {
			gateway[j] = byte(i)
		}
		tunnelID := uint32(1000 + i)
		endDate := uint32(time.Now().Add(5 * time.Minute).Unix())

		// Write Lease2 (40 bytes: 32 gateway + 4 tunnel ID + 4 end date)
		stream.Write(gateway)
		stream.WriteUint32(tunnelID)
		stream.WriteUint32(endDate)
	}

	// Write signature (64 bytes for Ed25519)
	signature := make([]byte, 64)
	for i := range signature {
		signature[i] = 0xff
	}
	stream.Write(signature)

	// Parse LeaseSet2
	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2: %v", err)
	}

	// Validate parsed data
	if ls.Type() != LEASESET_TYPE_STANDARD {
		t.Errorf("Expected type %d, got %d", LEASESET_TYPE_STANDARD, ls.Type())
	}

	if ls.PublishedSeconds() != published {
		t.Errorf("Expected published %d, got %d", published, ls.PublishedSeconds())
	}

	if ls.ExpiresSeconds() != expires {
		t.Errorf("Expected expires %d, got %d", expires, ls.ExpiresSeconds())
	}

	if ls.LeaseCount() != 2 {
		t.Errorf("Expected 2 leases, got %d", ls.LeaseCount())
	}

	if ls.HasOfflineSignature() {
		t.Error("Expected no offline signature")
	}

	if ls.IsExpired() {
		t.Error("LeaseSet2 should not be expired")
	}

	if !bytes.Equal(ls.Signature(), signature) {
		t.Error("Signature mismatch")
	}
}

// TestLeaseSet2Parsing_Encrypted tests parsing of an encrypted LeaseSet2 (type 5)
func TestLeaseSet2Parsing_Encrypted(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))

	// Write encrypted LeaseSet type
	stream.WriteByte(LEASESET_TYPE_ENCRYPTED)
	dest.WriteToStream(stream)

	published := uint32(time.Now().Unix())
	expires := uint32(time.Now().Add(10 * time.Minute).Unix())
	stream.WriteUint32(published)
	stream.WriteUint32(expires)
	stream.WriteUint16(0) // flags

	// Add some properties
	properties := map[string]string{
		"encryption": "chacha20-poly1305",
		"version":    "2",
	}
	stream.WriteMapping(properties)

	// 1 lease
	stream.WriteByte(1)
	gateway := make([]byte, 32)
	stream.Write(gateway)
	stream.WriteUint32(2000)
	stream.WriteUint32(uint32(time.Now().Add(5 * time.Minute).Unix()))

	// Signature
	signature := make([]byte, 64)
	stream.Write(signature)

	// Parse
	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse encrypted LeaseSet2: %v", err)
	}

	if ls.Type() != LEASESET_TYPE_ENCRYPTED {
		t.Errorf("Expected type %d, got %d", LEASESET_TYPE_ENCRYPTED, ls.Type())
	}

	props := ls.Properties()
	if props["encryption"] != "chacha20-poly1305" {
		t.Errorf("Property mismatch: expected 'chacha20-poly1305', got '%s'", props["encryption"])
	}
}

// TestLeaseSet2Parsing_WithOfflineSignature tests LeaseSet2 with offline signature
func TestLeaseSet2Parsing_WithOfflineSignature(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 2048))

	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)

	published := uint32(time.Now().Unix())
	expires := uint32(time.Now().Add(10 * time.Minute).Unix())
	stream.WriteUint32(published)
	stream.WriteUint32(expires)

	// Set bit 0 in flags to indicate offline signature present
	stream.WriteUint16(0x0001)

	stream.WriteMapping(map[string]string{})

	// 1 lease
	stream.WriteByte(1)
	gateway := make([]byte, 32)
	stream.Write(gateway)
	stream.WriteUint32(1500)
	stream.WriteUint32(uint32(time.Now().Add(5 * time.Minute).Unix()))

	// Write offline signature
	stream.WriteUint16(7)  // signing key type (Ed25519)
	stream.WriteUint16(32) // signing key length
	signingKey := make([]byte, 32)
	stream.Write(signingKey)
	stream.WriteUint32(uint32(time.Now().Add(24 * time.Hour).Unix())) // expires
	stream.WriteUint16(7)                                             // transient key type
	stream.WriteUint16(32)                                            // transient key length
	transientKey := make([]byte, 32)
	stream.Write(transientKey)
	stream.WriteUint16(64) // signature length
	offlineSig := make([]byte, 64)
	stream.Write(offlineSig)

	// Main signature
	signature := make([]byte, 64)
	stream.Write(signature)

	// Parse
	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2 with offline signature: %v", err)
	}

	if !ls.HasOfflineSignature() {
		t.Error("Expected offline signature to be present")
	}

	offlineSigData := ls.OfflineSignature()
	if offlineSigData == nil {
		t.Fatal("Offline signature is nil")
	}

	if offlineSigData.SigningKeyType() != 7 {
		t.Errorf("Expected signing key type 7, got %d", offlineSigData.SigningKeyType())
	}

	if offlineSigData.TransientKeyType() != 7 {
		t.Errorf("Expected transient key type 7, got %d", offlineSigData.TransientKeyType())
	}

	if len(offlineSigData.Signature()) != 64 {
		t.Errorf("Expected offline signature length 64, got %d", len(offlineSigData.Signature()))
	}
}

// TestLeaseSet2Parsing_InvalidType tests rejection of invalid LeaseSet type
func TestLeaseSet2Parsing_InvalidType(t *testing.T) {
	crypto := NewCrypto()

	stream := NewStream(make([]byte, 0, 100))
	stream.WriteByte(99) // Invalid type

	parseStream := NewStream(stream.Bytes())
	_, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err == nil {
		t.Error("Expected error for invalid LeaseSet type")
	}
}

// TestLeaseSet2Parsing_TooManyLeases tests rejection of >16 leases
func TestLeaseSet2Parsing_TooManyLeases(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))

	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{})

	// Try to add 17 leases (exceeds max of 16)
	stream.WriteByte(17)

	parseStream := NewStream(stream.Bytes())
	_, err = NewLeaseSet2FromStream(parseStream, crypto)
	if err == nil {
		t.Error("Expected error for too many leases")
	}
}

// TestLeaseSet2_IsExpired tests expiration checking
func TestLeaseSet2_IsExpired(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Test expired LeaseSet
	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)

	published := uint32(time.Now().Add(-20 * time.Minute).Unix())
	expires := uint32(time.Now().Add(-10 * time.Minute).Unix()) // Expired
	stream.WriteUint32(published)
	stream.WriteUint32(expires)
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{})
	stream.WriteByte(0) // 0 leases

	signature := make([]byte, 64)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2: %v", err)
	}

	if !ls.IsExpired() {
		t.Error("LeaseSet2 should be expired")
	}
}

// TestLeaseSet2_VerifySignature tests cryptographic signature verification
func TestLeaseSet2_VerifySignature(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	// Create LeaseSet2 data (everything before signature)
	dataStream := NewStream(make([]byte, 0, 1024))
	dataStream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(dataStream)
	dataStream.WriteUint32(uint32(time.Now().Unix()))
	dataStream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	dataStream.WriteUint16(0)
	dataStream.WriteMapping(map[string]string{})
	dataStream.WriteByte(0) // 0 leases

	// Sign the data using the destination's signing key (appends signature to stream)
	err = dest.sgk.ed25519KeyPair.SignStream(dataStream)
	if err != nil {
		t.Fatalf("Failed to sign LeaseSet2 data: %v", err)
	}

	// Parse the complete LeaseSet2 (data + signature)
	parseStream := NewStream(dataStream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2: %v", err)
	}

	// Cryptographic signature verification should pass for properly signed data
	if !ls.VerifySignature() {
		t.Error("Expected signature verification to pass for properly signed LeaseSet2")
	}
}

// TestLeaseSet2_VerifySignature_Invalid tests invalid signature rejection
func TestLeaseSet2_VerifySignature_Invalid(t *testing.T) {
	ls := &LeaseSet2{
		signature: []byte{}, // Empty signature
	}

	if ls.VerifySignature() {
		t.Error("Expected verification to fail for empty signature")
	}
}

// TestLeaseSet2_String tests String() method output
func TestLeaseSet2_String(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteByte(LEASESET_TYPE_ENCRYPTED)
	dest.WriteToStream(stream)

	published := uint32(time.Now().Unix())
	expires := uint32(time.Now().Add(10 * time.Minute).Unix())
	stream.WriteUint32(published)
	stream.WriteUint32(expires)
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{})
	stream.WriteByte(1) // 1 lease

	gateway := make([]byte, 32)
	stream.Write(gateway)
	stream.WriteUint32(3000)
	stream.WriteUint32(uint32(time.Now().Add(5 * time.Minute).Unix()))

	signature := make([]byte, 64)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2: %v", err)
	}

	str := ls.String()
	if str == "" {
		t.Error("String() returned empty string")
	}

	// Check that string contains expected fields
	if !containsSubstring(str, "encrypted") {
		t.Error("String() should contain 'encrypted' for encrypted LeaseSet")
	}
	if !containsSubstring(str, "leases=1") {
		t.Error("String() should contain lease count")
	}
}

// TestLeaseSet2_EmptyProperties tests handling of empty properties
func TestLeaseSet2_EmptyProperties(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteByte(LEASESET_TYPE_STANDARD)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{}) // Empty properties
	stream.WriteByte(0)

	signature := make([]byte, 64)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse LeaseSet2: %v", err)
	}

	props := ls.Properties()
	if props == nil {
		t.Error("Properties should not be nil")
	}
	if len(props) != 0 {
		t.Errorf("Expected 0 properties, got %d", len(props))
	}
}

// TestLeaseSet2_MetaType tests meta LeaseSet type (type 7)
func TestLeaseSet2_MetaType(t *testing.T) {
	crypto := NewCrypto()
	dest, err := NewDestination(crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}

	stream := NewStream(make([]byte, 0, 1024))
	stream.WriteByte(LEASESET_TYPE_META)
	dest.WriteToStream(stream)
	stream.WriteUint32(uint32(time.Now().Unix()))
	stream.WriteUint32(uint32(time.Now().Add(10 * time.Minute).Unix()))
	stream.WriteUint16(0)
	stream.WriteMapping(map[string]string{"meta": "true"})
	stream.WriteByte(0)

	signature := make([]byte, 64)
	stream.Write(signature)

	parseStream := NewStream(stream.Bytes())
	ls, err := NewLeaseSet2FromStream(parseStream, crypto)
	if err != nil {
		t.Fatalf("Failed to parse meta LeaseSet2: %v", err)
	}

	if ls.Type() != LEASESET_TYPE_META {
		t.Errorf("Expected type %d, got %d", LEASESET_TYPE_META, ls.Type())
	}
}

// TestOfflineSignature_IsExpired tests offline signature expiration
func TestOfflineSignature_IsExpired(t *testing.T) {
	// Create expired offline signature
	expired := &OfflineSignature{
		expires: uint32(time.Now().Add(-1 * time.Hour).Unix()),
	}

	if !expired.IsExpired() {
		t.Error("Offline signature should be expired")
	}

	// Create valid offline signature
	valid := &OfflineSignature{
		expires: uint32(time.Now().Add(24 * time.Hour).Unix()),
	}

	if valid.IsExpired() {
		t.Error("Offline signature should not be expired")
	}
}

// TestOfflineSignature_String tests String() method
func TestOfflineSignature_String(t *testing.T) {
	sig := &OfflineSignature{
		signingKeyType: 7,
		transientType:  7,
		expires:        uint32(time.Now().Add(24 * time.Hour).Unix()),
	}

	str := sig.String()
	if str == "" {
		t.Error("String() returned empty string")
	}

	if !containsSubstring(str, "sigType=7") {
		t.Error("String() should contain signing key type")
	}
}

// TestLeaseSet2_GetterMethods tests all getter methods
func TestLeaseSet2_GetterMethods(t *testing.T) {
	now := time.Now()
	published := uint32(now.Unix())
	expires := uint32(now.Add(10 * time.Minute).Unix())

	ls := &LeaseSet2{
		leaseSetType: LEASESET_TYPE_STANDARD,
		published:    published,
		expires:      expires,
		flags:        0x0001,
		properties:   map[string]string{"key": "value"},
		leases:       make([]*lease.Lease2, 3),
		signature:    make([]byte, 64),
		offlineSig:   &OfflineSignature{},
	}

	if ls.Type() != LEASESET_TYPE_STANDARD {
		t.Errorf("Type() failed: expected %d, got %d", LEASESET_TYPE_STANDARD, ls.Type())
	}

	if ls.PublishedSeconds() != published {
		t.Errorf("PublishedSeconds() failed: expected %d, got %d", published, ls.PublishedSeconds())
	}

	if ls.ExpiresSeconds() != expires {
		t.Errorf("ExpiresSeconds() failed: expected %d, got %d", expires, ls.ExpiresSeconds())
	}

	if ls.Flags() != 0x0001 {
		t.Errorf("Flags() failed: expected 0x0001, got 0x%04x", ls.Flags())
	}

	if len(ls.Properties()) != 1 {
		t.Errorf("Properties() failed: expected 1 property, got %d", len(ls.Properties()))
	}

	if ls.LeaseCount() != 3 {
		t.Errorf("LeaseCount() failed: expected 3, got %d", ls.LeaseCount())
	}

	if len(ls.Signature()) != 64 {
		t.Errorf("Signature() failed: expected 64 bytes (Ed25519), got %d", len(ls.Signature()))
	}

	if ls.OfflineSignature() == nil {
		t.Error("OfflineSignature() failed: expected non-nil")
	}

	// Test time conversions
	publishedTime := ls.Published()
	if publishedTime.Unix() != int64(published) {
		t.Errorf("Published() time conversion failed")
	}

	expiresTime := ls.Expires()
	if expiresTime.Unix() != int64(expires) {
		t.Errorf("Expires() time conversion failed")
	}
}
