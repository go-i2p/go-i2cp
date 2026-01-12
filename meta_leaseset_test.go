// meta_leaseset_test.go - Tests for MetaLeaseSet creation and management
package go_i2cp

import (
	"bytes"
	"testing"
	"time"
)

// TestNewMetaLease tests MetaLease creation
func TestNewMetaLease(t *testing.T) {
	hash := [32]byte{}
	for i := range hash {
		hash[i] = byte(i)
	}

	endDate := uint32(time.Now().Add(1 * time.Hour).Unix())
	ml := NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, 10, endDate)

	if ml == nil {
		t.Fatal("NewMetaLease returned nil")
	}

	if ml.Hash != hash {
		t.Error("Hash not set correctly")
	}

	if ml.Type() != META_LEASE_TYPE_LEASESET2 {
		t.Errorf("Type() = %d, want %d", ml.Type(), META_LEASE_TYPE_LEASESET2)
	}

	if ml.Cost != 10 {
		t.Errorf("Cost = %d, want 10", ml.Cost)
	}

	if ml.EndDate != endDate {
		t.Errorf("EndDate = %d, want %d", ml.EndDate, endDate)
	}
}

// TestMetaLease_Type tests Type() and SetType()
func TestMetaLease_Type(t *testing.T) {
	tests := []struct {
		name     string
		setType  uint8
		wantType uint8
	}{
		{"Unknown", META_LEASE_TYPE_UNKNOWN, 0},
		{"LeaseSet", META_LEASE_TYPE_LEASESET, 1},
		{"LeaseSet2", META_LEASE_TYPE_LEASESET2, 3},
		{"Meta", META_LEASE_TYPE_META, 5},
		{"Max value", 0x0F, 0x0F},
		{"Overflow truncates", 0xFF, 0x0F}, // Only lower 4 bits used
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ml := &MetaLease{}
			ml.SetType(tt.setType)
			if got := ml.Type(); got != tt.wantType {
				t.Errorf("Type() = %d, want %d", got, tt.wantType)
			}
		})
	}
}

// TestMetaLease_WriteToStream tests MetaLease serialization
func TestMetaLease_WriteToStream(t *testing.T) {
	hash := [32]byte{}
	for i := range hash {
		hash[i] = byte(i + 1)
	}

	ml := &MetaLease{
		Hash:    hash,
		Flags:   0x000003, // LeaseSet2 type
		Cost:    50,
		EndDate: 0x12345678,
	}

	stream := NewStream(make([]byte, 0, 64))
	err := ml.WriteToStream(stream)
	if err != nil {
		t.Fatalf("WriteToStream failed: %v", err)
	}

	data := stream.Bytes()
	if len(data) != 40 {
		t.Errorf("WriteToStream produced %d bytes, want 40", len(data))
	}

	// Verify hash (bytes 0-31)
	if !bytes.Equal(data[0:32], hash[:]) {
		t.Error("Hash not serialized correctly")
	}

	// Verify flags (bytes 32-34, big-endian 3 bytes)
	flags := (uint32(data[32]) << 16) | (uint32(data[33]) << 8) | uint32(data[34])
	if flags != 0x000003 {
		t.Errorf("Flags = 0x%06X, want 0x000003", flags)
	}

	// Verify cost (byte 35)
	if data[35] != 50 {
		t.Errorf("Cost = %d, want 50", data[35])
	}

	// Verify end date (bytes 36-39, big-endian)
	endDate := (uint32(data[36]) << 24) | (uint32(data[37]) << 16) |
		(uint32(data[38]) << 8) | uint32(data[39])
	if endDate != 0x12345678 {
		t.Errorf("EndDate = 0x%08X, want 0x12345678", endDate)
	}
}

// TestReadMetaLeaseFromStream tests MetaLease deserialization
func TestReadMetaLeaseFromStream(t *testing.T) {
	// Create a MetaLease, write it, and read it back
	original := &MetaLease{
		Hash:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Flags:   0x000005, // MetaLeaseSet type
		Cost:    100,
		EndDate: 1700000000,
	}

	writeStream := NewStream(make([]byte, 0, 64))
	err := original.WriteToStream(writeStream)
	if err != nil {
		t.Fatalf("WriteToStream failed: %v", err)
	}

	readStream := NewStream(writeStream.Bytes())
	parsed, err := ReadMetaLeaseFromStream(readStream)
	if err != nil {
		t.Fatalf("ReadMetaLeaseFromStream failed: %v", err)
	}

	if parsed.Hash != original.Hash {
		t.Error("Hash mismatch after round-trip")
	}

	if parsed.Flags != original.Flags {
		t.Errorf("Flags = 0x%06X, want 0x%06X", parsed.Flags, original.Flags)
	}

	if parsed.Cost != original.Cost {
		t.Errorf("Cost = %d, want %d", parsed.Cost, original.Cost)
	}

	if parsed.EndDate != original.EndDate {
		t.Errorf("EndDate = %d, want %d", parsed.EndDate, original.EndDate)
	}
}

// TestReadMetaLeaseFromStream_TruncatedHash tests error on truncated hash
func TestReadMetaLeaseFromStream_TruncatedHash(t *testing.T) {
	// Only 20 bytes instead of 32
	data := make([]byte, 20)
	stream := NewStream(data)

	_, err := ReadMetaLeaseFromStream(stream)
	if err == nil {
		t.Error("Expected error on truncated hash")
	}
}

// TestReadMetaLeaseFromStream_TruncatedFlags tests error on truncated flags
func TestReadMetaLeaseFromStream_TruncatedFlags(t *testing.T) {
	// 32 bytes hash + only 1 byte flags (need 3)
	data := make([]byte, 33)
	stream := NewStream(data)

	_, err := ReadMetaLeaseFromStream(stream)
	if err == nil {
		t.Error("Expected error on truncated flags")
	}
}

// TestNewMetaLeaseSetConfig tests MetaLeaseSetConfig creation
func TestNewMetaLeaseSetConfig(t *testing.T) {
	config := NewMetaLeaseSetConfig()

	if config == nil {
		t.Fatal("NewMetaLeaseSetConfig returned nil")
	}

	if config.MetaLeases == nil {
		t.Error("MetaLeases slice not initialized")
	}

	if config.Revocations == nil {
		t.Error("Revocations slice not initialized")
	}

	if config.Properties == nil {
		t.Error("Properties map not initialized")
	}
}

// TestMetaLeaseSetConfig_AddMetaLease tests adding MetaLeases
func TestMetaLeaseSetConfig_AddMetaLease(t *testing.T) {
	config := NewMetaLeaseSetConfig()

	// Add 16 MetaLeases (max allowed)
	for i := 0; i < 16; i++ {
		ml := &MetaLease{Cost: uint8(i)}
		err := config.AddMetaLease(ml)
		if err != nil {
			t.Errorf("AddMetaLease(%d) failed: %v", i, err)
		}
	}

	if len(config.MetaLeases) != 16 {
		t.Errorf("MetaLeases count = %d, want 16", len(config.MetaLeases))
	}

	// Try to add 17th - should fail
	err := config.AddMetaLease(&MetaLease{})
	if err == nil {
		t.Error("Expected error when adding 17th MetaLease")
	}
}

// TestMetaLeaseSetConfig_AddRevocation tests adding revocations
func TestMetaLeaseSetConfig_AddRevocation(t *testing.T) {
	config := NewMetaLeaseSetConfig()

	hash1 := [32]byte{1, 2, 3}
	hash2 := [32]byte{4, 5, 6}

	config.AddRevocation(hash1)
	config.AddRevocation(hash2)

	if len(config.Revocations) != 2 {
		t.Errorf("Revocations count = %d, want 2", len(config.Revocations))
	}

	if config.Revocations[0] != hash1 {
		t.Error("First revocation hash mismatch")
	}

	if config.Revocations[1] != hash2 {
		t.Error("Second revocation hash mismatch")
	}
}

// TestMsgCreateMetaLeaseSet_Basic tests basic MetaLeaseSet creation
func TestMsgCreateMetaLeaseSet_Basic(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	// Create destination
	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	// Set up router version (need 0.9.39+)
	client.router.date = 1000000
	client.router.version = Version{major: 0, minor: 9, micro: 67}

	// Create MetaLeaseSet config
	config := NewMetaLeaseSetConfig()
	hash := [32]byte{}
	for i := range hash {
		hash[i] = byte(i)
	}
	endDate := uint32(time.Now().Add(1 * time.Hour).Unix())
	ml := NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, 10, endDate)
	config.AddMetaLease(ml)

	// Call msgCreateMetaLeaseSet with queue=true
	err = client.msgCreateMetaLeaseSet(session, config, true)
	if err != nil {
		t.Fatalf("msgCreateMetaLeaseSet failed: %v", err)
	}

	// Verify message was queued
	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued")
	}
}

// TestMsgCreateMetaLeaseSet_VersionCheck tests version requirement
func TestMsgCreateMetaLeaseSet_VersionCheck(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, _ := NewDestination(client.crypto)
	session.config.destination = dest

	// Set old router version (pre-0.9.39)
	client.router.version = Version{major: 0, minor: 9, micro: 30}

	config := NewMetaLeaseSetConfig()
	config.AddMetaLease(&MetaLease{})

	err := client.msgCreateMetaLeaseSet(session, config, true)
	if err == nil {
		t.Error("Expected error for old router version")
	}
}

// TestMsgCreateMetaLeaseSet_EmptyConfig tests error on empty config
func TestMsgCreateMetaLeaseSet_EmptyConfig(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, _ := NewDestination(client.crypto)
	session.config.destination = dest

	client.router.version = Version{major: 0, minor: 9, micro: 67}

	// Empty config - no MetaLeases
	config := NewMetaLeaseSetConfig()

	err := client.msgCreateMetaLeaseSet(session, config, true)
	if err == nil {
		t.Error("Expected error for empty MetaLeaseSet config")
	}
}

// TestMsgCreateMetaLeaseSet_TooManyMetaLeases tests error on too many MetaLeases
func TestMsgCreateMetaLeaseSet_TooManyMetaLeases(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, _ := NewDestination(client.crypto)
	session.config.destination = dest

	client.router.version = Version{major: 0, minor: 9, micro: 67}

	// Create config with 17 MetaLeases (manually bypass AddMetaLease limit)
	config := &MetaLeaseSetConfig{
		MetaLeases:  make([]*MetaLease, 17),
		Revocations: make([][32]byte, 0),
		Properties:  make(map[string]string),
	}

	err := client.msgCreateMetaLeaseSet(session, config, true)
	if err == nil {
		t.Error("Expected error for too many MetaLeases")
	}
}

// TestMsgCreateMetaLeaseSet_WithRevocations tests MetaLeaseSet with revocations
func TestMsgCreateMetaLeaseSet_WithRevocations(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	client.router.date = 1000000
	client.router.version = Version{major: 0, minor: 9, micro: 67}

	config := NewMetaLeaseSetConfig()

	// Add a MetaLease
	hash := [32]byte{1, 2, 3}
	ml := NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, 10, uint32(time.Now().Add(1*time.Hour).Unix()))
	config.AddMetaLease(ml)

	// Add revocations
	revHash1 := [32]byte{10, 20, 30}
	revHash2 := [32]byte{40, 50, 60}
	config.AddRevocation(revHash1)
	config.AddRevocation(revHash2)

	err = client.msgCreateMetaLeaseSet(session, config, true)
	if err != nil {
		t.Fatalf("msgCreateMetaLeaseSet with revocations failed: %v", err)
	}

	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued")
	}
}

// TestMsgCreateMetaLeaseSet_WithProperties tests MetaLeaseSet with properties
func TestMsgCreateMetaLeaseSet_WithProperties(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	client.router.date = 1000000
	client.router.version = Version{major: 0, minor: 9, micro: 67}

	config := NewMetaLeaseSetConfig()
	config.Properties["custom.property"] = "value"
	config.Properties["another.option"] = "test"

	hash := [32]byte{}
	ml := NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, 0, uint32(time.Now().Add(1*time.Hour).Unix()))
	config.AddMetaLease(ml)

	err = client.msgCreateMetaLeaseSet(session, config, true)
	if err != nil {
		t.Fatalf("msgCreateMetaLeaseSet with properties failed: %v", err)
	}
}

// TestMsgCreateMetaLeaseSet_MultipleMetaLeases tests multiple MetaLease entries
func TestMsgCreateMetaLeaseSet_MultipleMetaLeases(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	client.router.date = 1000000
	client.router.version = Version{major: 0, minor: 9, micro: 67}

	config := NewMetaLeaseSetConfig()

	// Add multiple MetaLeases with different costs
	for i := 0; i < 5; i++ {
		hash := [32]byte{}
		hash[0] = byte(i)
		ml := NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, uint8(i*10), uint32(time.Now().Add(1*time.Hour).Unix()))
		config.AddMetaLease(ml)
	}

	err = client.msgCreateMetaLeaseSet(session, config, true)
	if err != nil {
		t.Fatalf("msgCreateMetaLeaseSet with multiple entries failed: %v", err)
	}

	if len(client.outputQueue) == 0 {
		t.Error("Expected message to be queued")
	}
}

// TestSession_CreateMetaLeaseSet tests the Session method
func TestSession_CreateMetaLeaseSet(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.id = 1

	dest, err := NewDestination(client.crypto)
	if err != nil {
		t.Fatalf("Failed to create destination: %v", err)
	}
	session.config.destination = dest

	client.router.date = 1000000
	client.router.version = Version{major: 0, minor: 9, micro: 67}

	config := NewMetaLeaseSetConfig()
	hash := [32]byte{1, 2, 3}
	config.AddMetaLease(NewMetaLease(hash, META_LEASE_TYPE_LEASESET2, 0, uint32(time.Now().Add(1*time.Hour).Unix())))

	// Note: This will fail because we're not actually connected
	// but we're testing the method routing, not the full connection
	err = session.CreateMetaLeaseSetQueued(config)
	if err != nil {
		t.Fatalf("CreateMetaLeaseSetQueued failed: %v", err)
	}
}

// TestSession_CreateMetaLeaseSet_NilClient tests error on nil client
func TestSession_CreateMetaLeaseSet_NilClient(t *testing.T) {
	session := &Session{}
	config := NewMetaLeaseSetConfig()

	err := session.CreateMetaLeaseSet(config)
	if err == nil {
		t.Error("Expected error on nil client")
	}
}

// TestSession_CreateMetaLeaseSet_ClosedSession tests error on closed session
func TestSession_CreateMetaLeaseSet_ClosedSession(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	session := newSession(client, SessionCallbacks{})
	session.closed = true

	config := NewMetaLeaseSetConfig()

	err := session.CreateMetaLeaseSet(config)
	if err == nil {
		t.Error("Expected error on closed session")
	}
}

// TestMetaLease_Constants tests MetaLease type constants
func TestMetaLease_Constants(t *testing.T) {
	// Verify constants match I2CP spec
	if META_LEASE_TYPE_UNKNOWN != 0 {
		t.Errorf("META_LEASE_TYPE_UNKNOWN = %d, want 0", META_LEASE_TYPE_UNKNOWN)
	}
	if META_LEASE_TYPE_LEASESET != 1 {
		t.Errorf("META_LEASE_TYPE_LEASESET = %d, want 1", META_LEASE_TYPE_LEASESET)
	}
	if META_LEASE_TYPE_LEASESET2 != 3 {
		t.Errorf("META_LEASE_TYPE_LEASESET2 = %d, want 3", META_LEASE_TYPE_LEASESET2)
	}
	if META_LEASE_TYPE_META != 5 {
		t.Errorf("META_LEASE_TYPE_META = %d, want 5", META_LEASE_TYPE_META)
	}
}

// TestWriteMetaLeases tests the writeMetaLeases helper
func TestWriteMetaLeases(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	stream := NewStream(make([]byte, 0, 256))

	metaLeases := []*MetaLease{
		{Hash: [32]byte{1}, Flags: 3, Cost: 10, EndDate: 1000},
		{Hash: [32]byte{2}, Flags: 3, Cost: 20, EndDate: 2000},
	}

	err := client.writeMetaLeases(stream, metaLeases)
	if err != nil {
		t.Fatalf("writeMetaLeases failed: %v", err)
	}

	data := stream.Bytes()

	// Should have: 1 byte count + 2 * 40 bytes = 81 bytes
	expectedLen := 1 + 2*40
	if len(data) != expectedLen {
		t.Errorf("writeMetaLeases produced %d bytes, want %d", len(data), expectedLen)
	}

	// First byte should be count
	if data[0] != 2 {
		t.Errorf("MetaLease count = %d, want 2", data[0])
	}
}

// TestWriteRevocations tests the writeRevocations helper
func TestWriteRevocations(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	stream := NewStream(make([]byte, 0, 128))

	revocations := [][32]byte{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}

	err := client.writeRevocations(stream, revocations)
	if err != nil {
		t.Fatalf("writeRevocations failed: %v", err)
	}

	data := stream.Bytes()

	// Should have: 1 byte count + 3 * 32 bytes = 97 bytes
	expectedLen := 1 + 3*32
	if len(data) != expectedLen {
		t.Errorf("writeRevocations produced %d bytes, want %d", len(data), expectedLen)
	}

	// First byte should be count
	if data[0] != 3 {
		t.Errorf("Revocation count = %d, want 3", data[0])
	}
}

// TestWriteRevocations_Empty tests writeRevocations with no revocations
func TestWriteRevocations_Empty(t *testing.T) {
	client := NewClient(&ClientCallBacks{})
	stream := NewStream(make([]byte, 0, 16))

	err := client.writeRevocations(stream, nil)
	if err != nil {
		t.Fatalf("writeRevocations (empty) failed: %v", err)
	}

	data := stream.Bytes()

	// Should have just 1 byte (count = 0)
	if len(data) != 1 {
		t.Errorf("writeRevocations (empty) produced %d bytes, want 1", len(data))
	}

	if data[0] != 0 {
		t.Errorf("Revocation count = %d, want 0", data[0])
	}
}

// TestMetaLease_RoundTrip tests complete serialization round-trip
func TestMetaLease_RoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		original *MetaLease
	}{
		{
			name: "LeaseSet type with high cost",
			original: &MetaLease{
				Hash:    [32]byte{0xFF, 0xFE, 0xFD},
				Flags:   0x000001,
				Cost:    255,
				EndDate: 0xFFFFFFFF,
			},
		},
		{
			name: "LeaseSet2 type with zero cost",
			original: &MetaLease{
				Hash:    [32]byte{},
				Flags:   0x000003,
				Cost:    0,
				EndDate: 0,
			},
		},
		{
			name: "MetaLeaseSet type with flags",
			original: &MetaLease{
				Hash:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Flags:   0x0F0005, // Additional flags beyond type bits
				Cost:    128,
				EndDate: 1700000000,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeStream := NewStream(make([]byte, 0, 64))
			err := tc.original.WriteToStream(writeStream)
			if err != nil {
				t.Fatalf("WriteToStream failed: %v", err)
			}

			readStream := NewStream(writeStream.Bytes())
			parsed, err := ReadMetaLeaseFromStream(readStream)
			if err != nil {
				t.Fatalf("ReadMetaLeaseFromStream failed: %v", err)
			}

			if parsed.Hash != tc.original.Hash {
				t.Error("Hash mismatch")
			}

			// Only compare lower 24 bits of flags (3 bytes serialized)
			originalFlags24 := tc.original.Flags & 0x00FFFFFF
			parsedFlags24 := parsed.Flags & 0x00FFFFFF
			if parsedFlags24 != originalFlags24 {
				t.Errorf("Flags = 0x%06X, want 0x%06X", parsedFlags24, originalFlags24)
			}

			if parsed.Cost != tc.original.Cost {
				t.Errorf("Cost = %d, want %d", parsed.Cost, tc.original.Cost)
			}

			if parsed.EndDate != tc.original.EndDate {
				t.Errorf("EndDate = %d, want %d", parsed.EndDate, tc.original.EndDate)
			}
		})
	}
}
