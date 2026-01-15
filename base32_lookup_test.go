package go_i2cp

import (
	"testing"

	"github.com/go-i2p/common/base32"
)

// TestPrepareLookupData_Base32Hash verifies that 52-character base32 hashes are decoded correctly.
func TestPrepareLookupData_Base32Hash(t *testing.T) {
	session := &Session{}

	// Create a valid 52-character base32 hash (32 bytes encoded)
	originalHash := make([]byte, 32)
	for i := range originalHash {
		originalHash[i] = byte(i)
	}
	encoded := base32.EncodeToString(originalHash)

	if len(encoded) != 56 {
		t.Fatalf("expected encoded hash to be 56 chars, got %d", len(encoded))
	}

	lookupType, lookupData, err := session.prepareLookupData(encoded)
	if err != nil {
		t.Fatalf("prepareLookupData failed: %v", err)
	}

	if lookupType != 0 {
		t.Errorf("expected lookupType 0 (hash), got %d", lookupType)
	}

	if len(lookupData) != 32 {
		t.Errorf("expected decoded hash to be 32 bytes, got %d", len(lookupData))
	}

	for i, b := range lookupData {
		if b != originalHash[i] {
			t.Errorf("decoded hash mismatch at byte %d: got %d, want %d", i, b, originalHash[i])
		}
	}
}

// TestPrepareLookupData_Hostname verifies that hostnames are handled correctly.
func TestPrepareLookupData_Hostname(t *testing.T) {
	session := &Session{}

	testCases := []string{
		"example.i2p",
		"test.b32.i2p",
		"short",
		"a-very-long-hostname-that-is-not-52-characters.i2p",
	}

	for _, hostname := range testCases {
		lookupType, lookupData, err := session.prepareLookupData(hostname)
		if err != nil {
			t.Errorf("prepareLookupData(%q) failed: %v", hostname, err)
			continue
		}

		if lookupType != 1 {
			t.Errorf("prepareLookupData(%q): expected lookupType 1 (hostname), got %d", hostname, lookupType)
		}

		if string(lookupData) != hostname {
			t.Errorf("prepareLookupData(%q): expected lookupData %q, got %q", hostname, hostname, string(lookupData))
		}
	}
}

// TestPrepareLookupData_InvalidBase32 verifies that invalid 52-char strings return an error.
func TestPrepareLookupData_InvalidBase32(t *testing.T) {
	session := &Session{}

	// 56 characters but invalid base32 (contains invalid chars like '1', '0', '8', '9')
	invalidBase32 := "00000000000000000000000000000000000000000000000000000000"

	_, _, err := session.prepareLookupData(invalidBase32)
	if err == nil {
		t.Error("expected error for invalid base32 string, got nil")
	}
}
