package go_i2cp

import (
	"testing"
	"time"
)

// TestLeaseSet2_Getters tests all LeaseSet2 getter methods
func TestLeaseSet2_Getters(t *testing.T) {
	t.Run("Destination getter", func(t *testing.T) {
		crypto := NewCrypto()
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		ls2 := &LeaseSet2{
			destination: dest,
		}

		got := ls2.Destination()
		if got != dest {
			t.Error("Destination() did not return the correct destination")
		}
		if got.b32 != dest.b32 {
			t.Errorf("Destination base32 mismatch: got %s, want %s", got.b32, dest.b32)
		}
	})

	t.Run("Leases getter", func(t *testing.T) {
		// Create empty LeaseSet2
		ls2 := &LeaseSet2{
			leases: nil,
		}

		// Test with nil leases
		leases := ls2.Leases()
		if leases != nil {
			t.Errorf("Leases() with nil = %v, want nil", leases)
		}

		// Test LeaseCount with nil leases
		count := ls2.LeaseCount()
		if count != 0 {
			t.Errorf("LeaseCount() with nil leases = %d, want 0", count)
		}
	})

	t.Run("ExpiresSeconds getter", func(t *testing.T) {
		expiresTime := uint32(time.Now().Unix() + 3600) // 1 hour from now

		ls2 := &LeaseSet2{
			expires: expiresTime,
		}

		got := ls2.ExpiresSeconds()
		if got != expiresTime {
			t.Errorf("ExpiresSeconds() = %d, want %d", got, expiresTime)
		}

		// Verify Expires() returns correct time.Time
		expectedTime := time.Unix(int64(expiresTime), 0)
		gotTime := ls2.Expires()
		if gotTime.Unix() != expectedTime.Unix() {
			t.Errorf("Expires() = %v, want %v", gotTime, expectedTime)
		}
	})
}

// TestOfflineSignature_Getters tests all OfflineSignature getter methods
func TestOfflineSignature_Getters(t *testing.T) {
	t.Run("SigningKey getter", func(t *testing.T) {
		expectedKey := []byte{1, 2, 3, 4, 5}

		os := &OfflineSignature{
			signingKeyType: 7, // Ed25519
			signingKey:     expectedKey,
		}

		// Test SigningKeyType
		keyType := os.SigningKeyType()
		if keyType != 7 {
			t.Errorf("SigningKeyType() = %d, want 7", keyType)
		}

		// Test SigningKey
		gotKey := os.SigningKey()
		if len(gotKey) != len(expectedKey) {
			t.Errorf("SigningKey() length = %d, want %d", len(gotKey), len(expectedKey))
		}
		for i, b := range gotKey {
			if b != expectedKey[i] {
				t.Errorf("SigningKey()[%d] = %d, want %d", i, b, expectedKey[i])
			}
		}
	})

	t.Run("ExpiresSeconds getter", func(t *testing.T) {
		expiresTime := uint32(time.Now().Unix() + 7200) // 2 hours from now

		os := &OfflineSignature{
			expires: expiresTime,
		}

		got := os.ExpiresSeconds()
		if got != expiresTime {
			t.Errorf("ExpiresSeconds() = %d, want %d", got, expiresTime)
		}

		// Verify Expires() returns correct time.Time
		expectedTime := time.Unix(int64(expiresTime), 0)
		gotTime := os.Expires()
		if gotTime.Unix() != expectedTime.Unix() {
			t.Errorf("Expires() = %v, want %v", gotTime, expectedTime)
		}
	})

	t.Run("TransientKey getter", func(t *testing.T) {
		expectedKey := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1}

		os := &OfflineSignature{
			transientType: 11, // Ed25519ph
			transientKey:  expectedKey,
		}

		// Test TransientKeyType
		keyType := os.TransientKeyType()
		if keyType != 11 {
			t.Errorf("TransientKeyType() = %d, want 11", keyType)
		}

		// Test TransientKey
		gotKey := os.TransientKey()
		if len(gotKey) != len(expectedKey) {
			t.Errorf("TransientKey() length = %d, want %d", len(gotKey), len(expectedKey))
		}
		for i, b := range gotKey {
			if b != expectedKey[i] {
				t.Errorf("TransientKey()[%d] = %d, want %d", i, b, expectedKey[i])
			}
		}
	})

	t.Run("All getters together", func(t *testing.T) {
		now := uint32(time.Now().Unix())
		sigKey := []byte{0xAA, 0xBB, 0xCC}
		transKey := []byte{0x11, 0x22, 0x33, 0x44}

		os := &OfflineSignature{
			signingKeyType: 7,
			signingKey:     sigKey,
			expires:        now + 86400, // 24 hours
			transientType:  11,
			transientKey:   transKey,
		}

		// Verify all getters return expected values
		if os.SigningKeyType() != 7 {
			t.Error("SigningKeyType mismatch")
		}
		if len(os.SigningKey()) != len(sigKey) {
			t.Error("SigningKey length mismatch")
		}
		if os.ExpiresSeconds() != now+86400 {
			t.Error("ExpiresSeconds mismatch")
		}
		if os.TransientKeyType() != 11 {
			t.Error("TransientKeyType mismatch")
		}
		if len(os.TransientKey()) != len(transKey) {
			t.Error("TransientKey length mismatch")
		}

		// Verify Expires() works correctly
		expectedExpiry := time.Unix(int64(now+86400), 0)
		if os.Expires().Unix() != expectedExpiry.Unix() {
			t.Errorf("Expires() = %v, want %v", os.Expires(), expectedExpiry)
		}
	})
}

// TestOfflineSignature_EdgeCases tests edge cases for OfflineSignature getters
func TestOfflineSignature_EdgeCases(t *testing.T) {
	t.Run("Empty signing key", func(t *testing.T) {
		os := &OfflineSignature{
			signingKey: []byte{},
		}

		key := os.SigningKey()
		if key == nil {
			t.Error("SigningKey() should return empty slice, not nil")
		}
		if len(key) != 0 {
			t.Errorf("SigningKey() length = %d, want 0", len(key))
		}
	})

	t.Run("Nil signing key", func(t *testing.T) {
		os := &OfflineSignature{
			signingKey: nil,
		}

		key := os.SigningKey()
		if key != nil {
			t.Errorf("SigningKey() = %v, want nil", key)
		}
	})

	t.Run("Empty transient key", func(t *testing.T) {
		os := &OfflineSignature{
			transientKey: []byte{},
		}

		key := os.TransientKey()
		if key == nil {
			t.Error("TransientKey() should return empty slice, not nil")
		}
		if len(key) != 0 {
			t.Errorf("TransientKey() length = %d, want 0", len(key))
		}
	})

	t.Run("Nil transient key", func(t *testing.T) {
		os := &OfflineSignature{
			transientKey: nil,
		}

		key := os.TransientKey()
		if key != nil {
			t.Errorf("TransientKey() = %v, want nil", key)
		}
	})

	t.Run("Zero expiration time", func(t *testing.T) {
		os := &OfflineSignature{
			expires: 0,
		}

		if os.ExpiresSeconds() != 0 {
			t.Errorf("ExpiresSeconds() = %d, want 0", os.ExpiresSeconds())
		}

		// Verify Expires() returns Unix epoch
		epoch := time.Unix(0, 0)
		if os.Expires().Unix() != epoch.Unix() {
			t.Errorf("Expires() = %v, want %v", os.Expires(), epoch)
		}
	})

	t.Run("Maximum expiration time", func(t *testing.T) {
		maxTime := uint32(0xFFFFFFFF) // Maximum uint32 value

		os := &OfflineSignature{
			expires: maxTime,
		}

		if os.ExpiresSeconds() != maxTime {
			t.Errorf("ExpiresSeconds() = %d, want %d", os.ExpiresSeconds(), maxTime)
		}

		// Verify Expires() handles max value
		expectedTime := time.Unix(int64(maxTime), 0)
		if os.Expires().Unix() != expectedTime.Unix() {
			t.Errorf("Expires() unix = %d, want %d", os.Expires().Unix(), expectedTime.Unix())
		}
	})
}
