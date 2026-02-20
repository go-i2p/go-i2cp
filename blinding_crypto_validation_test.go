package go_i2cp

import (
	"testing"
	"time"
)

// TestMsgBlindingInfo_Validation tests BlindingInfoMessage validation logic.
func TestMsgBlindingInfo_Validation(t *testing.T) {
	client := NewClient(nil)
	client.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))

	session := &Session{
		id:     1,
		client: client,
	}

	tests := []struct {
		name        string
		session     *Session
		info        *BlindingInfo
		expectError bool
		errorSubstr string
	}{
		{
			name:        "nil session",
			session:     nil,
			info:        &BlindingInfo{},
			expectError: true,
			errorSubstr: "session cannot be nil",
		},
		{
			name:        "nil info",
			session:     session,
			info:        nil,
			expectError: true,
			errorSubstr: "blinding info cannot be nil",
		},
		{
			name:    "invalid endpoint type",
			session: session,
			info: &BlindingInfo{
				EndpointType: 4, // Invalid, must be 0-3
				Endpoint:     make([]byte, 32),
			},
			expectError: true,
			errorSubstr: "invalid endpoint type",
		},
		{
			name:    "hash endpoint wrong size",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_HASH,
				Endpoint:     make([]byte, 31), // Should be 32
			},
			expectError: true,
			errorSubstr: "hash endpoint must be exactly 32 bytes",
		},
		{
			name:    "empty hostname",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_HOSTNAME,
				Endpoint:     []byte{},
			},
			expectError: true,
			errorSubstr: "hostname endpoint cannot be empty",
		},
		{
			name:    "hostname too long",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_HOSTNAME,
				Endpoint:     make([]byte, 256), // Max is 255
			},
			expectError: true,
			errorSubstr: "hostname too long",
		},
		{
			name:    "destination too short",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_DESTINATION,
				Endpoint:     make([]byte, 100), // Min is 387
			},
			expectError: true,
			errorSubstr: "destination endpoint too short",
		},
		{
			name:    "sigkey too short",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_SIGKEY,
				Endpoint:     make([]byte, 2), // Min is 3
			},
			expectError: true,
			errorSubstr: "sigkey endpoint too short",
		},
		{
			name:    "invalid auth scheme",
			session: session,
			info: &BlindingInfo{
				EndpointType: BLINDING_ENDPOINT_HASH,
				Endpoint:     make([]byte, 32),
				AuthScheme:   2, // Invalid, must be 0 or 1
			},
			expectError: true,
			errorSubstr: "invalid auth scheme",
		},
		{
			name:    "per-client auth without decryption key",
			session: session,
			info: &BlindingInfo{
				EndpointType:  BLINDING_ENDPOINT_HASH,
				Endpoint:      make([]byte, 32),
				PerClientAuth: true,
				DecryptionKey: make([]byte, 16), // Should be 32
			},
			expectError: true,
			errorSubstr: "decryption key must be exactly 32 bytes",
		},
		{
			name:    "valid hash endpoint",
			session: session,
			info: &BlindingInfo{
				EndpointType:   BLINDING_ENDPOINT_HASH,
				Endpoint:       make([]byte, 32),
				BlindedSigType: 11,
				Expiration:     uint32(time.Now().Unix()),
			},
			expectError: false,
		},
		{
			name:    "valid hostname endpoint",
			session: session,
			info: &BlindingInfo{
				EndpointType:   BLINDING_ENDPOINT_HOSTNAME,
				Endpoint:       []byte("example.i2p"),
				BlindedSigType: 11,
				Expiration:     uint32(time.Now().Unix()),
			},
			expectError: false,
		},
		{
			name:    "valid with per-client auth",
			session: session,
			info: &BlindingInfo{
				EndpointType:   BLINDING_ENDPOINT_HASH,
				Endpoint:       make([]byte, 32),
				BlindedSigType: 11,
				Expiration:     uint32(time.Now().Unix()),
				PerClientAuth:  true,
				AuthScheme:     BLINDING_AUTH_SCHEME_DH,
				DecryptionKey:  make([]byte, 32),
			},
			expectError: false,
		},
		{
			name:    "valid with lookup password",
			session: session,
			info: &BlindingInfo{
				EndpointType:   BLINDING_ENDPOINT_HASH,
				Endpoint:       make([]byte, 32),
				BlindedSigType: 11,
				Expiration:     uint32(time.Now().Unix()),
				LookupPassword: "secret123",
			},
			expectError: false,
		},
		{
			name:    "valid with per-client auth and password",
			session: session,
			info: &BlindingInfo{
				EndpointType:   BLINDING_ENDPOINT_HASH,
				Endpoint:       make([]byte, 32),
				BlindedSigType: 11,
				Expiration:     uint32(time.Now().Unix()),
				PerClientAuth:  true,
				AuthScheme:     BLINDING_AUTH_SCHEME_PSK,
				DecryptionKey:  make([]byte, 32),
				LookupPassword: "secret123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateBlindingInfo(tt.session, tt.info)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorSubstr)
				} else if tt.errorSubstr != "" && !containsSubstring(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestBuildBlindingFlags tests the flags byte construction.
func TestBuildBlindingFlags(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name          string
		info          *BlindingInfo
		expectedFlags uint8
	}{
		{
			name: "no flags set",
			info: &BlindingInfo{
				PerClientAuth:  false,
				LookupPassword: "",
			},
			expectedFlags: 0x00,
		},
		{
			name: "per-client auth with DH",
			info: &BlindingInfo{
				PerClientAuth: true,
				AuthScheme:    BLINDING_AUTH_SCHEME_DH, // 0
			},
			expectedFlags: 0x01, // Bit 0 set, auth scheme 0 in bits 3-1
		},
		{
			name: "per-client auth with PSK",
			info: &BlindingInfo{
				PerClientAuth: true,
				AuthScheme:    BLINDING_AUTH_SCHEME_PSK, // 1
			},
			expectedFlags: 0x03, // Bit 0 set, auth scheme 1 in bits 3-1 (0x02)
		},
		{
			name: "secret required only",
			info: &BlindingInfo{
				PerClientAuth:  false,
				LookupPassword: "secret",
			},
			expectedFlags: 0x10, // Bit 4 set
		},
		{
			name: "per-client auth with PSK and secret",
			info: &BlindingInfo{
				PerClientAuth:  true,
				AuthScheme:     BLINDING_AUTH_SCHEME_PSK,
				LookupPassword: "secret",
			},
			expectedFlags: 0x13, // Bits 0, 1, 4 set
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := client.buildBlindingFlags(tt.info)
			if flags != tt.expectedFlags {
				t.Errorf("expected flags 0x%02x, got 0x%02x", tt.expectedFlags, flags)
			}
		})
	}
}

// TestBlindingInfoMessageFormat tests the wire format of BlindingInfoMessage.
func TestBlindingInfoMessageFormat(t *testing.T) {
	client := NewClient(nil)
	client.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))

	session := &Session{
		id:     0x1234,
		client: client,
	}

	// Create a test BlindingInfo with known values
	endpoint := make([]byte, 32)
	for i := range endpoint {
		endpoint[i] = byte(i)
	}

	info := &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_HASH,
		Endpoint:       endpoint,
		BlindedSigType: 0x000B, // Ed25519-SHA512
		Expiration:     0x12345678,
	}

	// Validate and build the message
	err := client.validateBlindingInfo(session, info)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	client.messageStream.Reset()
	client.messageStream.WriteUint16(session.id)
	flags := client.buildBlindingFlags(info)
	client.messageStream.WriteByte(flags)
	client.messageStream.WriteByte(info.EndpointType)
	client.messageStream.WriteUint16(info.BlindedSigType)
	client.messageStream.WriteUint32(info.Expiration)
	client.writeBlindingEndpoint(info)

	data := client.messageStream.Bytes()

	// Verify message format
	// Session ID (2 bytes)
	if data[0] != 0x12 || data[1] != 0x34 {
		t.Errorf("session ID mismatch: got %02x%02x, expected 1234", data[0], data[1])
	}

	// Flags (1 byte) - should be 0 for this test
	if data[2] != 0x00 {
		t.Errorf("flags mismatch: got 0x%02x, expected 0x00", data[2])
	}

	// Endpoint type (1 byte)
	if data[3] != BLINDING_ENDPOINT_HASH {
		t.Errorf("endpoint type mismatch: got %d, expected %d", data[3], BLINDING_ENDPOINT_HASH)
	}

	// Blinded sig type (2 bytes, big-endian)
	if data[4] != 0x00 || data[5] != 0x0B {
		t.Errorf("blinded sig type mismatch: got %02x%02x, expected 000B", data[4], data[5])
	}

	// Expiration (4 bytes, big-endian)
	if data[6] != 0x12 || data[7] != 0x34 || data[8] != 0x56 || data[9] != 0x78 {
		t.Errorf("expiration mismatch: got %02x%02x%02x%02x, expected 12345678",
			data[6], data[7], data[8], data[9])
	}

	// Endpoint (32 bytes for hash)
	for i := 0; i < 32; i++ {
		if data[10+i] != byte(i) {
			t.Errorf("endpoint byte %d mismatch: got %02x, expected %02x", i, data[10+i], byte(i))
		}
	}

	// Total length: 2 + 1 + 1 + 2 + 4 + 32 = 42 bytes
	expectedLen := 42
	if len(data) != expectedLen {
		t.Errorf("message length mismatch: got %d, expected %d", len(data), expectedLen)
	}
}

// TestBlindingInfoWithPerClientAuth tests message format with per-client authentication.
func TestBlindingInfoWithPerClientAuth(t *testing.T) {
	client := NewClient(nil)
	client.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))

	session := &Session{
		id:     1,
		client: client,
	}

	// 32-byte hash endpoint
	endpoint := make([]byte, 32)
	// 32-byte decryption key
	decryptionKey := make([]byte, 32)
	for i := range decryptionKey {
		decryptionKey[i] = byte(0xFF - i)
	}

	info := &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_HASH,
		Endpoint:       endpoint,
		BlindedSigType: 11,
		Expiration:     uint32(time.Now().Unix()),
		PerClientAuth:  true,
		AuthScheme:     BLINDING_AUTH_SCHEME_PSK,
		DecryptionKey:  decryptionKey,
	}

	err := client.validateBlindingInfo(session, info)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Build the message manually to verify format
	client.messageStream.Reset()
	client.messageStream.WriteUint16(session.id)
	flags := client.buildBlindingFlags(info)
	client.messageStream.WriteByte(flags)
	client.messageStream.WriteByte(info.EndpointType)
	client.messageStream.WriteUint16(info.BlindedSigType)
	client.messageStream.WriteUint32(info.Expiration)
	client.writeBlindingEndpoint(info)
	client.messageStream.Write(info.DecryptionKey)

	data := client.messageStream.Bytes()

	// Flags should have per-client bit and PSK auth scheme
	expectedFlags := uint8(0x03) // Bit 0 + PSK in bits 3-1
	if data[2] != expectedFlags {
		t.Errorf("flags mismatch: got 0x%02x, expected 0x%02x", data[2], expectedFlags)
	}

	// Expected length: 2 + 1 + 1 + 2 + 4 + 32 + 32 = 74 bytes
	expectedLen := 74
	if len(data) != expectedLen {
		t.Errorf("message length mismatch: got %d, expected %d", len(data), expectedLen)
	}

	// Verify decryption key is at correct offset
	decryptionKeyOffset := 42 // After endpoint
	for i := 0; i < 32; i++ {
		if data[decryptionKeyOffset+i] != byte(0xFF-i) {
			t.Errorf("decryption key byte %d mismatch", i)
		}
	}
}

// TestBlindingInfoWithLookupPassword tests message format with lookup password.
func TestBlindingInfoWithLookupPassword(t *testing.T) {
	client := NewClient(nil)
	client.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))

	session := &Session{
		id:     1,
		client: client,
	}

	endpoint := make([]byte, 32)
	password := "test-password"

	info := &BlindingInfo{
		EndpointType:   BLINDING_ENDPOINT_HASH,
		Endpoint:       endpoint,
		BlindedSigType: 11,
		Expiration:     uint32(time.Now().Unix()),
		LookupPassword: password,
	}

	err := client.validateBlindingInfo(session, info)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Build the message
	client.messageStream.Reset()
	client.messageStream.WriteUint16(session.id)
	flags := client.buildBlindingFlags(info)
	client.messageStream.WriteByte(flags)
	client.messageStream.WriteByte(info.EndpointType)
	client.messageStream.WriteUint16(info.BlindedSigType)
	client.messageStream.WriteUint32(info.Expiration)
	client.writeBlindingEndpoint(info)
	client.messageStream.WriteLenPrefixedString(info.LookupPassword)

	data := client.messageStream.Bytes()

	// Flags should have secret bit set
	expectedFlags := uint8(0x10) // Bit 4 only
	if data[2] != expectedFlags {
		t.Errorf("flags mismatch: got 0x%02x, expected 0x%02x", data[2], expectedFlags)
	}

	// Password should be at offset 42 (after hash endpoint)
	// Format: 1-byte length + password bytes
	passwordOffset := 42
	if data[passwordOffset] != byte(len(password)) {
		t.Errorf("password length mismatch: got %d, expected %d", data[passwordOffset], len(password))
	}

	actualPassword := string(data[passwordOffset+1 : passwordOffset+1+len(password)])
	if actualPassword != password {
		t.Errorf("password mismatch: got %q, expected %q", actualPassword, password)
	}
}

// TestBlindingEndpointTypes tests all endpoint type serializations.
func TestBlindingEndpointTypes(t *testing.T) {
	client := NewClient(nil)
	client.messageStream = NewStream(make([]byte, 0, I2CP_MESSAGE_SIZE))

	tests := []struct {
		name         string
		endpointType uint8
		endpoint     []byte
		expectedLen  int // Just the endpoint portion length
	}{
		{
			name:         "hash endpoint",
			endpointType: BLINDING_ENDPOINT_HASH,
			endpoint:     make([]byte, 32),
			expectedLen:  32,
		},
		{
			name:         "hostname endpoint",
			endpointType: BLINDING_ENDPOINT_HOSTNAME,
			endpoint:     []byte("test.i2p"),
			expectedLen:  9, // 1-byte length + 8 bytes
		},
		{
			name:         "destination endpoint",
			endpointType: BLINDING_ENDPOINT_DESTINATION,
			endpoint:     make([]byte, 391), // Typical destination size
			expectedLen:  391,
		},
		{
			name:         "sigkey endpoint",
			endpointType: BLINDING_ENDPOINT_SIGKEY,
			endpoint:     make([]byte, 34), // 2-byte sig type + 32-byte Ed25519 key
			expectedLen:  34,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &BlindingInfo{
				EndpointType: tt.endpointType,
				Endpoint:     tt.endpoint,
			}

			client.messageStream.Reset()
			err := client.writeBlindingEndpoint(info)
			if err != nil {
				t.Fatalf("failed to write endpoint: %v", err)
			}

			data := client.messageStream.Bytes()
			if len(data) != tt.expectedLen {
				t.Errorf("endpoint length mismatch: got %d, expected %d", len(data), tt.expectedLen)
			}
		})
	}
}

// TestBlindingInfoConstants verifies constant values match spec.
func TestBlindingInfoConstants(t *testing.T) {
	// Verify endpoint type constants
	if BLINDING_ENDPOINT_HASH != 0 {
		t.Errorf("BLINDING_ENDPOINT_HASH should be 0, got %d", BLINDING_ENDPOINT_HASH)
	}
	if BLINDING_ENDPOINT_HOSTNAME != 1 {
		t.Errorf("BLINDING_ENDPOINT_HOSTNAME should be 1, got %d", BLINDING_ENDPOINT_HOSTNAME)
	}
	if BLINDING_ENDPOINT_DESTINATION != 2 {
		t.Errorf("BLINDING_ENDPOINT_DESTINATION should be 2, got %d", BLINDING_ENDPOINT_DESTINATION)
	}
	if BLINDING_ENDPOINT_SIGKEY != 3 {
		t.Errorf("BLINDING_ENDPOINT_SIGKEY should be 3, got %d", BLINDING_ENDPOINT_SIGKEY)
	}

	// Verify auth scheme constants
	if BLINDING_AUTH_SCHEME_DH != 0 {
		t.Errorf("BLINDING_AUTH_SCHEME_DH should be 0, got %d", BLINDING_AUTH_SCHEME_DH)
	}
	if BLINDING_AUTH_SCHEME_PSK != 1 {
		t.Errorf("BLINDING_AUTH_SCHEME_PSK should be 1, got %d", BLINDING_AUTH_SCHEME_PSK)
	}

	// Verify flag constants
	if BLINDING_FLAG_PER_CLIENT != 0x01 {
		t.Errorf("BLINDING_FLAG_PER_CLIENT should be 0x01, got 0x%02x", BLINDING_FLAG_PER_CLIENT)
	}
	if BLINDING_FLAG_SECRET != 0x10 {
		t.Errorf("BLINDING_FLAG_SECRET should be 0x10, got 0x%02x", BLINDING_FLAG_SECRET)
	}

	// Verify message type constant
	if I2CP_MSG_BLINDING_INFO != 42 {
		t.Errorf("I2CP_MSG_BLINDING_INFO should be 42, got %d", I2CP_MSG_BLINDING_INFO)
	}
}
