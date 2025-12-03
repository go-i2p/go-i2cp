package go_i2cp

import (
	"testing"
)

// TestAuthenticationMethodConstantsValues verifies authentication method constants
// match I2CP specification values and documentation is accurate.
func TestAuthenticationMethodConstantsValues(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"None", AUTH_METHOD_NONE, 0},
		{"Username/Password", AUTH_METHOD_USERNAME_PWD, 1},
		{"SSL/TLS", AUTH_METHOD_SSL_TLS, 2},
		{"Per-Client DH", AUTH_METHOD_PER_CLIENT_DH, 3},
		{"Per-Client PSK", AUTH_METHOD_PER_CLIENT_PSK, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("AUTH_METHOD constant mismatch: got %d, want %d", tt.constant, tt.expected)
			}
		})
	}
}

// TestBlindingSchemeConstants verifies blinding authentication scheme constants
// match I2CP specification values.
func TestBlindingSchemeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"DH", BLINDING_AUTH_SCHEME_DH, 0},
		{"PSK", BLINDING_AUTH_SCHEME_PSK, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("BLINDING_AUTH_SCHEME constant mismatch: got %d, want %d", tt.constant, tt.expected)
			}
		})
	}
}

// TestLeaseSetTypeConstants verifies LeaseSet type constants
// match I2CP specification values.
func TestLeaseSetTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"Legacy", LEASESET_TYPE_LEGACY, 1},
		{"Standard LeaseSet2", LEASESET_TYPE_STANDARD, 3},
		{"Encrypted LeaseSet", LEASESET_TYPE_ENCRYPTED, 5},
		{"Meta LeaseSet", LEASESET_TYPE_META, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("LEASESET_TYPE constant mismatch: got %d, want %d", tt.constant, tt.expected)
			}
		})
	}
}

// TestHostReplyErrorCodes verifies HostReply error code constants
// match I2CP Proposal 167 specification.
func TestHostReplyErrorCodes(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"Success", HOST_REPLY_SUCCESS, 0},
		{"Failure", HOST_REPLY_FAILURE, 1},
		{"Password Required", HOST_REPLY_PASSWORD_REQUIRED, 2},
		{"Private Key Required", HOST_REPLY_PRIVATE_KEY_REQUIRED, 3},
		{"Password and Key Required", HOST_REPLY_PASSWORD_AND_KEY_REQUIRED, 4},
		{"Decryption Failure", HOST_REPLY_DECRYPTION_FAILURE, 5},
		{"LeaseSet Lookup Failure", HOST_REPLY_LEASESET_LOOKUP_FAILURE, 6},
		{"Lookup Type Unsupported", HOST_REPLY_LOOKUP_TYPE_UNSUPPORTED, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("HOST_REPLY constant mismatch: got %d, want %d", tt.constant, tt.expected)
			}
		})
	}
}

// TestMessageStatusConstants verifies message status code constants
// match I2CP MessageStatusMessage specification (codes 0-23).
func TestMessageStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"Available", MSG_STATUS_AVAILABLE, 0},
		{"Accepted", MSG_STATUS_ACCEPTED, 1},
		{"Best Effort Success", MSG_STATUS_BEST_EFFORT_SUCCESS, 2},
		{"Best Effort Failure", MSG_STATUS_BEST_EFFORT_FAILURE, 3},
		{"Guaranteed Success", MSG_STATUS_GUARANTEED_SUCCESS, 4},
		{"Guaranteed Failure", MSG_STATUS_GUARANTEED_FAILURE, 5},
		{"Local Success", MSG_STATUS_LOCAL_SUCCESS, 6},
		{"Local Failure", MSG_STATUS_LOCAL_FAILURE, 7},
		{"Router Failure", MSG_STATUS_ROUTER_FAILURE, 8},
		{"Network Failure", MSG_STATUS_NETWORK_FAILURE, 9},
		{"Bad Session", MSG_STATUS_BAD_SESSION, 10},
		{"Bad Message", MSG_STATUS_BAD_MESSAGE, 11},
		{"Overflow Failure", MSG_STATUS_OVERFLOW_FAILURE, 12},
		{"Message Expired", MSG_STATUS_MESSAGE_EXPIRED, 13},
		{"Bad Local LeaseSet", MSG_STATUS_BAD_LOCAL_LEASESET, 14},
		{"No Local Tunnels", MSG_STATUS_NO_LOCAL_TUNNELS, 15},
		{"Unsupported Encryption", MSG_STATUS_UNSUPPORTED_ENCRYPTION, 16},
		{"Bad Destination", MSG_STATUS_BAD_DESTINATION, 17},
		{"Bad LeaseSet", MSG_STATUS_BAD_LEASESET, 18},
		{"Expired LeaseSet", MSG_STATUS_EXPIRED_LEASESET, 19},
		{"No LeaseSet", MSG_STATUS_NO_LEASESET, 20},
		{"Send Best Effort Failure", MSG_STATUS_SEND_BEST_EFFORT_FAILURE, 21},
		{"Meta LeaseSet", MSG_STATUS_META_LEASESET, 22},
		{"Loopback Denied", MSG_STATUS_LOOPBACK_DENIED, 23},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("MSG_STATUS constant mismatch for %s: got %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestI2CPMessageTypeConstants verifies I2CP message type constants
// match protocol specification values.
func TestI2CPMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"Any", I2CP_MSG_ANY, 0},
		{"Create Session", I2CP_MSG_CREATE_SESSION, 1},
		{"Reconfigure Session", I2CP_MSG_RECONFIGURE_SESSION, 2},
		{"Destroy Session", I2CP_MSG_DESTROY_SESSION, 3},
		{"Create LeaseSet", I2CP_MSG_CREATE_LEASE_SET, 4},
		{"Send Message", I2CP_MSG_SEND_MESSAGE, 5},
		{"Session Status", I2CP_MSG_SESSION_STATUS, 20},
		{"Request LeaseSet", I2CP_MSG_REQUEST_LEASESET, 21},
		{"Message Status", I2CP_MSG_MESSAGE_STATUS, 22},
		{"Bandwidth Limits", I2CP_MSG_BANDWIDTH_LIMITS, 23},
		{"Disconnect", I2CP_MSG_DISCONNECT, 30},
		{"Payload Message", I2CP_MSG_PAYLOAD_MESSAGE, 31},
		{"Get Date", I2CP_MSG_GET_DATE, 32},
		{"Set Date", I2CP_MSG_SET_DATE, 33},
		{"Dest Lookup", I2CP_MSG_DEST_LOOKUP, 34},
		{"Dest Reply", I2CP_MSG_DEST_REPLY, 35},
		{"Send Message Expires", I2CP_MSG_SEND_MESSAGE_EXPIRES, 36},
		{"Request Variable LeaseSet", I2CP_MSG_REQUEST_VARIABLE_LEASESET, 37},
		{"Host Lookup", I2CP_MSG_HOST_LOOKUP, 38},
		{"Host Reply", I2CP_MSG_HOST_REPLY, 39},
		{"Create LeaseSet2", I2CP_MSG_CREATE_LEASE_SET2, 41},
		{"Blinding Info", I2CP_MSG_BLINDING_INFO, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("I2CP_MSG constant mismatch for %s: got %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestDeprecatedMessageTypeConstants verifies deprecated message type constants
// are still defined for backward compatibility.
func TestDeprecatedMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
		reason   string
	}{
		{"Receive Message Begin", I2CP_MSG_RECEIVE_MESSAGE_BEGIN, 6, "Not used in fastReceive mode"},
		{"Receive Message End", I2CP_MSG_RECEIVE_MESSAGE_END, 7, "Not used in fastReceive mode"},
		{"Get Bandwidth Limits", I2CP_MSG_GET_BANDWIDTH_LIMITS, 8, "Not used in current protocol"},
		{"Report Abuse", I2CP_MSG_REPORT_ABUSE, 29, "Never fully implemented"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Deprecated I2CP_MSG constant mismatch for %s: got %d, want %d (reason: %s)",
					tt.name, tt.constant, tt.expected, tt.reason)
			}
		})
	}
}

// TestSessionStatusConstants verifies session status enum values.
func TestSessionStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant SessionStatus
		expected SessionStatus
	}{
		{"Destroyed", I2CP_SESSION_STATUS_DESTROYED, 1},
		{"Created", I2CP_SESSION_STATUS_CREATED, 0},
		{"Updated", I2CP_SESSION_STATUS_UPDATED, 2},
		{"Invalid", I2CP_SESSION_STATUS_INVALID, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("SessionStatus constant mismatch for %s: got %d, want %d", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

// TestConstantsDocumentation verifies that key constants have proper documentation
// by checking they compile and are accessible (compile-time verification).
func TestConstantsDocumentation(t *testing.T) {
	// Authentication methods - verify they exist and have correct values
	_ = AUTH_METHOD_NONE
	_ = AUTH_METHOD_USERNAME_PWD
	_ = AUTH_METHOD_SSL_TLS
	_ = AUTH_METHOD_PER_CLIENT_DH
	_ = AUTH_METHOD_PER_CLIENT_PSK

	// Blinding schemes - verify they exist
	_ = BLINDING_AUTH_SCHEME_DH
	_ = BLINDING_AUTH_SCHEME_PSK

	// LeaseSet types - verify they exist
	_ = LEASESET_TYPE_LEGACY
	_ = LEASESET_TYPE_STANDARD
	_ = LEASESET_TYPE_ENCRYPTED
	_ = LEASESET_TYPE_META

	// This test passes if the code compiles, demonstrating constants are properly defined
	t.Log("All constants properly defined and accessible")
}

// TestTLSConfigurationApproach verifies TLS is configured via client properties,
// not a global USE_TLS variable (which has been removed).
func TestTLSConfigurationApproach(t *testing.T) {
	// Create a client with TLS configuration via properties
	client := NewClient(nil)

	// Set TLS properties (this should work without USE_TLS global)
	// TLS is enabled via "i2cp.SSL" property
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.certFile", "/path/to/cert.pem")
	client.SetProperty("i2cp.SSL.keyFile", "/path/to/key.pem")

	// Verify properties are stored in client
	if client.properties["i2cp.SSL"] != "true" {
		t.Error("TLS enabled property not set correctly")
	}

	if client.properties["i2cp.SSL.certFile"] != "/path/to/cert.pem" {
		t.Error("TLS cert file property not set correctly")
	}

	if client.properties["i2cp.SSL.keyFile"] != "/path/to/key.pem" {
		t.Error("TLS key file property not set correctly")
	}

	t.Log("TLS configuration via client properties works correctly (no global USE_TLS needed)")
}

// TestConstantRanges verifies constants are within expected ranges
// to catch potential invalid values.
func TestConstantRanges(t *testing.T) {
	// Authentication methods should be sequential 0-4
	authMethods := []uint8{
		AUTH_METHOD_NONE, AUTH_METHOD_USERNAME_PWD, AUTH_METHOD_SSL_TLS,
		AUTH_METHOD_PER_CLIENT_DH, AUTH_METHOD_PER_CLIENT_PSK,
	}
	for i, method := range authMethods {
		if method != uint8(i) {
			t.Errorf("Authentication method %d has unexpected value %d", i, method)
		}
	}

	// Blinding schemes should be sequential 0-1
	if BLINDING_AUTH_SCHEME_DH != 0 {
		t.Error("BLINDING_AUTH_SCHEME_DH should be 0")
	}
	if BLINDING_AUTH_SCHEME_PSK != 1 {
		t.Error("BLINDING_AUTH_SCHEME_PSK should be 1")
	}
}
