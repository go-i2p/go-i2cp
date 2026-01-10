package go_i2cp

import (
	"strings"
	"testing"
)

// TestVersionConstants verifies the predefined version constants match spec requirements.
func TestVersionConstants(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		expected string
	}{
		{"VersionFastReceive", VersionFastReceive, "0.9.4"},
		{"VersionHostLookup", VersionHostLookup, "0.9.11"},
		{"VersionMultiSession", VersionMultiSession, "0.9.21"},
		{"VersionCreateLeaseSet2", VersionCreateLeaseSet2, "0.9.39"},
		{"VersionBlindingInfo", VersionBlindingInfo, "0.9.43"},
		{"VersionProposal167", VersionProposal167, "0.9.66"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("%s.String() = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

// TestVersionAtLeast tests the AtLeast method for version comparison.
func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		v        Version
		other    Version
		expected bool
	}{
		{
			name:     "equal versions",
			v:        Version{major: 0, minor: 9, micro: 43},
			other:    Version{major: 0, minor: 9, micro: 43},
			expected: true,
		},
		{
			name:     "greater major",
			v:        Version{major: 1, minor: 0, micro: 0},
			other:    Version{major: 0, minor: 9, micro: 99},
			expected: true,
		},
		{
			name:     "greater minor",
			v:        Version{major: 0, minor: 10, micro: 0},
			other:    Version{major: 0, minor: 9, micro: 99},
			expected: true,
		},
		{
			name:     "greater micro",
			v:        Version{major: 0, minor: 9, micro: 44},
			other:    Version{major: 0, minor: 9, micro: 43},
			expected: true,
		},
		{
			name:     "less than",
			v:        Version{major: 0, minor: 9, micro: 42},
			other:    Version{major: 0, minor: 9, micro: 43},
			expected: false,
		},
		{
			name:     "less minor",
			v:        Version{major: 0, minor: 8, micro: 99},
			other:    Version{major: 0, minor: 9, micro: 0},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.AtLeast(tt.other); got != tt.expected {
				t.Errorf("Version{%d.%d.%d}.AtLeast(Version{%d.%d.%d}) = %v, want %v",
					tt.v.major, tt.v.minor, tt.v.micro,
					tt.other.major, tt.other.minor, tt.other.micro,
					got, tt.expected)
			}
		})
	}
}

// TestVersionString tests the String method for version formatting.
func TestVersionString(t *testing.T) {
	tests := []struct {
		name     string
		v        Version
		expected string
	}{
		{
			name:     "standard version",
			v:        Version{major: 0, minor: 9, micro: 67},
			expected: "0.9.67",
		},
		{
			name:     "with qualifier",
			v:        Version{major: 0, minor: 9, micro: 67, qualifier: 1},
			expected: "0.9.67.1",
		},
		{
			name:     "original string preserved",
			v:        Version{major: 0, minor: 9, micro: 67, version: "0.9.67-test"},
			expected: "0.9.67-test",
		},
		{
			name:     "major version",
			v:        Version{major: 2, minor: 0, micro: 0},
			expected: "2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.String(); got != tt.expected {
				t.Errorf("Version.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestSupportsVersion tests the Client.SupportsVersion method.
func TestSupportsVersion(t *testing.T) {
	tests := []struct {
		name          string
		routerVersion Version
		checkVersion  Version
		expected      bool
	}{
		{
			name:          "modern router supports BlindingInfo",
			routerVersion: Version{major: 0, minor: 9, micro: 67},
			checkVersion:  VersionBlindingInfo,
			expected:      true,
		},
		{
			name:          "old router does not support BlindingInfo",
			routerVersion: Version{major: 0, minor: 9, micro: 40},
			checkVersion:  VersionBlindingInfo,
			expected:      false,
		},
		{
			name:          "exact version match",
			routerVersion: Version{major: 0, minor: 9, micro: 43},
			checkVersion:  VersionBlindingInfo,
			expected:      true,
		},
		{
			name:          "router supports HostLookup",
			routerVersion: Version{major: 0, minor: 9, micro: 11},
			checkVersion:  VersionHostLookup,
			expected:      true,
		},
		{
			name:          "very old router",
			routerVersion: Version{major: 0, minor: 9, micro: 3},
			checkVersion:  VersionFastReceive,
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				crypto:     NewCrypto(),
				properties: make(map[string]string),
				sessions:   make(map[uint16]*Session),
				router:     RouterInfo{version: tt.routerVersion},
			}

			if got := client.SupportsVersion(tt.checkVersion); got != tt.expected {
				t.Errorf("SupportsVersion(%s) with router %s = %v, want %v",
					tt.checkVersion.String(), tt.routerVersion.String(), got, tt.expected)
			}
		})
	}
}

// TestSupportsVersion_Uninitialized tests that SupportsVersion returns false for uninitialized client.
func TestSupportsVersion_Uninitialized(t *testing.T) {
	client := &Client{} // Zero-value client is uninitialized

	if client.SupportsVersion(VersionHostLookup) {
		t.Error("SupportsVersion should return false for uninitialized client")
	}
}

// TestMsgCreateLeaseSet2_VersionCheck tests that msgCreateLeaseSet2 enforces version requirement.
func TestMsgCreateLeaseSet2_VersionCheck(t *testing.T) {
	// Test that old router versions are rejected
	client := &Client{
		crypto:        NewCrypto(),
		properties:    make(map[string]string),
		sessions:      make(map[uint16]*Session),
		router:        RouterInfo{version: Version{major: 0, minor: 9, micro: 38}},
		messageStream: NewStream(make([]byte, 0, 1024)),
	}

	session := &Session{
		id:     1,
		config: &SessionConfig{destination: &Destination{}},
	}

	err := client.msgCreateLeaseSet2(session, 1, true)
	if err == nil {
		t.Error("expected error for old router, got nil")
	} else if !strings.Contains(err.Error(), "does not support CreateLeaseSet2") {
		t.Errorf("expected version error, got: %v", err)
	}
}

// TestMsgBlindingInfo_VersionCheck tests that msgBlindingInfo enforces version requirement.
func TestMsgBlindingInfo_VersionCheck(t *testing.T) {
	// Test that old router versions are rejected
	client := &Client{
		crypto:        NewCrypto(),
		properties:    make(map[string]string),
		sessions:      make(map[uint16]*Session),
		router:        RouterInfo{version: Version{major: 0, minor: 9, micro: 42}},
		messageStream: NewStream(make([]byte, 0, 1024)),
	}

	session := &Session{id: 1}
	info := &BlindingInfo{
		EndpointType: BLINDING_ENDPOINT_HASH,
		Endpoint:     make([]byte, 32),
	}

	err := client.msgBlindingInfo(session, info, true)
	if err == nil {
		t.Error("expected error for old router, got nil")
	} else if !strings.Contains(err.Error(), "does not support BlindingInfo") {
		t.Errorf("expected version error, got: %v", err)
	}
}

// TestMsgHostLookup_VersionCheck tests that msgHostLookup enforces version requirement.
func TestMsgHostLookup_VersionCheck(t *testing.T) {
	// Test that old router versions are rejected
	client := &Client{
		crypto:        NewCrypto(),
		properties:    make(map[string]string),
		sessions:      make(map[uint16]*Session),
		router:        RouterInfo{version: Version{major: 0, minor: 9, micro: 10}},
		messageStream: NewStream(make([]byte, 0, 1024)),
	}

	err := client.msgHostLookup(nil, 1, 30000, HOST_LOOKUP_TYPE_HASH, make([]byte, 32), true)
	if err == nil {
		t.Error("expected error for old router, got nil")
	} else if !strings.Contains(err.Error(), "does not support HostLookup") {
		t.Errorf("expected version error, got: %v", err)
	}
}
