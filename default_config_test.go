package go_i2cp

import (
	"testing"
)

// TestDefaultProperties verifies that defaultProperties includes all required tunnel configuration
// per PLAN.md Task 1.2: Fix Default Session Configuration
func TestDefaultProperties(t *testing.T) {
	tests := []struct {
		name     string
		property string
		want     string
	}{
		{
			name:     "inbound tunnel quantity",
			property: "inbound.quantity",
			want:     "3",
		},
		{
			name:     "inbound tunnel length",
			property: "inbound.length",
			want:     "3",
		},
		{
			name:     "outbound tunnel quantity",
			property: "outbound.quantity",
			want:     "3",
		},
		{
			name:     "outbound tunnel length",
			property: "outbound.length",
			want:     "3",
		},
		{
			name:     "inbound backup quantity",
			property: "inbound.backupQuantity",
			want:     "0",
		},
		{
			name:     "outbound backup quantity",
			property: "outbound.backupQuantity",
			want:     "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, exists := defaultProperties[tt.property]
			if !exists {
				t.Errorf("defaultProperties missing required property: %s", tt.property)
				return
			}

			if got != tt.want {
				t.Errorf("defaultProperties[%s] = %q, want %q", tt.property, got, tt.want)
			}
		})
	}
}

// TestNewSessionCreatesDestination verifies that NewSession auto-creates destination
// per PLAN.md Task 1.2: Fix Default Session Configuration
func TestNewSessionCreatesDestination(t *testing.T) {
	t.Run("NewSession creates destination automatically", func(t *testing.T) {
		callbacks := &ClientCallBacks{}
		client := NewClient(callbacks)

		session := NewSession(client, SessionCallbacks{})

		if session == nil {
			t.Fatal("NewSession() returned nil")
		}

		// Use public Destination() method to verify destination was created
		dest := session.Destination()
		if dest == nil {
			t.Error("Expected destination to be auto-created, got nil")
		}

		// Destination should have valid base64 representation
		if dest != nil && dest.b64 == "" {
			t.Error("Expected destination to have base64 representation")
		}
	})

	t.Run("session with auto-created destination is usable", func(t *testing.T) {
		callbacks := &ClientCallBacks{}
		client := NewClient(callbacks)

		session := NewSession(client, SessionCallbacks{})

		// Should be able to get destination without panicking
		dest := session.Destination()
		if dest == nil {
			t.Error("Expected non-nil destination")
		}

		// Destination should have valid base64 representation
		if dest != nil && dest.b64 == "" {
			t.Error("Expected destination to have base64 representation")
		}
	})
}

// TestDefaultTunnelPropertiesExist validates that defaultProperties includes tunnel configuration
// per PLAN.md Task 1.2: Fix Default Session Configuration
func TestDefaultTunnelPropertiesExist(t *testing.T) {
	// Test that the defaultProperties map includes tunnel configuration
	// This ensures sessions can actually send/receive messages
	tunnelProperties := []string{
		"inbound.quantity",
		"inbound.length",
		"outbound.quantity",
		"outbound.length",
		"inbound.backupQuantity",
		"outbound.backupQuantity",
	}

	for _, prop := range tunnelProperties {
		t.Run("property_"+prop, func(t *testing.T) {
			_, exists := defaultProperties[prop]
			if !exists {
				t.Errorf("defaultProperties missing critical tunnel property: %s", prop)
			}
		})
	}
}

// TestDefaultTunnelConfiguration validates the tunnel defaults provide proper anonymity
func TestDefaultTunnelConfiguration(t *testing.T) {
	// According to PLAN.md: "3 tunnels with 3 hops each provides strong anonymity"
	t.Run("default provides strong anonymity (3x3 configuration)", func(t *testing.T) {
		inboundQuantity := defaultProperties["inbound.quantity"]
		inboundLength := defaultProperties["inbound.length"]
		outboundQuantity := defaultProperties["outbound.quantity"]
		outboundLength := defaultProperties["outbound.length"]

		// Strong anonymity configuration
		if inboundQuantity != "3" || inboundLength != "3" {
			t.Errorf("Inbound config = %sx%s, want 3x3 for strong anonymity",
				inboundQuantity, inboundLength)
		}

		if outboundQuantity != "3" || outboundLength != "3" {
			t.Errorf("Outbound config = %sx%s, want 3x3 for strong anonymity",
				outboundQuantity, outboundLength)
		}
	})

	t.Run("backup tunnels disabled by default", func(t *testing.T) {
		inboundBackup := defaultProperties["inbound.backupQuantity"]
		outboundBackup := defaultProperties["outbound.backupQuantity"]

		// Backups should be 0 by default (can be increased for high-availability)
		if inboundBackup != "0" {
			t.Errorf("inbound.backupQuantity = %s, want 0", inboundBackup)
		}

		if outboundBackup != "0" {
			t.Errorf("outbound.backupQuantity = %s, want 0", outboundBackup)
		}
	})
}
