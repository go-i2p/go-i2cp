package go_i2cp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSessionConfig_propFromString tests the private propFromString method
func TestSessionConfig_propFromString(t *testing.T) {
	config := SessionConfig{}

	tests := []struct {
		name     string
		propName string
		want     SessionConfigProperty
	}{
		{
			name:     "valid property - inbound.quantity",
			propName: "inbound.quantity",
			want:     SESSION_CONFIG_PROP_INBOUND_QUANTITY,
		},
		{
			name:     "valid property - outbound.quantity",
			propName: "outbound.quantity",
			want:     SESSION_CONFIG_PROP_OUTBOUND_QUANTITY,
		},
		{
			name:     "valid property - inbound.length",
			propName: "inbound.length",
			want:     SESSION_CONFIG_PROP_INBOUND_LENGTH,
		},
		{
			name:     "valid property - outbound.length",
			propName: "outbound.length",
			want:     SESSION_CONFIG_PROP_OUTBOUND_LENGTH,
		},
		{
			name:     "invalid property",
			propName: "nonexistent.property",
			want:     SessionConfigProperty(-1),
		},
		{
			name:     "empty string",
			propName: "",
			want:     SessionConfigProperty(-1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.propFromString(tt.propName)
			if got != tt.want {
				t.Errorf("propFromString(%q) = %v, want %v", tt.propName, got, tt.want)
			}
		})
	}
}

// TestNewSessionConfigFromDestinationFile tests loading session config from destination file
func TestNewSessionConfigFromDestinationFile(t *testing.T) {
	crypto := NewCrypto()

	t.Run("nonexistent file creates new destination", func(t *testing.T) {
		// Use temp file that doesn't exist
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "nonexistent.dat")

		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have created a new destination
		if config.destination == nil {
			t.Error("Expected destination to be created, got nil")
		}

		// Should have written the file
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Error("Expected destination file to be created")
		}
	})

	t.Run("valid destination file", func(t *testing.T) {
		// Create a valid destination file
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "test.dat")

		// Create and save a destination
		dest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}
		err = dest.WriteToFile(filename)
		if err != nil {
			t.Fatalf("Failed to write destination file: %v", err)
		}

		// Load it back
		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have loaded the destination
		if config.destination == nil {
			t.Error("Expected destination to be loaded, got nil")
		}

		// Verify it matches (compare base64)
		if config.destination.b64 != dest.b64 {
			t.Error("Loaded destination doesn't match original")
		}
	})

	t.Run("empty filename", func(t *testing.T) {
		config := NewSessionConfigFromDestinationFile("", crypto)

		// Should have created a new destination
		if config.destination == nil {
			t.Error("Expected destination to be created, got nil")
		}

		// Should NOT have tried to write a file
		if _, err := os.Stat(""); err == nil {
			t.Error("Should not have created a file with empty name")
		}
	})

	t.Run("corrupted file creates new destination", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "corrupted.dat")

		// Write invalid data
		err := os.WriteFile(filename, []byte("invalid destination data"), 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		config := NewSessionConfigFromDestinationFile(filename, crypto)

		// Should have created a new destination (not loaded corrupted one)
		if config.destination == nil {
			t.Error("Expected new destination to be created, got nil")
		}
	})
}

// TestNewDestinationFromFile tests loading a destination from file
func TestNewDestinationFromFile(t *testing.T) {
	crypto := NewCrypto()

	t.Run("valid destination file", func(t *testing.T) {
		// Create a destination and save it
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "test_dest.dat")

		originalDest, err := NewDestination(crypto)
		if err != nil {
			t.Fatalf("Failed to create destination: %v", err)
		}

		err = originalDest.WriteToFile(filename)
		if err != nil {
			t.Fatalf("Failed to write destination: %v", err)
		}

		// Open and read it back
		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		loadedDest, err := NewDestinationFromFile(file, crypto)
		if err != nil {
			t.Fatalf("NewDestinationFromFile failed: %v", err)
		}

		// Verify they match
		if loadedDest.b64 != originalDest.b64 {
			t.Error("Loaded destination doesn't match original")
		}
	})

	t.Run("invalid file data", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "invalid.dat")

		// Write invalid data
		err := os.WriteFile(filename, []byte("not a valid destination"), 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		_, err = NewDestinationFromFile(file, crypto)
		if err == nil {
			t.Error("Expected error for invalid destination data, got nil")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "empty.dat")

		// Create empty file
		err := os.WriteFile(filename, []byte{}, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		file, err := os.Open(filename)
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		_, err = NewDestinationFromFile(file, crypto)
		if err == nil {
			t.Error("Expected error for empty file, got nil")
		}
	})
}
