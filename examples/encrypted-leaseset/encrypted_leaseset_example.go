package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
	"golang.org/x/crypto/pbkdf2"
)

// Example demonstrating LeaseSet2 and blinding info callbacks
//
// This example shows how to handle modern LeaseSet2 publications and
// blinding information for encrypted destinations.
//
// Requirements:
// - I2P router version 0.9.38+ (LeaseSet2 support)
// - I2P router version 0.9.43+ (blinding support)

func main() {
	fmt.Println("=== Encrypted LeaseSet Example ===")
	fmt.Println("Demonstrates LeaseSet2 and blinding info callbacks")
	fmt.Println()

	// Example 1: Monitor LeaseSet2 publications
	if err := monitorLeaseSet2(); err != nil {
		log.Fatalf("LeaseSet2 monitoring example failed: %v", err)
	}

	fmt.Println()

	// Example 2: Handle blinding information for encrypted LeaseSets
	if err := handleBlindingInfo(); err != nil {
		log.Fatalf("Blinding info example failed: %v", err)
	}

	fmt.Println()
	fmt.Println("Encrypted LeaseSet example completed successfully!")
}

// monitorLeaseSet2 demonstrates handling LeaseSet2 callbacks
func monitorLeaseSet2() error {
	fmt.Println("--- Example 1: Monitor LeaseSet2 Publications ---")

	// Create client
	client := i2cp.NewClient(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()
	fmt.Println("✓ Connected to I2P router")

	// Create session with LeaseSet2 callback
	callbacks := i2cp.SessionCallbacks{
		OnLeaseSet2: func(session *i2cp.Session, leaseSet *i2cp.LeaseSet2) {
			fmt.Printf("✓ LeaseSet2 published!\n")
			fmt.Printf("  - Expires: %s\n", leaseSet.Expires())
			fmt.Printf("  - Published: %s\n", leaseSet.Published())
			fmt.Printf("  - Lease count: %d\n", leaseSet.LeaseCount())
			
			if leaseSet.IsExpired() {
				fmt.Println("  ⚠ WARNING: LeaseSet is expired!")
			} else {
				fmt.Println("  ✓ LeaseSet is valid")
			}
		},
	}

	session := i2cp.NewSession(client, callbacks)

	// Create session
	fmt.Println("Creating session...")
	if err := client.CreateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	fmt.Println("✓ Session created successfully")
	fmt.Println("Waiting for LeaseSet2 publication...")

	// Keep session alive to receive LeaseSet2 callback
	time.Sleep(8 * time.Second)

	return nil
}

// handleBlindingInfo demonstrates secure storage of blinding parameters
func handleBlindingInfo() error {
	fmt.Println("--- Example 2: Handle Blinding Information ---")

	// Storage for blinding parameters (in production, use secure storage)
	var storedBlindingParams []byte
	var storedScheme, storedFlags uint16

	// Create client
	client := i2cp.NewClient(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	// Create session with blinding info callback
	callbacks := i2cp.SessionCallbacks{
		OnBlindingInfo: func(session *i2cp.Session, blindingScheme, blindingFlags uint16, blindingParams []byte) {
			fmt.Printf("✓ Blinding info received!\n")
			fmt.Printf("  - Blinding scheme: %d ", blindingScheme)
			switch blindingScheme {
			case 0:
				fmt.Println("(DH)")
			case 1:
				fmt.Println("(PSK)")
			default:
				fmt.Println("(Unknown)")
			}
			fmt.Printf("  - Blinding flags: 0x%04x\n", blindingFlags)
			fmt.Printf("  - Blinding params: %d bytes\n", len(blindingParams))
			
			// CRITICAL: Store blinding parameters securely!
			// These are required to:
			// - Decrypt the encrypted LeaseSet
			// - Allow clients to connect to this destination
			// - Cannot be recovered if lost!
			
			storedScheme = blindingScheme
			storedFlags = blindingFlags
			storedBlindingParams = make([]byte, len(blindingParams))
			copy(storedBlindingParams, blindingParams)
			
			// Encrypt blinding params with password (for secure storage)
			password := "your-strong-password-here"
			encrypted, err := encryptBlindingParams(blindingParams, password)
			if err != nil {
				log.Printf("ERROR: Failed to encrypt blinding params: %v", err)
				return
			}
			
			fmt.Printf("  ✓ Encrypted blinding params: %d bytes\n", len(encrypted))
			fmt.Println()
			fmt.Println("  IMPORTANT: Save this encrypted data to secure storage!")
			fmt.Println("  - Store in password manager or KMS")
			fmt.Println("  - Backup to multiple locations")
			fmt.Println("  - Never commit to version control")
			fmt.Println("  - Required for all future connections")
		},
		OnLeaseSet2: func(session *i2cp.Session, leaseSet *i2cp.LeaseSet2) {
			fmt.Printf("✓ LeaseSet2 published with blinding enabled\n")
			fmt.Printf("  - Expires: %s\n", leaseSet.Expires())
			fmt.Printf("  - This destination is now encrypted!\n")
		},
	}

	session := i2cp.NewSession(client, callbacks)

	// Note: To enable blinding, you would configure the router's I2CP settings
	// or use SessionConfig when creating the session. The router will then
	// call OnBlindingInfo when blinding is enabled.

	fmt.Println("Creating session...")
	if err := client.CreateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	fmt.Println("✓ Session created successfully")
	fmt.Println("Waiting for blinding info...")

	// Keep session alive
	time.Sleep(8 * time.Second)

	if len(storedBlindingParams) > 0 {
		fmt.Println()
		fmt.Printf("✓ Stored blinding parameters (%d bytes) for future use\n", len(storedBlindingParams))
		fmt.Printf("  Scheme: %d, Flags: 0x%04x\n", storedScheme, storedFlags)
	}

	return nil
}

// encryptBlindingParams encrypts blinding parameters with a password
// Using AES-256-GCM with PBKDF2 key derivation
func encryptBlindingParams(params []byte, password string) ([]byte, error) {
	// Derive encryption key from password using PBKDF2
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// PBKDF2 with SHA-256, 100,000 iterations
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: ciphertext = salt || nonce || encrypted_data || auth_tag
	ciphertext := gcm.Seal(nil, nonce, params, nil)
	
	// Return: salt || nonce || ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// decryptBlindingParams decrypts blinding parameters with a password
func decryptBlindingParams(encrypted []byte, password string) ([]byte, error) {
	if len(encrypted) < 32+12 { // salt + nonce minimum
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract components
	salt := encrypted[:32]
	nonce := encrypted[32:44] // GCM nonce is 12 bytes
	ciphertext := encrypted[44:]

	// Derive key from password
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}
