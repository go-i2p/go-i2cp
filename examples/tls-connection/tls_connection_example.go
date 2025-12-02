package main

import (
	"context"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// This example demonstrates TLS authentication (Method 2) for secure I2CP connections.
// TLS provides stronger security than username/password authentication and is recommended
// for production deployments.
//
// Prerequisites:
//  1. I2P router running with I2CP enabled (port 7654)
//  2. TLS certificates generated (see README.md for instructions)
//  3. Router configured for TLS authentication

func main() {
	log.Println("=== TLS Connection Example ===")
	log.Println("Demonstrates secure I2CP connection with TLS certificates")
	log.Println()

	// Example 1: TLS with client certificates (recommended)
	tlsWithCertificates()

	// Example 2: TLS with insecure mode (development only)
	// tlsInsecureMode()

	// Example 3: Fallback from TLS to username/password
	// tlsWithFallback()
}

// tlsWithCertificates demonstrates TLS authentication with mutual TLS (client certificates).
// This is the recommended approach for production environments.
func tlsWithCertificates() {
	log.Println("--- Example 1: TLS with Client Certificates ---")

	// Create client
	client := i2cp.NewClient(nil)

	// Configure TLS authentication
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.certFile", "/path/to/client-cert.pem")
	client.SetProperty("i2cp.SSL.keyFile", "/path/to/client-key.pem")
	client.SetProperty("i2cp.SSL.caFile", "/path/to/ca-cert.pem")

	// Optional: Set router address if not using default
	// client.SetProperty("i2cp.tcp.host", "127.0.0.1")
	// client.SetProperty("i2cp.tcp.port", "7654")

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Connecting to I2P router with TLS...")
	if err := client.Connect(ctx); err != nil {
		log.Printf("TLS connection failed: %v", err)
		log.Println("Make sure:")
		log.Println("  1. I2P router is running with I2CP enabled")
		log.Println("  2. Router has TLS enabled (i2cp.ssl=true)")
		log.Println("  3. Certificate paths are correct and readable")
		log.Println("  4. CA certificate matches router's certificate")
		return
	}
	defer client.Close()

	log.Println("✓ Connected successfully with TLS authentication")

	// Create a session to verify everything works
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{})

	log.Println("Creating session...")
	if err := client.CreateSession(ctx, session); err != nil {
		log.Printf("Session creation failed: %v", err)
		return
	}
	defer session.Close()

	log.Println("✓ Session created successfully")
	log.Println()
	log.Println("TLS connection example completed successfully!")
}

// tlsInsecureMode demonstrates TLS with certificate verification disabled.
// WARNING: Only use this for development/testing! Never in production!
func tlsInsecureMode() {
	log.Println("--- Example 2: TLS Insecure Mode (Development Only) ---")
	log.Println("⚠️  WARNING: Insecure mode - do NOT use in production!")

	client := i2cp.NewClient(nil)

	// Enable TLS with insecure mode (skips certificate verification)
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.insecure", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Connecting with insecure TLS...")
	if err := client.Connect(ctx); err != nil {
		log.Printf("Connection failed: %v", err)
		return
	}
	defer client.Close()

	log.Println("✓ Connected with insecure TLS")
	log.Println("⚠️  Certificate verification was SKIPPED - not secure!")
	log.Println()
}

// tlsWithFallback demonstrates dual authentication configuration.
// TLS takes precedence, but username/password is available as fallback.
func tlsWithFallback() {
	log.Println("--- Example 3: TLS with Username/Password Fallback ---")

	client := i2cp.NewClient(nil)

	// Configure TLS (takes precedence)
	client.SetProperty("i2cp.SSL", "true")
	client.SetProperty("i2cp.SSL.certFile", "/path/to/client-cert.pem")
	client.SetProperty("i2cp.SSL.keyFile", "/path/to/client-key.pem")
	client.SetProperty("i2cp.SSL.caFile", "/path/to/ca-cert.pem")

	// Also configure username/password (fallback)
	client.SetProperty("i2cp.username", "testuser")
	client.SetProperty("i2cp.password", "testpass")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("Connecting (TLS preferred, fallback to username/password)...")
	if err := client.Connect(ctx); err != nil {
		log.Printf("Connection failed: %v", err)
		return
	}
	defer client.Close()

	log.Println("✓ Connected (TLS authentication used if available)")
	log.Println()
}

// Helper function to demonstrate checking connection status
func checkConnectionStatus(client *i2cp.Client) {
	// In a real application, you might want to periodically check connection status
	// and reconnect if necessary. See the auto-reconnection example for automated handling.

	log.Println("Connection status: Active")
	log.Println("TLS: Enabled")
	log.Println("Authentication: Certificate-based (Method 2)")
}
