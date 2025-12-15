// Example program to test CreateSession signature fix
// This verifies that the signature is now valid according to I2CP specification
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	fmt.Println("=== CreateSession Signature Fix Test ===")
	fmt.Println("This test verifies the fix for 'Invalid signature on CreateSessionMessage' bug")
	fmt.Println()

	// Create client with callbacks to track connection status
	client := i2cp.NewClient(&i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			log.Printf("❌ Disconnected: %s", reason)
			if reason == "Invalid signature on CreateSessionMessage" {
				log.Fatal("BUG STILL PRESENT: Router rejected signature")
			}
		},
	})

	// Connect to router
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Connecting to I2P router...")
	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to router: %v", err)
	}
	defer client.Close()

	fmt.Println("✅ Connected to I2P router")
	fmt.Println()

	// Create session with callbacks
	sessionCreated := make(chan bool, 1)
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			switch status {
			case i2cp.I2CP_SESSION_STATUS_CREATED:
				fmt.Printf("✅ Session %d created successfully\n", s.ID())
				sessionCreated <- true
			case i2cp.I2CP_SESSION_STATUS_DESTROYED:
				fmt.Printf("Session %d destroyed\n", s.ID())
			default:
				fmt.Printf("Session status: %d\n", status)
			}
		},
	})

	// Use CreateSessionSync (recommended method)
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Creating session...")
	fmt.Println("(This is where the signature is validated by the router)")
	err = client.CreateSessionSync(ctx, session)
	if err != nil {
		log.Fatalf("❌ CreateSessionSync failed: %v", err)
	}

	fmt.Println()
	fmt.Printf("✅ SUCCESS! Session %d created without signature error\n", session.ID())
	fmt.Println()
	fmt.Println("=== Test Results ===")
	fmt.Println("✓ Router accepted CreateSession message")
	fmt.Println("✓ Signature validation passed")
	fmt.Println("✓ Session created successfully")
	fmt.Println()
	fmt.Println("The 'Invalid signature on CreateSessionMessage' bug is FIXED!")

	// Clean up
	fmt.Println()
	fmt.Println("Cleaning up...")
	// Session will be cleaned up when client closes

	time.Sleep(1 * time.Second) // Give time for cleanup
}
