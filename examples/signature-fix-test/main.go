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

	client := createTestClient()
	defer client.Close()

	connectTestClient(client)

	session := createTestSession(client)
	runSignatureTest(client, session)

	printTestResults(session)
	cleanup()
}

// createTestClient creates the test client with disconnect callback.
func createTestClient() *i2cp.Client {
	return i2cp.NewClient(&i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			log.Printf("❌ Disconnected: %s", reason)
			if reason == "Invalid signature on CreateSessionMessage" {
				log.Fatal("BUG STILL PRESENT: Router rejected signature")
			}
		},
	})
}

// connectTestClient connects to the I2P router.
func connectTestClient(client *i2cp.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Connecting to I2P router...")
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect to router: %v", err)
	}
	fmt.Println("✅ Connected to I2P router")
	fmt.Println()
}

// createTestSession creates a session with status callback.
func createTestSession(client *i2cp.Client) *i2cp.Session {
	return i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			switch status {
			case i2cp.I2CP_SESSION_STATUS_CREATED:
				fmt.Printf("✅ Session %d created successfully\n", s.ID())
			case i2cp.I2CP_SESSION_STATUS_DESTROYED:
				fmt.Printf("Session %d destroyed\n", s.ID())
			default:
				fmt.Printf("Session status: %d\n", status)
			}
		},
	})
}

// runSignatureTest runs the signature validation test.
func runSignatureTest(client *i2cp.Client, session *i2cp.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Creating session...")
	fmt.Println("(This is where the signature is validated by the router)")
	if err := client.CreateSessionSync(ctx, session); err != nil {
		log.Fatalf("❌ CreateSessionSync failed: %v", err)
	}
}

// printTestResults prints the test results.
func printTestResults(session *i2cp.Session) {
	fmt.Println()
	fmt.Printf("✅ SUCCESS! Session %d created without signature error\n", session.ID())
	fmt.Println()
	fmt.Println("=== Test Results ===")
	fmt.Println("✓ Router accepted CreateSession message")
	fmt.Println("✓ Signature validation passed")
	fmt.Println("✓ Session created successfully")
	fmt.Println()
	fmt.Println("The 'Invalid signature on CreateSessionMessage' bug is FIXED!")
}

// cleanup performs cleanup after the test.
func cleanup() {
	fmt.Println()
	fmt.Println("Cleaning up...")
	time.Sleep(1 * time.Second)
}
