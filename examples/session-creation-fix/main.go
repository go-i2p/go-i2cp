// Package main demonstrates the CORRECT way to create I2CP sessions
// This example shows the fix for the "CreateSession hangs with Java I2P router" bug.
//
// KEY POINTS:
// 1. Start ProcessIO loop BEFORE calling CreateSession
// 2. Use CreateSessionSync for simple synchronous waiting
// 3. Use CreateSession + callback for async pattern
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	// Example 1: Synchronous session creation (easiest)
	fmt.Println("=== Example 1: Synchronous Session Creation (Recommended for Testing) ===")
	synchronousSessionCreation()

	// Example 2: Asynchronous session creation with callbacks
	fmt.Println("\n=== Example 2: Asynchronous Session Creation (Production Pattern) ===")
	asynchronousSessionCreation()
}

// Example 1: Synchronous Session Creation
// Uses CreateSessionSync which handles ProcessIO internally
func synchronousSessionCreation() {
	// Create client
	client := i2cp.NewClient(&i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			log.Printf("Disconnected: %s", reason)
		},
	})

	// Connect to router with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected to I2P router")

	// Create session WITH callbacks for message handling
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnMessage: func(s *i2cp.Session, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
			fmt.Printf("Received message: protocol=%d, srcPort=%d, destPort=%d, size=%d\n",
				protocol, srcPort, destPort, payload.Len())
		},
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			switch status {
			case i2cp.I2CP_SESSION_STATUS_CREATED:
				fmt.Printf("Session %d created\n", s.ID())
			case i2cp.I2CP_SESSION_STATUS_DESTROYED:
				fmt.Printf("Session %d destroyed\n", s.ID())
			}
		},
	})

	// Create session synchronously (blocks until created or timeout)
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Creating session (this will wait for router response)...")
	err = client.CreateSessionSync(ctx, session)
	if err != nil {
		log.Fatalf("CreateSessionSync failed: %v", err)
	}

	fmt.Printf("Session created successfully! Session ID: %d\n", session.ID())

	// Session is now ready to use
	// You can send messages, etc.
}

// Example 2: Asynchronous Session Creation
// Manual ProcessIO loop for production use
func asynchronousSessionCreation() {
	// Create client
	client := i2cp.NewClient(&i2cp.ClientCallBacks{})

	// Connect
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	fmt.Println("Connected to I2P router")

	// Start ProcessIO loop in background BEFORE creating session
	// This is the KEY to fixing the hang!
	processIOCtx, cancelProcessIO := context.WithCancel(context.Background())
	defer cancelProcessIO()

	go func() {
		fmt.Println("Starting ProcessIO loop...")
		for {
			select {
			case <-processIOCtx.Done():
				fmt.Println("ProcessIO loop stopped")
				return
			default:
			}

			err := client.ProcessIO(processIOCtx)
			if err != nil {
				if err == i2cp.ErrClientClosed {
					return
				}
				log.Printf("ProcessIO error: %v", err)
			}

			// Small sleep to prevent busy loop
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Give ProcessIO time to start
	time.Sleep(500 * time.Millisecond)

	// Create session with callback notification
	sessionReady := make(chan bool, 1)
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			if status == i2cp.I2CP_SESSION_STATUS_CREATED {
				fmt.Printf("Session %d created via callback!\n", s.ID())
				sessionReady <- true
			}
		},
	})

	// Send CreateSession message (returns immediately)
	fmt.Println("Sending CreateSession message...")
	err = client.CreateSession(ctx, session)
	if err != nil {
		log.Fatalf("CreateSession failed: %v", err)
	}

	// Wait for session creation confirmation via callback
	select {
	case <-sessionReady:
		fmt.Println("Session confirmed via callback")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout waiting for session creation")
	}

	fmt.Printf("Session ready! Session ID: %d\n", session.ID())

	// Keep running for a bit to show ProcessIO continues
	time.Sleep(2 * time.Second)
}
