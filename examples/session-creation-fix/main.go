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
		OnMessage: func(s *i2cp.Session, srcDest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
			fmt.Printf("Received message from %s: protocol=%d, srcPort=%d, destPort=%d, size=%d\n",
				srcDest.Base32(), protocol, srcPort, destPort, payload.Len())
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

// asynchronousSessionCreation demonstrates asynchronous session creation
// with manual ProcessIO loop for production use.
func asynchronousSessionCreation() {
	client := createAndConnectClient()
	defer client.Close()

	_, cancelProcessIO := startProcessIOLoop(client)
	defer cancelProcessIO()

	sessionReady := make(chan bool, 1)
	session := createSessionWithCallback(client, sessionReady)

	waitForSessionReady(session, sessionReady)

	// Keep running for a bit to show ProcessIO continues
	time.Sleep(2 * time.Second)
}

// createAndConnectClient creates a new I2CP client and connects to the I2P router.
func createAndConnectClient() *i2cp.Client {
	client := i2cp.NewClient(&i2cp.ClientCallBacks{})

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		log.Fatalf("Connect failed: %v", err)
	}

	fmt.Println("Connected to I2P router")
	return client
}

// startProcessIOLoop starts the ProcessIO loop in a background goroutine
// and returns the context and cancel function for cleanup.
func startProcessIOLoop(client *i2cp.Client) (context.Context, context.CancelFunc) {
	processIOCtx, cancelProcessIO := context.WithCancel(context.Background())

	go runProcessIOLoop(client, processIOCtx)

	// Give ProcessIO time to start
	time.Sleep(500 * time.Millisecond)

	return processIOCtx, cancelProcessIO
}

// runProcessIOLoop executes the ProcessIO loop continuously until the context is cancelled.
func runProcessIOLoop(client *i2cp.Client, ctx context.Context) {
	fmt.Println("Starting ProcessIO loop...")
	for {
		select {
		case <-ctx.Done():
			fmt.Println("ProcessIO loop stopped")
			return
		default:
		}

		if processIOShouldStop(client, ctx) {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// processIOShouldStop executes a single ProcessIO cycle and returns true if the loop should stop.
func processIOShouldStop(client *i2cp.Client, ctx context.Context) bool {
	err := client.ProcessIO(ctx)
	if err == nil {
		return false
	}

	if err == i2cp.ErrClientClosed {
		return true
	}

	log.Printf("ProcessIO error: %v", err)
	return false
}

// createSessionWithCallback creates a new session with callback notification
// and sends the CreateSession message to the router.
func createSessionWithCallback(client *i2cp.Client, sessionReady chan bool) *i2cp.Session {
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			if status == i2cp.I2CP_SESSION_STATUS_CREATED {
				fmt.Printf("Session %d created via callback!\n", s.ID())
				sessionReady <- true
			}
		},
	})

	fmt.Println("Sending CreateSession message...")
	ctx := context.Background()
	err := client.CreateSession(ctx, session)
	if err != nil {
		log.Fatalf("CreateSession failed: %v", err)
	}

	return session
}

// waitForSessionReady waits for session creation confirmation via callback
// or times out after 30 seconds.
func waitForSessionReady(session *i2cp.Session, sessionReady chan bool) {
	select {
	case <-sessionReady:
		fmt.Println("Session confirmed via callback")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout waiting for session creation")
	}

	fmt.Printf("Session ready! Session ID: %d\n", session.ID())
}
