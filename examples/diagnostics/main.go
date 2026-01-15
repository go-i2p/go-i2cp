// Package main demonstrates go-i2cp diagnostic capabilities for troubleshooting
// I2CP protocol interactions, particularly useful for debugging session creation
// timeouts with Java I2P routers.
//
// This example shows:
// - Enabling message statistics tracking
// - Connection state inspection
// - Debug logging configuration
// - Diagnostic report generation
// - Troubleshooting session creation issues
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	fmt.Println("=== go-i2cp Diagnostics Example ===")
	fmt.Println("This example demonstrates diagnostic tools for troubleshooting I2CP issues")

	client := setupClient()
	defer client.Close()

	ctx := connectToRouter(client)

	fmt.Println("Step 4: Inspecting connection state...")
	printConnectionState(client)

	sessionCreated := make(chan bool, 1)
	session := createDiagnosticSession(client, sessionCreated)

	cancelProcessIO := startProcessIOLoop(client, ctx)
	defer cancelProcessIO()

	sendCreateSession(client, ctx, session)
	waitForSessionCreation(client, session, sessionCreated)

	fmt.Println("\n=== Step 10: Message Statistics Details ===")
	demonstrateMessageStats(client)

	printKeyTakeaways()
}

// setupClient creates and configures the I2CP client with diagnostics.
func setupClient() *i2cp.Client {
	fmt.Println("Step 1: Enabling debug logging...")
	i2cp.LogInit(i2cp.DEBUG)
	fmt.Println("✓ Debug logging enabled - all I2CP messages will be traced")

	fmt.Println("Step 2: Creating I2CP client with diagnostics enabled...")
	client := i2cp.NewClient(&i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			log.Printf("Disconnected from router: %s", reason)
		},
	})
	client.EnableMessageStats()
	fmt.Println("✓ Message statistics tracking enabled")
	return client
}

// connectToRouter connects to the I2P router.
func connectToRouter(client *i2cp.Client) context.Context {
	fmt.Println("Step 3: Connecting to I2P router...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	fmt.Println("✓ Connected to I2P router")
	return ctx
}

// createDiagnosticSession creates a session with diagnostic callbacks.
func createDiagnosticSession(client *i2cp.Client, sessionCreated chan bool) *i2cp.Session {
	fmt.Println("\nStep 5: Creating I2CP session with diagnostic callbacks...")
	return i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			log.Printf(">>> OnStatus callback invoked: session=%d, status=%s", s.ID(), getStatusName(status))
			if status == i2cp.I2CP_SESSION_STATUS_CREATED {
				sessionCreated <- true
			}
		},
		OnMessage: func(s *i2cp.Session, srcDest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
			log.Printf(">>> OnMessage callback invoked: protocol=%d, size=%d", protocol, payload.Len())
		},
	})
}

// startProcessIOLoop starts the ProcessIO loop in the background.
func startProcessIOLoop(client *i2cp.Client, ctx context.Context) context.CancelFunc {
	fmt.Println("\nStep 6: Starting ProcessIO loop...")
	processIOCtx, cancelProcessIO := context.WithCancel(ctx)

	go runProcessIOLoop(client, processIOCtx)

	fmt.Println("✓ ProcessIO loop running in background")
	time.Sleep(100 * time.Millisecond)
	return cancelProcessIO
}

// runProcessIOLoop runs the ProcessIO loop until context cancellation or error.
func runProcessIOLoop(client *i2cp.Client, ctx context.Context) {
	for {
		if shouldExitIOLoop(ctx) {
			return
		}
		if handleProcessIO(client, ctx) {
			return
		}
	}
}

// shouldExitIOLoop checks if the context is done and the loop should exit.
func shouldExitIOLoop(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// handleProcessIO executes a single ProcessIO iteration and returns true if the loop should exit.
func handleProcessIO(client *i2cp.Client, ctx context.Context) bool {
	err := client.ProcessIO(ctx)
	if err == nil {
		return false
	}
	if err != context.Canceled {
		log.Printf("ProcessIO error: %v", err)
	}
	return true
}

// sendCreateSession sends the CreateSession message.
func sendCreateSession(client *i2cp.Client, ctx context.Context, session *i2cp.Session) {
	fmt.Println("Step 7: Sending CreateSession message to router...")
	fmt.Println("(Watch for debug logs showing message flow)")
	if err := client.CreateSession(ctx, session); err != nil {
		log.Fatalf("CreateSession failed: %v", err)
	}
}

// waitForSessionCreation waits for session creation or timeout.
func waitForSessionCreation(client *i2cp.Client, session *i2cp.Session, sessionCreated chan bool) {
	fmt.Println("Step 8: Waiting for SessionCreated response...")
	fmt.Println("(This is where timeouts typically occur if there are issues)")

	select {
	case <-sessionCreated:
		handleSessionSuccess(client, session)
	case <-time.After(30 * time.Second):
		handleSessionTimeout(client)
	}
}

// handleSessionSuccess handles successful session creation.
func handleSessionSuccess(client *i2cp.Client, session *i2cp.Session) {
	fmt.Println("✓✓✓ Session created successfully! ✓✓✓")
	fmt.Printf("    Session ID: %d\n\n", session.ID())

	fmt.Println("Step 9: Printing diagnostic report...")
	client.PrintDiagnostics()

	fmt.Println("\n=== Message Statistics ===")
	if stats := client.GetMessageStats(); stats != nil {
		fmt.Println(stats.Summary())
	}
}

// handleSessionTimeout handles session creation timeout.
func handleSessionTimeout(client *i2cp.Client) {
	fmt.Println("\n❌❌❌ Session creation TIMEOUT ❌❌❌")
	fmt.Println("This indicates an issue with the I2CP handshake")

	fmt.Println("=== DIAGNOSTIC REPORT ===")
	client.PrintDiagnostics()

	fmt.Println("\n=== Message Flow Analysis ===")
	if stats := client.GetMessageStats(); stats != nil {
		fmt.Println(stats.DiagnosticReport())
	}

	fmt.Println("\n=== Connection State ===")
	printConnectionState(client)

	log.Fatal("\nSession creation failed - see diagnostic output above")
}

// printKeyTakeaways prints the key lessons learned.
func printKeyTakeaways() {
	fmt.Println("\n=== Diagnostics Example Complete ===")
	fmt.Println("Key takeaways:")
	fmt.Println("1. Enable message stats BEFORE connecting")
	fmt.Println("2. Start ProcessIO BEFORE CreateSession")
	fmt.Println("3. Use PrintDiagnostics() when issues occur")
	fmt.Println("4. Check message stats to verify protocol flow")
}

// printConnectionState displays the current I2CP connection state
func printConnectionState(client *i2cp.Client) {
	state := client.GetConnectionState()

	fmt.Println("Connection State:")
	fmt.Printf("  Connected:        %v\n", state.Connected)
	fmt.Printf("  Router Version:   %s\n", state.RouterVersion)
	fmt.Printf("  Router Date:      %v\n", state.RouterDate)
	fmt.Printf("  Active Sessions:  %d\n", state.SessionsActive)
	fmt.Printf("  Primary Sessions: %d\n", state.PrimarySessions)
	fmt.Printf("  SubSessions:      %d\n", state.SubSessions)

	if state.LastError != nil {
		fmt.Printf("  Last Error:       %v (at %v)\n", state.LastError, state.LastErrorTime)
	}
}

// demonstrateMessageStats shows how to inspect individual message statistics
func demonstrateMessageStats(client *i2cp.Client) {
	stats := client.GetMessageStats()
	if stats == nil || !stats.IsEnabled() {
		fmt.Println("Message statistics not available")
		return
	}

	// Check CreateSession message
	createSent := stats.GetSentCount(i2cp.I2CP_MSG_CREATE_SESSION)
	fmt.Printf("CreateSession sent:       %d times\n", createSent)

	if lastSent, ok := stats.GetLastSent(i2cp.I2CP_MSG_CREATE_SESSION); ok {
		fmt.Printf("  Last sent:              %v (%v ago)\n",
			lastSent.Format(time.RFC3339), time.Since(lastSent))
	}

	// Check SessionStatus response
	statusRecv := stats.GetReceivedCount(i2cp.I2CP_MSG_SESSION_STATUS)
	fmt.Printf("\nSessionStatus received:   %d times\n", statusRecv)

	if lastRecv, ok := stats.GetLastReceived(i2cp.I2CP_MSG_SESSION_STATUS); ok {
		fmt.Printf("  Last received:          %v (%v ago)\n",
			lastRecv.Format(time.RFC3339), time.Since(lastRecv))
	}

	// Check SetDate message (protocol handshake)
	setDateRecv := stats.GetReceivedCount(i2cp.I2CP_MSG_SET_DATE)
	fmt.Printf("\nSetDate received:         %d times\n", setDateRecv)

	// Analyze message flow
	fmt.Println("\nMessage Flow Analysis:")
	if createSent > 0 && statusRecv == 0 {
		fmt.Println("  ❌ CreateSession sent but no SessionStatus received")
		fmt.Println("     → Router may not be responding")
		fmt.Println("     → ProcessIO may not be running")
	} else if createSent == statusRecv {
		fmt.Println("  ✓ Message flow healthy - all requests got responses")
	}
}

// getStatusName returns human-readable session status name
func getStatusName(status i2cp.SessionStatus) string {
	switch status {
	case i2cp.I2CP_SESSION_STATUS_CREATED:
		return "CREATED"
	case i2cp.I2CP_SESSION_STATUS_DESTROYED:
		return "DESTROYED"
	case i2cp.I2CP_SESSION_STATUS_UPDATED:
		return "UPDATED"
	case i2cp.I2CP_SESSION_STATUS_INVALID:
		return "INVALID"
	case i2cp.I2CP_SESSION_STATUS_REFUSED:
		return "REFUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}
