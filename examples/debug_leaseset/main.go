// Example: Debugging RequestVariableLeaseSet Issue
//
// This example demonstrates how to use the go-i2cp debugging enhancements
// to diagnose the issue where Java I2P Router never sends RequestVariableLeaseSet
// (type 37) to go-i2cp sessions.
//
// Usage:
//   go run main.go
//
// Prerequisites:
//   - Java I2P router running with I2CP enabled (default port 7654)
//   - Router logs enabled for debugging

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	fmt.Println("=== go-i2cp RequestVariableLeaseSet Debug Example ===")
	fmt.Println()

	client := setupDebugClient()
	defer client.Close()

	ctx := context.Background()
	connectDebugClient(client, ctx)

	createDebugSession(client, ctx)
	startBackgroundProcessIO(client, ctx)

	waitForLeaseSetRequest(client)
}

// createSessionCallbacks creates session callbacks for debugging.
func createSessionCallbacks() i2cp.SessionCallbacks {
	return i2cp.SessionCallbacks{
		OnStatus: func(sess *i2cp.Session, status i2cp.SessionStatus) {
			fmt.Printf("\n>>> CALLBACK: Session status changed to: %v\n", status)
			logSessionStatus(status)
		},
	}
}

// logSessionStatus logs detailed information based on session status.
func logSessionStatus(status i2cp.SessionStatus) {
	if status == i2cp.I2CP_SESSION_STATUS_CREATED {
		fmt.Println(">>> Session CREATED - now waiting for RequestVariableLeaseSet (type 37)...")
		fmt.Println(">>> If this message never arrives, check router logs for:")
		fmt.Println("    - 'Invalid signature on CreateSessionMessage'")
		fmt.Println("    - 'Session rejected'")
		fmt.Println("    - Any errors related to LeaseSet publication")
	}
	if status == i2cp.I2CP_SESSION_STATUS_DESTROYED {
		fmt.Println(">>> Session DESTROYED - check /tmp/go-i2cp-debug/ for disconnect info")
	}
}

// setupDebugClient creates and configures the debug client.
func setupDebugClient() *i2cp.Client {
	clientCallbacks := &i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			fmt.Printf("\n>>> CALLBACK: Disconnected! Reason: %s\n", reason)
		},
	}

	client := i2cp.NewClient(clientCallbacks)
	if client == nil {
		log.Fatal("Failed to create I2CP client")
	}

	i2cp.LogInit(i2cp.DEBUG)

	fmt.Println("Enabling debugging features...")
	if err := client.EnableAllDebugging(); err != nil {
		log.Fatalf("Failed to enable debugging: %v", err)
	}
	fmt.Println("Debug files will be written to: /tmp/go-i2cp-debug/")
	fmt.Println()
	return client
}

// connectDebugClient connects to the I2P router.
func connectDebugClient(client *i2cp.Client, ctx context.Context) {
	fmt.Println("Connecting to I2P router at 127.0.0.1:7654...")
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	fmt.Println("Connected to router!")
	client.PrintDiagnostics()
}

// createDebugSession creates the debug session.
func createDebugSession(client *i2cp.Client, ctx context.Context) *i2cp.Session {
	fmt.Println("\nCreating session...")
	printExpectedMessages()

	session := i2cp.NewSession(client, createSessionCallbacks())
	if err := client.CreateSession(ctx, session); err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	fmt.Printf("Session creation request sent\n")
	return session
}

// printExpectedMessages prints the expected message flow.
func printExpectedMessages() {
	fmt.Println("Watch for these messages:")
	fmt.Println("  1. '>>> SENDING CreateSessionMessage' - we send CreateSession")
	fmt.Println("  2. 'Session X CREATED' - router accepted session")
	fmt.Println("  3. '>>> RECEIVED RequestVariableLeaseSet' - router requests LeaseSet (THE KEY MESSAGE)")
	fmt.Println()
}

// startBackgroundProcessIO starts ProcessIO in the background.
func startBackgroundProcessIO(client *i2cp.Client, ctx context.Context) {
	go func() {
		fmt.Println("Starting ProcessIO loop...")
		for {
			if err := client.ProcessIO(ctx); err != nil {
				fmt.Printf("ProcessIO error: %v\n", err)
				return
			}
		}
	}()
}

// waitForLeaseSetRequest waits for RequestVariableLeaseSet with timeout.
func waitForLeaseSetRequest(client *i2cp.Client) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("\nWaiting for RequestVariableLeaseSet (type 37)...")
	fmt.Println("Press Ctrl+C to print diagnostics and exit")
	fmt.Println()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	timeout := time.After(2 * time.Minute)

	for {
		select {
		case <-ticker.C:
			printCurrentState(client)
		case <-timeout:
			fmt.Println("\n>>> TIMEOUT: 2 minutes elapsed without receiving RequestVariableLeaseSet!")
			fmt.Println(">>> This confirms the bug - router is not sending type 37 message")
			printFinalDiagnostics(client)
			return

		case <-sigChan:
			fmt.Println("\n>>> Interrupted by user")
			printFinalDiagnostics(client)
			return
		}
	}
}

// printCurrentState prints the current state from the tracker.
func printCurrentState(client *i2cp.Client) {
	tracker := client.GetStateTracker()
	if tracker != nil {
		fmt.Println("\n--- Current State ---")
		fmt.Println(tracker.GetLeaseSetWaitDiagnostics())
	}
}

func printFinalDiagnostics(client *i2cp.Client) {
	fmt.Println("\n==========================================")
	fmt.Println("       FINAL DIAGNOSTIC REPORT")
	fmt.Println("==========================================")
	client.PrintFullDiagnostics()
	printDebugFilesInfo()
	printNextSteps()
}

// printDebugFilesInfo prints information about debug files.
func printDebugFilesInfo() {
	fmt.Println("\n--- Debug Files ---")
	fmt.Println("Check /tmp/go-i2cp-debug/ for:")
	fmt.Println("  - CreateSession-*.bin - Raw CreateSession message")
	fmt.Println("  - CreateSession-*-breakdown.txt - Message analysis")
	fmt.Println("  - Disconnect-*.txt - Disconnect details (if any)")
}

// printNextSteps prints recommended next steps.
func printNextSteps() {
	fmt.Println("\n--- Next Steps ---")
	fmt.Println("1. Compare CreateSession hex dump with Java I2CP client")
	fmt.Println("2. Check router logs for signature verification errors")
	fmt.Println("3. Verify Destination serialization format")
	fmt.Println("4. Check session properties (i2cp.dontPublishLeaseSet)")
}
