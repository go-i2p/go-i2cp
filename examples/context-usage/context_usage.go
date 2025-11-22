// Package main demonstrates context-aware operations in go-i2cp
//
// This example shows:
// - Using context.WithTimeout for connection timeout
// - Using context.WithCancel for manual cancellation
// - Graceful shutdown with Close()
// - Error handling for context cancellation
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	// Example 1: Connection with timeout
	fmt.Println("=== Example 1: Connection with Timeout ===")
	connectWithTimeout()

	// Example 2: Session creation with cancellation
	fmt.Println("\n=== Example 2: Session with Cancellation ===")
	sessionWithCancellation()

	// Example 3: Graceful shutdown
	fmt.Println("\n=== Example 3: Graceful Shutdown ===")
	gracefulShutdown()

	// Example 4: Background processing with context
	fmt.Println("\n=== Example 4: Background Processing ===")
	backgroundProcessing()
}

// Example 1: Connect with a timeout to prevent hanging indefinitely
func connectWithTimeout() {
	// Create client with nil callbacks (simplest case)
	client := i2cp.NewClient(nil)

	// Create a context with 10 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		log.Printf("Connect failed: %v", err)
		return
	}
	defer client.Close()

	fmt.Println("Connected successfully with timeout context")
}

// Example 2: Session creation with manual cancellation
func sessionWithCancellation() {
	client := i2cp.NewClient(&i2cp.ClientCallBacks{})

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Simulate cancellation after 5 seconds
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("Cancelling session creation...")
		cancel()
	}()

	err := client.Connect(ctx)
	if err != nil {
		log.Printf("Connect failed: %v", err)
		return
	}
	defer client.Close()

	// Create session with empty callbacks
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{})

	err = client.CreateSession(ctx, session)
	if err != nil {
		// This will likely fail due to cancellation
		log.Printf("Session creation failed (expected): %v", err)
		return
	}

	fmt.Println("Session created successfully")
}

// Example 3: Graceful shutdown with proper cleanup
func gracefulShutdown() {
	client := i2cp.NewClient(&i2cp.ClientCallBacks{})

	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		log.Printf("Connect failed: %v", err)
		return
	}

	// Create multiple sessions
	for i := 0; i < 3; i++ {
		session := i2cp.NewSession(client, i2cp.SessionCallbacks{})
		err = client.CreateSession(ctx, session)
		if err != nil {
			log.Printf("Session %d creation failed: %v", i, err)
		}
	}

	// Close will:
	// 1. Destroy all sessions
	// 2. Wait for pending operations (max 5 seconds)
	// 3. Close TCP connection
	fmt.Println("Starting graceful shutdown...")
	err = client.Close()
	if err != nil {
		log.Printf("Close failed: %v", err)
	} else {
		fmt.Println("Shutdown completed successfully")
	}
}

// Example 4: Background message processing with context
func backgroundProcessing() {
	client := i2cp.NewClient(&i2cp.ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		log.Printf("Connect failed: %v", err)
		return
	}
	defer client.Close()

	// Create session with empty callbacks
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{})

	err = client.CreateSession(ctx, session)
	if err != nil {
		log.Printf("Session creation failed: %v", err)
		return
	}

	// Process I/O in background with context cancellation support
	go func() {
		for {
			err := client.ProcessIO(ctx)
			if err != nil {
				if err == i2cp.ErrClientClosed {
					log.Println("Client closed, stopping I/O processing")
					return
				}
				if err == context.Canceled || err == context.DeadlineExceeded {
					log.Printf("Context cancelled: %v", err)
					return
				}
				log.Printf("ProcessIO error: %v", err)
			}

			// Small delay to prevent busy loop
			time.Sleep(100 * time.Millisecond)

			// Check if context is done
			select {
			case <-ctx.Done():
				log.Println("Context done, stopping processing")
				return
			default:
			}
		}
	}()

	// Simulate some work
	time.Sleep(2 * time.Second)
	fmt.Println("Background processing completed")
}
