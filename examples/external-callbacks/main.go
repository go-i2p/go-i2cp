package main

import (
	"context"
	"fmt"
	"log"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// This example demonstrates how to use SessionCallbacks from an external package
// With the exported fields (OnMessage, OnStatus, OnDestination, OnMessageStatus),
// external packages can now register callbacks using struct literals

func main() {
	// Create I2CP client
	client := go_i2cp.NewClient(nil)

	// Define callbacks using the exported fields
	// This pattern now works from external packages!
	callbacks := go_i2cp.SessionCallbacks{
		OnMessage: func(session *go_i2cp.Session, protocol uint8, srcPort, destPort uint16, payload *go_i2cp.Stream) {
			fmt.Printf("Received message: protocol=%d, srcPort=%d, destPort=%d\n", protocol, srcPort, destPort)

			// Example: Filter for I2P streaming protocol (protocol 6)
			if protocol == 6 {
				fmt.Printf("I2P streaming packet received (%d bytes)\n", payload.Len())
				// Process streaming packet...
			}
		},

		OnStatus: func(session *go_i2cp.Session, status go_i2cp.SessionStatus) {
			fmt.Printf("Session status changed: %d\n", status)

			switch status {
			case go_i2cp.I2CP_SESSION_STATUS_CREATED:
				fmt.Println("Session created successfully")
			case go_i2cp.I2CP_SESSION_STATUS_DESTROYED:
				fmt.Println("Session destroyed")
			case go_i2cp.I2CP_SESSION_STATUS_UPDATED:
				fmt.Println("Session configuration updated")
			case go_i2cp.I2CP_SESSION_STATUS_INVALID:
				fmt.Println("Session marked as invalid")
			}
		},

		OnDestination: func(session *go_i2cp.Session, requestId uint32, address string, dest *go_i2cp.Destination) {
			fmt.Printf("Destination lookup result: requestId=%d, address=%s\n", requestId, address)

			if dest != nil {
				fmt.Println("Destination resolved successfully")
			} else {
				fmt.Println("Destination lookup failed")
			}
		},

		OnMessageStatus: func(session *go_i2cp.Session, messageId uint32, status go_i2cp.SessionMessageStatus, size, nonce uint32) {
			fmt.Printf("Message status: messageId=%d, status=%d, size=%d, nonce=%d\n", messageId, status, size, nonce)
		},
	}

	// Create session with callbacks
	_ = go_i2cp.NewSession(client, callbacks)

	fmt.Println("Session created successfully!")
	fmt.Println("External callback registration successful!")
	fmt.Println()
	fmt.Println("This demonstrates that SessionCallbacks fields are now exported and")
	fmt.Println("can be used from external packages like go-streaming.")

	// Clean up
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		log.Printf("Warning: Could not connect to router (expected if not running): %v", err)
	} else {
		defer client.Close()
	}
}
