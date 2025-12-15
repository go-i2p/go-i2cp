package main

import (
	"context"
	"fmt"
	"log"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	fmt.Println("=== I2CP Metrics Collection Example ===")
	fmt.Println("Demonstrates monitoring I2CP client operations")
	fmt.Println()

	// Create I2CP client
	client := i2cp.NewClient(&i2cp.ClientCallBacks{
		OnDisconnect: func(c *i2cp.Client, reason string, opaque *interface{}) {
			log.Printf("Disconnected: %s", reason)
		},
	})

	// Enable metrics collection
	metrics := i2cp.NewInMemoryMetrics()
	client.SetMetrics(metrics)
	fmt.Println("✓ Metrics collection enabled")

	// Connect to I2P router
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("\nConnecting to I2P router...")
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
	fmt.Println("✓ Connected to I2P router")

	// Print initial metrics
	fmt.Println("\n--- Initial Metrics ---")
	printMetrics(metrics)

	// Create session
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnMessage: func(s *i2cp.Session, srcDest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
			fmt.Printf("Received message from %s: protocol=%d, size=%d\n", srcDest.Base32(), protocol, payload.Len())
		},
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			fmt.Printf("Session status: %d\n", status)
		},
	})

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("\nCreating session...")
	if err := client.CreateSessionSync(ctx, session); err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()
	fmt.Printf("✓ Session %d created\n", session.ID())

	// Print metrics after session creation
	fmt.Println("\n--- Metrics After Session Creation ---")
	printMetrics(metrics)

	// Simulate some activity
	fmt.Println("\nSimulating activity...")
	time.Sleep(2 * time.Second)

	// Print final metrics
	fmt.Println("\n--- Final Metrics ---")
	printMetrics(metrics)

	fmt.Println("\n✓ Metrics example completed successfully")
}

// printMetrics displays all collected metrics from the I2CP client.
func printMetrics(m *i2cp.InMemoryMetrics) {
	printBasicMetrics(m)
	printMessagesSent(m)
	printMessagesReceived(m)
	printErrorMetrics(m)
	printLatencyMetrics(m)
}

// printBasicMetrics displays connection state, active sessions, and byte counters.
func printBasicMetrics(m *i2cp.InMemoryMetrics) {
	fmt.Printf("Connection State: %s\n", m.ConnectionState())
	fmt.Printf("Active Sessions: %d\n", m.ActiveSessions())
	fmt.Printf("Bytes Sent: %d\n", m.BytesSent())
	fmt.Printf("Bytes Received: %d\n", m.BytesReceived())
}

// printMessagesSent displays statistics for messages sent to the I2P router.
func printMessagesSent(m *i2cp.InMemoryMetrics) {
	createSessionSent := m.MessagesSent(i2cp.I2CP_MSG_CREATE_SESSION)
	getDateSent := m.MessagesSent(i2cp.I2CP_MSG_GET_DATE)
	sendMessageSent := m.MessagesSent(i2cp.I2CP_MSG_SEND_MESSAGE)

	if createSessionSent > 0 || getDateSent > 0 || sendMessageSent > 0 {
		fmt.Println("\nMessages Sent:")
		if createSessionSent > 0 {
			fmt.Printf("  CREATE_SESSION: %d\n", createSessionSent)
		}
		if getDateSent > 0 {
			fmt.Printf("  GET_DATE: %d\n", getDateSent)
		}
		if sendMessageSent > 0 {
			fmt.Printf("  SEND_MESSAGE: %d\n", sendMessageSent)
		}
	}
}

// printMessagesReceived displays statistics for messages received from the I2P router.
func printMessagesReceived(m *i2cp.InMemoryMetrics) {
	setDateRecv := m.MessagesReceived(i2cp.I2CP_MSG_SET_DATE)
	sessionStatusRecv := m.MessagesReceived(i2cp.I2CP_MSG_SESSION_STATUS)
	payloadMsgRecv := m.MessagesReceived(i2cp.I2CP_MSG_PAYLOAD_MESSAGE)

	if setDateRecv > 0 || sessionStatusRecv > 0 || payloadMsgRecv > 0 {
		fmt.Println("\nMessages Received:")
		if setDateRecv > 0 {
			fmt.Printf("  SET_DATE: %d\n", setDateRecv)
		}
		if sessionStatusRecv > 0 {
			fmt.Printf("  SESSION_STATUS: %d\n", sessionStatusRecv)
		}
		if payloadMsgRecv > 0 {
			fmt.Printf("  PAYLOAD_MESSAGE: %d\n", payloadMsgRecv)
		}
	}
}

// printErrorMetrics displays all tracked errors and their counts.
func printErrorMetrics(m *i2cp.InMemoryMetrics) {
	errors := m.AllErrors()
	if len(errors) > 0 {
		fmt.Println("\nErrors:")
		for errType, count := range errors {
			fmt.Printf("  %s: %d\n", errType, count)
		}
	}
}

// printLatencyMetrics displays latency statistics for CREATE_SESSION operations.
func printLatencyMetrics(m *i2cp.InMemoryMetrics) {
	if avg := m.AvgLatency(i2cp.I2CP_MSG_CREATE_SESSION); avg > 0 {
		fmt.Println("\nCREATE_SESSION Latency:")
		fmt.Printf("  Avg: %v\n", avg)
		fmt.Printf("  Min: %v\n", m.MinLatency(i2cp.I2CP_MSG_CREATE_SESSION))
		fmt.Printf("  Max: %v\n", m.MaxLatency(i2cp.I2CP_MSG_CREATE_SESSION))
	}
}
