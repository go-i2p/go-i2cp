# Metrics Example

This example demonstrates how to use the metrics collection feature to monitor I2CP client operations.

## Overview

The `go-i2cp` library provides optional metrics collection for production monitoring. You can use the built-in `InMemoryMetrics` collector or implement your own `MetricsCollector` interface to integrate with Prometheus, StatsD, or other monitoring systems.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	// Create I2CP client
	client := go_i2cp.NewClient(nil)

	// Enable metrics collection
	metrics := go_i2cp.NewInMemoryMetrics()
	client.SetMetrics(metrics)

	// Connect to I2P router
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Create session
	session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{})
	if err := client.CreateSession(ctx, session); err != nil {
		log.Fatal(err)
	}

	// Process I/O for a while
	go func() {
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				return
			}
		}
	}()

	// Wait a bit for some activity
	time.Sleep(2 * time.Second)

	// Print metrics
	printMetrics(metrics)
}

func printMetrics(m *go_i2cp.InMemoryMetrics) {
	fmt.Println("=== I2CP Metrics ===")
	fmt.Printf("Connection State: %s\n", m.ConnectionState())
	fmt.Printf("Active Sessions: %d\n", m.ActiveSessions())
	fmt.Printf("Bytes Sent: %d\n", m.BytesSent())
	fmt.Printf("Bytes Received: %d\n", m.BytesReceived())

	// Message counters
	fmt.Printf("\nMessages Sent:\n")
	fmt.Printf("  CREATE_SESSION: %d\n", m.MessagesSent(go_i2cp.I2CP_MSG_CREATE_SESSION))
	fmt.Printf("  GET_DATE: %d\n", m.MessagesSent(go_i2cp.I2CP_MSG_GET_DATE))
	fmt.Printf("  SEND_MESSAGE: %d\n", m.MessagesSent(go_i2cp.I2CP_MSG_SEND_MESSAGE))

	fmt.Printf("\nMessages Received:\n")
	fmt.Printf("  SET_DATE: %d\n", m.MessagesReceived(go_i2cp.I2CP_MSG_SET_DATE))
	fmt.Printf("  SESSION_STATUS: %d\n", m.MessagesReceived(go_i2cp.I2CP_MSG_SESSION_STATUS))
	fmt.Printf("  PAYLOAD_MESSAGE: %d\n", m.MessagesReceived(go_i2cp.I2CP_MSG_PAYLOAD_MESSAGE))

	// Error tracking
	fmt.Printf("\nErrors:\n")
	errors := m.AllErrors()
	if len(errors) == 0 {
		fmt.Println("  None")
	} else {
		for errType, count := range errors {
			fmt.Printf("  %s: %d\n", errType, count)
		}
	}

	// Latency stats
	if avg := m.AvgLatency(go_i2cp.I2CP_MSG_SEND_MESSAGE); avg > 0 {
		fmt.Printf("\nSEND_MESSAGE Latency:\n")
		fmt.Printf("  Avg: %v\n", avg)
		fmt.Printf("  Min: %v\n", m.MinLatency(go_i2cp.I2CP_MSG_SEND_MESSAGE))
		fmt.Printf("  Max: %v\n", m.MaxLatency(go_i2cp.I2CP_MSG_SEND_MESSAGE))
	}
}
```

## Custom Metrics Collector

You can implement the `MetricsCollector` interface to integrate with your monitoring system:

```go
package main

import (
	"time"
	go_i2cp "github.com/go-i2p/go-i2cp"
)

// PrometheusMetrics implements MetricsCollector for Prometheus
type PrometheusMetrics struct {
	// Your Prometheus client fields here
}

func (m *PrometheusMetrics) IncrementMessageSent(messageType uint8) {
	// Increment Prometheus counter
}

func (m *PrometheusMetrics) IncrementMessageReceived(messageType uint8) {
	// Increment Prometheus counter
}

func (m *PrometheusMetrics) SetActiveSessions(count int) {
	// Update Prometheus gauge
}

func (m *PrometheusMetrics) IncrementError(errorType string) {
	// Increment Prometheus counter with label
}

func (m *PrometheusMetrics) RecordMessageLatency(messageType uint8, duration time.Duration) {
	// Record to Prometheus histogram
}

func (m *PrometheusMetrics) SetConnectionState(state string) {
	// Update Prometheus gauge or state vector
}

func (m *PrometheusMetrics) AddBytesSent(bytes uint64) {
	// Increment Prometheus counter
}

func (m *PrometheusMetrics) AddBytesReceived(bytes uint64) {
	// Increment Prometheus counter
}

func main() {
	client := go_i2cp.NewClient(nil)
	
	// Use custom metrics implementation
	prometheusMetrics := &PrometheusMetrics{}
	client.SetMetrics(prometheusMetrics)
	
	// Now all I2CP operations will be tracked in Prometheus
}
```

## Disabling Metrics

Metrics collection is optional. To disable:

```go
client.SetMetrics(nil)
```

## Performance Considerations

- Metrics collection uses atomic operations and minimal locking for thread-safety
- Overhead is negligible (<1μs per operation) for most use cases
- The `InMemoryMetrics` implementation is suitable for production use
- For high-volume deployments, implement custom sampling in your `MetricsCollector`

## Metric Types

### Counters (always increasing)
- Message sent/received counts by type
- Error counts by category
- Bytes sent/received

### Gauges (point-in-time values)
- Active sessions count
- Connection state

### Histograms (distribution)
- Message latency tracking (min, max, avg)
