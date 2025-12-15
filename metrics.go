package go_i2cp

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector defines the interface for collecting I2CP client metrics.
// This interface allows applications to plug in custom metrics implementations
// (e.g., Prometheus, StatsD, custom logging) for production monitoring.
//
// All methods are safe for concurrent use and should be non-blocking.
type MetricsCollector interface {
	// Message Counters

	// IncrementMessageSent increments the count of messages sent by type.
	// messageType should be an I2CP message type constant (e.g., I2CP_MSG_SEND_MESSAGE).
	IncrementMessageSent(messageType uint8)

	// IncrementMessageReceived increments the count of messages received by type.
	// messageType should be an I2CP message type constant (e.g., I2CP_MSG_PAYLOAD_MESSAGE).
	IncrementMessageReceived(messageType uint8)

	// Session Tracking

	// SetActiveSessions updates the gauge of currently active sessions.
	SetActiveSessions(count int)

	// Error Tracking

	// IncrementError increments the error counter by error type.
	// errorType should describe the error category (e.g., "network", "protocol", "timeout").
	IncrementError(errorType string)

	// Latency Tracking

	// RecordMessageLatency records the latency of a message send operation.
	// messageType is the I2CP message type, duration is the operation time.
	RecordMessageLatency(messageType uint8, duration time.Duration)

	// Connection State

	// SetConnectionState updates the current connection state.
	// state should be "connected", "disconnected", or "reconnecting".
	SetConnectionState(state string)

	// Bandwidth Tracking

	// AddBytesSent adds to the total bytes sent counter.
	AddBytesSent(bytes uint64)

	// AddBytesReceived adds to the total bytes received counter.
	AddBytesReceived(bytes uint64)
}

// InMemoryMetrics provides a simple in-memory implementation of MetricsCollector.
// Suitable for development, testing, and applications that want basic metrics
// without external dependencies.
//
// All operations are thread-safe using atomic operations and minimal locking.
type InMemoryMetrics struct {
	// Message counters by type (index = message type)
	messagesSent     [256]uint64
	messagesReceived [256]uint64

	// Session tracking
	activeSessions int32

	// Error tracking (map protected by mutex)
	errorsMu     sync.RWMutex
	errorsByType map[string]uint64

	// Latency tracking (protected by mutex for histogram updates)
	latencyMu       sync.RWMutex
	latencyByType   map[uint8]*latencyStats
	connectionState atomic.Value // stores string

	// Bandwidth tracking
	bytesSent     uint64
	bytesReceived uint64
}

// latencyStats tracks latency statistics for a message type
type latencyStats struct {
	count      uint64
	totalNanos uint64
	minNanos   uint64
	maxNanos   uint64
}

// NewInMemoryMetrics creates a new in-memory metrics collector.
func NewInMemoryMetrics() *InMemoryMetrics {
	m := &InMemoryMetrics{
		errorsByType:  make(map[string]uint64),
		latencyByType: make(map[uint8]*latencyStats),
	}
	m.connectionState.Store("disconnected")
	return m
}

// IncrementMessageSent increments the sent message counter for the given type.
func (m *InMemoryMetrics) IncrementMessageSent(messageType uint8) {
	atomic.AddUint64(&m.messagesSent[messageType], 1)
}

// IncrementMessageReceived increments the received message counter for the given type.
func (m *InMemoryMetrics) IncrementMessageReceived(messageType uint8) {
	atomic.AddUint64(&m.messagesReceived[messageType], 1)
}

// SetActiveSessions updates the active sessions gauge.
func (m *InMemoryMetrics) SetActiveSessions(count int) {
	atomic.StoreInt32(&m.activeSessions, int32(count))
}

// IncrementError increments the error counter for the given error type.
func (m *InMemoryMetrics) IncrementError(errorType string) {
	m.errorsMu.Lock()
	m.errorsByType[errorType]++
	m.errorsMu.Unlock()
}

// RecordMessageLatency records the latency for a message type.
func (m *InMemoryMetrics) RecordMessageLatency(messageType uint8, duration time.Duration) {
	nanos := uint64(duration.Nanoseconds())

	m.latencyMu.Lock()
	defer m.latencyMu.Unlock()

	stats := m.latencyByType[messageType]
	if stats == nil {
		stats = &latencyStats{
			minNanos: nanos,
			maxNanos: nanos,
		}
		m.latencyByType[messageType] = stats
	}

	stats.count++
	stats.totalNanos += nanos

	if nanos < stats.minNanos {
		stats.minNanos = nanos
	}
	if nanos > stats.maxNanos {
		stats.maxNanos = nanos
	}
}

// SetConnectionState updates the connection state.
func (m *InMemoryMetrics) SetConnectionState(state string) {
	m.connectionState.Store(state)
}

// AddBytesSent adds to the total bytes sent.
func (m *InMemoryMetrics) AddBytesSent(bytes uint64) {
	atomic.AddUint64(&m.bytesSent, bytes)
}

// AddBytesReceived adds to the total bytes received.
func (m *InMemoryMetrics) AddBytesReceived(bytes uint64) {
	atomic.AddUint64(&m.bytesReceived, bytes)
}

// Getter methods for programmatic access to metrics

// MessagesSent returns the total count of sent messages by type.
func (m *InMemoryMetrics) MessagesSent(messageType uint8) uint64 {
	return atomic.LoadUint64(&m.messagesSent[messageType])
}

// MessagesReceived returns the total count of received messages by type.
func (m *InMemoryMetrics) MessagesReceived(messageType uint8) uint64 {
	return atomic.LoadUint64(&m.messagesReceived[messageType])
}

// ActiveSessions returns the current count of active sessions.
func (m *InMemoryMetrics) ActiveSessions() int {
	return int(atomic.LoadInt32(&m.activeSessions))
}

// Errors returns the total count of errors by type.
func (m *InMemoryMetrics) Errors(errorType string) uint64 {
	m.errorsMu.RLock()
	defer m.errorsMu.RUnlock()
	return m.errorsByType[errorType]
}

// AllErrors returns a copy of all error counts by type.
func (m *InMemoryMetrics) AllErrors() map[string]uint64 {
	m.errorsMu.RLock()
	defer m.errorsMu.RUnlock()

	result := make(map[string]uint64, len(m.errorsByType))
	for k, v := range m.errorsByType {
		result[k] = v
	}
	return result
}

// AvgLatency returns the average latency for a message type in nanoseconds.
// Returns 0 if no measurements have been recorded.
func (m *InMemoryMetrics) AvgLatency(messageType uint8) time.Duration {
	m.latencyMu.RLock()
	defer m.latencyMu.RUnlock()

	stats := m.latencyByType[messageType]
	if stats == nil || stats.count == 0 {
		return 0
	}

	return time.Duration(stats.totalNanos / stats.count)
}

// MinLatency returns the minimum latency for a message type.
// Returns 0 if no measurements have been recorded.
func (m *InMemoryMetrics) MinLatency(messageType uint8) time.Duration {
	m.latencyMu.RLock()
	defer m.latencyMu.RUnlock()

	stats := m.latencyByType[messageType]
	if stats == nil {
		return 0
	}

	return time.Duration(stats.minNanos)
}

// MaxLatency returns the maximum latency for a message type.
// Returns 0 if no measurements have been recorded.
func (m *InMemoryMetrics) MaxLatency(messageType uint8) time.Duration {
	m.latencyMu.RLock()
	defer m.latencyMu.RUnlock()

	stats := m.latencyByType[messageType]
	if stats == nil {
		return 0
	}

	return time.Duration(stats.maxNanos)
}

// ConnectionState returns the current connection state.
func (m *InMemoryMetrics) ConnectionState() string {
	return m.connectionState.Load().(string)
}

// BytesSent returns the total bytes sent.
func (m *InMemoryMetrics) BytesSent() uint64 {
	return atomic.LoadUint64(&m.bytesSent)
}

// BytesReceived returns the total bytes received.
func (m *InMemoryMetrics) BytesReceived() uint64 {
	return atomic.LoadUint64(&m.bytesReceived)
}

// Reset clears all metrics. Useful for testing.
func (m *InMemoryMetrics) Reset() {
	// Reset message counters
	for i := range m.messagesSent {
		atomic.StoreUint64(&m.messagesSent[i], 0)
		atomic.StoreUint64(&m.messagesReceived[i], 0)
	}

	// Reset sessions
	atomic.StoreInt32(&m.activeSessions, 0)

	// Reset errors
	m.errorsMu.Lock()
	m.errorsByType = make(map[string]uint64)
	m.errorsMu.Unlock()

	// Reset latency
	m.latencyMu.Lock()
	m.latencyByType = make(map[uint8]*latencyStats)
	m.latencyMu.Unlock()

	// Reset connection state
	m.connectionState.Store("disconnected")

	// Reset bandwidth
	atomic.StoreUint64(&m.bytesSent, 0)
	atomic.StoreUint64(&m.bytesReceived, 0)
}
