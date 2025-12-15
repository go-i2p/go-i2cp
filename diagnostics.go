package go_i2cp

import (
	"fmt"
	"sync"
	"time"
)

// MessageStats tracks sent and received message counts by type for diagnostic purposes.
// This is useful for debugging I2CP protocol interactions and identifying message flow issues.
type MessageStats struct {
	mu            sync.RWMutex
	sent          map[uint8]uint64    // Count of sent messages by type
	received      map[uint8]uint64    // Count of received messages by type
	lastSent      map[uint8]time.Time // Timestamp of last sent message by type
	lastReceived  map[uint8]time.Time // Timestamp of last received message by type
	enabled       bool                // Whether stats tracking is enabled
	startTime     time.Time           // When stats tracking started
	bytesSent     uint64              // Total bytes sent
	bytesReceived uint64              // Total bytes received
}

// NewMessageStats creates a new message statistics tracker.
func NewMessageStats() *MessageStats {
	return &MessageStats{
		sent:         make(map[uint8]uint64),
		received:     make(map[uint8]uint64),
		lastSent:     make(map[uint8]time.Time),
		lastReceived: make(map[uint8]time.Time),
		enabled:      false,
		startTime:    time.Now(),
	}
}

// Enable enables message statistics tracking.
func (ms *MessageStats) Enable() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.enabled = true
	ms.startTime = time.Now()
}

// Disable disables message statistics tracking.
func (ms *MessageStats) Disable() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.enabled = false
}

// IsEnabled returns whether statistics tracking is enabled.
func (ms *MessageStats) IsEnabled() bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.enabled
}

// RecordSent records a sent message of the given type.
func (ms *MessageStats) RecordSent(msgType uint8, size uint64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if !ms.enabled {
		return
	}

	ms.sent[msgType]++
	ms.lastSent[msgType] = time.Now()
	ms.bytesSent += size
}

// RecordReceived records a received message of the given type.
func (ms *MessageStats) RecordReceived(msgType uint8, size uint64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if !ms.enabled {
		return
	}

	ms.received[msgType]++
	ms.lastReceived[msgType] = time.Now()
	ms.bytesReceived += size
}

// GetSentCount returns the number of sent messages of the given type.
func (ms *MessageStats) GetSentCount(msgType uint8) uint64 {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.sent[msgType]
}

// GetReceivedCount returns the number of received messages of the given type.
func (ms *MessageStats) GetReceivedCount(msgType uint8) uint64 {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return ms.received[msgType]
}

// GetLastSent returns the timestamp of the last sent message of the given type.
func (ms *MessageStats) GetLastSent(msgType uint8) (time.Time, bool) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	t, exists := ms.lastSent[msgType]
	return t, exists
}

// GetLastReceived returns the timestamp of the last received message of the given type.
func (ms *MessageStats) GetLastReceived(msgType uint8) (time.Time, bool) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	t, exists := ms.lastReceived[msgType]
	return t, exists
}

// Reset clears all statistics.
func (ms *MessageStats) Reset() {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.sent = make(map[uint8]uint64)
	ms.received = make(map[uint8]uint64)
	ms.lastSent = make(map[uint8]time.Time)
	ms.lastReceived = make(map[uint8]time.Time)
	ms.startTime = time.Now()
	ms.bytesSent = 0
	ms.bytesReceived = 0
}

// Summary returns a human-readable summary of message statistics.
func (ms *MessageStats) Summary() string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if !ms.enabled {
		return "Message statistics tracking is disabled"
	}

	duration := time.Since(ms.startTime)

	summary := fmt.Sprintf("Message Statistics (tracking for %v):\n", duration)
	summary += fmt.Sprintf("  Total Bytes: sent=%d, received=%d\n", ms.bytesSent, ms.bytesReceived)
	summary += fmt.Sprintf("  Total Messages: sent=%d, received=%d\n\n", ms.totalSent(), ms.totalReceived())

	summary += "Sent Messages:\n"
	for msgType, count := range ms.sent {
		lastTime := ms.lastSent[msgType]
		summary += fmt.Sprintf("  %s (type %d): count=%d, last=%v\n",
			getMessageTypeName(msgType), msgType, count, lastTime.Format(time.RFC3339))
	}

	summary += "\nReceived Messages:\n"
	for msgType, count := range ms.received {
		lastTime := ms.lastReceived[msgType]
		summary += fmt.Sprintf("  %s (type %d): count=%d, last=%v\n",
			getMessageTypeName(msgType), msgType, count, lastTime.Format(time.RFC3339))
	}

	return summary
}

// DiagnosticReport generates a diagnostic report for troubleshooting session creation issues.
// This is particularly useful when debugging "no SessionCreated response" problems.
func (ms *MessageStats) DiagnosticReport() string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if !ms.enabled {
		return "Message statistics tracking is disabled. Enable with client.EnableMessageStats()"
	}

	duration := time.Since(ms.startTime)
	report := fmt.Sprintf("=== I2CP Diagnostic Report (tracking for %v) ===\n\n", duration)

	// Check if CreateSession was sent
	createSent := ms.sent[I2CP_MSG_CREATE_SESSION]
	if createSent == 0 {
		report += "❌ ISSUE: No CreateSession message sent\n"
		report += "   → CreateSession must be sent before expecting SessionCreated response\n\n"
	} else {
		report += fmt.Sprintf("✓ CreateSession sent: %d time(s)\n", createSent)
		if lastSent, exists := ms.lastSent[I2CP_MSG_CREATE_SESSION]; exists {
			report += fmt.Sprintf("  Last sent: %v (%v ago)\n", lastSent.Format(time.RFC3339), time.Since(lastSent))
		}
		report += "\n"
	}

	// Check if SessionStatus was received
	statusReceived := ms.received[I2CP_MSG_SESSION_STATUS]
	if createSent > 0 && statusReceived == 0 {
		report += "❌ ISSUE: SessionStatus response not received\n"
		report += "   Possible causes:\n"
		report += "   1. Router not responding (check router logs)\n"
		report += "   2. ProcessIO not running (must be started before CreateSession)\n"
		report += "   3. Network/connection issue\n"
		report += "   4. Router rejected session (would show in router logs)\n\n"
	} else if statusReceived > 0 {
		report += fmt.Sprintf("✓ SessionStatus received: %d time(s)\n", statusReceived)
		if lastRecv, exists := ms.lastReceived[I2CP_MSG_SESSION_STATUS]; exists {
			report += fmt.Sprintf("  Last received: %v (%v ago)\n", lastRecv.Format(time.RFC3339), time.Since(lastRecv))
		}
		report += "\n"
	}

	// Check message flow
	report += fmt.Sprintf("Message Flow:\n")
	report += fmt.Sprintf("  Sent:     %d messages (%d bytes)\n", ms.totalSent(), ms.bytesSent)
	report += fmt.Sprintf("  Received: %d messages (%d bytes)\n", ms.totalReceived(), ms.bytesReceived)

	if ms.totalSent() > 0 && ms.totalReceived() == 0 {
		report += "\n❌ WARNING: Messages sent but none received - ProcessIO may not be running\n"
	}

	return report
}

// totalSent returns the total number of sent messages.
func (ms *MessageStats) totalSent() uint64 {
	var total uint64
	for _, count := range ms.sent {
		total += count
	}
	return total
}

// totalReceived returns the total number of received messages.
func (ms *MessageStats) totalReceived() uint64 {
	var total uint64
	for _, count := range ms.received {
		total += count
	}
	return total
}

// ConnectionState represents the current state of the I2CP connection.
type ConnectionState struct {
	Connected       bool
	RouterVersion   string
	RouterDate      time.Time
	SessionsActive  int
	PrimarySessions int
	SubSessions     int
	LastError       error
	LastErrorTime   time.Time
	ConnectedSince  time.Time
}

// GetConnectionState returns the current connection state for diagnostic purposes.
func (c *Client) GetConnectionState() *ConnectionState {
	if err := c.ensureInitialized(); err != nil {
		return &ConnectionState{
			Connected:     false,
			LastError:     err,
			LastErrorTime: time.Now(),
		}
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	state := &ConnectionState{
		Connected:      c.connected,
		SessionsActive: len(c.sessions),
	}

	// Get router info
	c.routerVersionMu.RLock()
	state.RouterVersion = c.routerVersion
	c.routerVersionMu.RUnlock()

	if c.router.date > 0 {
		state.RouterDate = time.Unix(int64(c.router.date/1000), 0)
	}

	// Count primary vs subsessions
	for _, sess := range c.sessions {
		if sess.isPrimary {
			state.PrimarySessions++
		} else {
			state.SubSessions++
		}
	}

	return state
}

// GetMessageStats returns the current message statistics for diagnostic purposes.
// Returns nil if message statistics tracking is not enabled.
func (c *Client) GetMessageStats() *MessageStats {
	if err := c.ensureInitialized(); err != nil {
		return nil
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.messageStats
}

// EnableMessageStats enables message statistics tracking for diagnostic purposes.
// This should be enabled when troubleshooting I2CP protocol issues.
func (c *Client) EnableMessageStats() {
	if err := c.ensureInitialized(); err != nil {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.messageStats == nil {
		c.messageStats = NewMessageStats()
	}
	c.messageStats.Enable()
	Debug("Message statistics tracking enabled")
}

// DisableMessageStats disables message statistics tracking.
func (c *Client) DisableMessageStats() {
	if err := c.ensureInitialized(); err != nil {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.messageStats != nil {
		c.messageStats.Disable()
		Debug("Message statistics tracking disabled")
	}
}

// PrintDiagnostics prints a comprehensive diagnostic report to help troubleshoot I2CP issues.
// This is particularly useful when debugging session creation timeouts.
func (c *Client) PrintDiagnostics() {
	if err := c.ensureInitialized(); err != nil {
		Error("Cannot print diagnostics: %v", err)
		return
	}

	Info("=== I2CP Client Diagnostics ===")

	// Connection state
	state := c.GetConnectionState()
	Info("Connection State:")
	Info("  Connected: %v", state.Connected)
	if state.Connected {
		Info("  Router Version: %s", state.RouterVersion)
		Info("  Router Date: %v", state.RouterDate)
		Info("  Active Sessions: %d (primary: %d, subsessions: %d)",
			state.SessionsActive, state.PrimarySessions, state.SubSessions)
	}
	if state.LastError != nil {
		Error("  Last Error: %v (at %v)", state.LastError, state.LastErrorTime)
	}

	// Message statistics
	if c.messageStats != nil && c.messageStats.IsEnabled() {
		Info("\n%s", c.messageStats.DiagnosticReport())
	} else {
		Info("\nMessage statistics tracking is disabled")
		Info("Enable with client.EnableMessageStats() to track message flow")
	}
}
