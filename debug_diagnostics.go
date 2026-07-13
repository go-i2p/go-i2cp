package go_i2cp

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// reportBuilder is a helper for constructing diagnostic reports with consistent formatting.
type reportBuilder struct {
	buf *strings.Builder
}

// newReportBuilder creates a new report builder.
func newReportBuilder() *reportBuilder {
	return &reportBuilder{
		buf: &strings.Builder{},
	}
}

// Section writes a formatted section to the report with a newline appended.
func (rb *reportBuilder) Section(format string, args ...interface{}) {
	fmt.Fprintf(rb.buf, format+"\n", args...)
}

// Append appends raw content to the report without formatting.
func (rb *reportBuilder) Append(content string) {
	rb.buf.WriteString(content)
}

// String returns the accumulated report as a string.
func (rb *reportBuilder) String() string {
	return rb.buf.String()
}

// SessionState represents the lifecycle state of an I2CP session.
// This helps diagnose where in the protocol flow issues occur.
type SessionState uint8

const (
	// SessionStatePending - CreateSession sent, awaiting response
	SessionStatePending SessionState = iota
	// SessionStateCreated - SessionStatus received with CREATED status
	SessionStateCreated
	// SessionStateAwaitingLeaseSet - Waiting for RequestVariableLeaseSet from router
	SessionStateAwaitingLeaseSet
	// SessionStateLeaseSetRequested - Router requested LeaseSet (type 37 received)
	SessionStateLeaseSetRequested
	// SessionStateLeaseSetSent - CreateLeaseSet2 sent to router
	SessionStateLeaseSetSent
	// SessionStateActive - Session fully established and active
	SessionStateActive
	// SessionStateDestroying - DestroySession sent
	SessionStateDestroying
	// SessionStateDestroyed - Session destroyed
	SessionStateDestroyed
	// SessionStateRejected - Session was rejected by router
	SessionStateRejected
	// SessionStateDisconnected - Connection lost
	SessionStateDisconnected
)

var sessionStateNames = map[SessionState]string{
	SessionStatePending:           "PENDING",
	SessionStateCreated:           "CREATED",
	SessionStateAwaitingLeaseSet:  "AWAITING_LEASESET",
	SessionStateLeaseSetRequested: "LEASESET_REQUESTED",
	SessionStateLeaseSetSent:      "LEASESET_SENT",
	SessionStateActive:            "ACTIVE",
	SessionStateDestroying:        "DESTROYING",
	SessionStateDestroyed:         "DESTROYED",
	SessionStateRejected:          "REJECTED",
	SessionStateDisconnected:      "DISCONNECTED",
}

// String returns a human-readable name for the session state.
func (s SessionState) String() string {
	if name, ok := sessionStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}

// SessionStateTracker tracks the lifecycle state of I2CP sessions for debugging.
type SessionStateTracker struct {
	mu               sync.RWMutex
	states           map[uint16]SessionState               // Session ID -> State
	stateTimestamps  map[uint16]map[SessionState]time.Time // Session ID -> State -> Time
	stateHistory     map[uint16][]StateTransition          // Session ID -> History
	pendingSessionID uint16                                // Session ID of pending session (before ID assigned)
	leaseSetWaiters  map[uint16]*LeaseSetWaitInfo          // Sessions waiting for RequestVariableLeaseSet
	enabled          bool
}

// StateTransition records a state change for diagnostic purposes.
type StateTransition struct {
	From      SessionState
	To        SessionState
	Timestamp time.Time
	Reason    string
}

// LeaseSetWaitInfo tracks waiting for RequestVariableLeaseSet message.
type LeaseSetWaitInfo struct {
	SessionID   uint16
	StartedAt   time.Time
	Timeout     time.Duration
	Received    bool
	ReceivedAt  time.Time
	TunnelCount uint8
}

// NewSessionStateTracker creates a new session state tracker.
func NewSessionStateTracker() *SessionStateTracker {
	return &SessionStateTracker{
		states:          make(map[uint16]SessionState),
		stateTimestamps: make(map[uint16]map[SessionState]time.Time),
		stateHistory:    make(map[uint16][]StateTransition),
		leaseSetWaiters: make(map[uint16]*LeaseSetWaitInfo),
		enabled:         false,
	}
}

// Enable enables session state tracking.
func (sst *SessionStateTracker) Enable() {
	sst.mu.Lock()
	defer sst.mu.Unlock()
	sst.enabled = true
}

// Disable disables session state tracking.
func (sst *SessionStateTracker) Disable() {
	sst.mu.Lock()
	defer sst.mu.Unlock()
	sst.enabled = false
}

// IsEnabled returns whether state tracking is enabled.
func (sst *SessionStateTracker) IsEnabled() bool {
	sst.mu.RLock()
	defer sst.mu.RUnlock()
	return sst.enabled
}

// SetState sets the state for a session and records the transition.
func (sst *SessionStateTracker) SetState(sessionID uint16, newState SessionState, reason string) {
	sst.mu.Lock()
	defer sst.mu.Unlock()

	if !sst.enabled {
		return
	}

	oldState, exists := sst.states[sessionID]
	now := time.Now()

	// Initialize maps for this session if needed
	if sst.stateTimestamps[sessionID] == nil {
		sst.stateTimestamps[sessionID] = make(map[SessionState]time.Time)
	}

	// Record state
	sst.states[sessionID] = newState
	sst.stateTimestamps[sessionID][newState] = now

	// Record transition history
	transition := StateTransition{
		To:        newState,
		Timestamp: now,
		Reason:    reason,
	}
	if exists {
		transition.From = oldState
	}
	sst.stateHistory[sessionID] = append(sst.stateHistory[sessionID], transition)

	// Log transition
	if exists {
		Debug("Session %d state: %s -> %s (%s)", sessionID, oldState, newState, reason)
	} else {
		Debug("Session %d state: -> %s (%s)", sessionID, newState, reason)
	}
}

// GetState returns the current state of a session.
func (sst *SessionStateTracker) GetState(sessionID uint16) (SessionState, bool) {
	sst.mu.RLock()
	defer sst.mu.RUnlock()
	state, exists := sst.states[sessionID]
	return state, exists
}

// StartLeaseSetWait records that a session is waiting for RequestVariableLeaseSet.
func (sst *SessionStateTracker) StartLeaseSetWait(sessionID uint16, timeout time.Duration) {
	sst.mu.Lock()
	defer sst.mu.Unlock()

	if !sst.enabled {
		return
	}

	sst.leaseSetWaiters[sessionID] = &LeaseSetWaitInfo{
		SessionID: sessionID,
		StartedAt: time.Now(),
		Timeout:   timeout,
		Received:  false,
	}
	Debug("Session %d: Started waiting for RequestVariableLeaseSet (timeout: %v)", sessionID, timeout)
}

// RecordLeaseSetReceived records that RequestVariableLeaseSet was received.
func (sst *SessionStateTracker) RecordLeaseSetReceived(sessionID uint16, tunnelCount uint8) {
	sst.mu.Lock()
	defer sst.mu.Unlock()

	if !sst.enabled {
		return
	}

	if info, exists := sst.leaseSetWaiters[sessionID]; exists {
		info.Received = true
		info.ReceivedAt = time.Now()
		info.TunnelCount = tunnelCount
		waitTime := info.ReceivedAt.Sub(info.StartedAt)
		Debug("Session %d: RequestVariableLeaseSet received after %v (tunnels: %d)", sessionID, waitTime, tunnelCount)
	} else {
		Debug("Session %d: RequestVariableLeaseSet received (no wait record)", sessionID)
	}
}

// GetLeaseSetWaitDiagnostics returns diagnostic info about LeaseSet waits.
func (sst *SessionStateTracker) GetLeaseSetWaitDiagnostics() string {
	sst.mu.RLock()
	defer sst.mu.RUnlock()

	if !sst.enabled || len(sst.leaseSetWaiters) == 0 {
		return "No LeaseSet wait information available"
	}

	report := "LeaseSet Wait Diagnostics:\n"
	for sessionID, info := range sst.leaseSetWaiters {
		report += fmt.Sprintf("  Session %d:\n", sessionID)
		report += fmt.Sprintf("    Started waiting: %v\n", info.StartedAt.Format(time.RFC3339))
		report += fmt.Sprintf("    Timeout: %v\n", info.Timeout)
		if info.Received {
			waitTime := info.ReceivedAt.Sub(info.StartedAt)
			report += fmt.Sprintf("    ✅ Received: %v (wait time: %v)\n", info.ReceivedAt.Format(time.RFC3339), waitTime)
			report += fmt.Sprintf("    Tunnel count: %d\n", info.TunnelCount)
		} else {
			elapsed := time.Since(info.StartedAt)
			if elapsed > info.Timeout {
				report += fmt.Sprintf("    ❌ TIMED OUT after %v (expected within %v)\n", elapsed, info.Timeout)
			} else {
				report += fmt.Sprintf("    ⏳ Still waiting (%v elapsed of %v)\n", elapsed, info.Timeout)
			}
		}
	}
	return report
}

// DiagnosticReport generates a comprehensive session state report.
func (sst *SessionStateTracker) DiagnosticReport() string {
	sst.mu.RLock()
	defer sst.mu.RUnlock()

	if !sst.enabled {
		return "Session state tracking is disabled"
	}

	rb := newReportBuilder()
	rb.Section("=== Session State Diagnostic Report ===")

	if len(sst.states) == 0 {
		rb.Section("No sessions tracked")
		return rb.String()
	}

	for sessionID, state := range sst.states {
		rb.Section("\nSession %d: %s", sessionID, state)

		// Add state timestamps
		if timestamps, exists := sst.stateTimestamps[sessionID]; exists {
			rb.Section("  State Timeline:")
			for s, ts := range timestamps {
				rb.Section("    %s: %v", s, ts.Format(time.RFC3339))
			}
		}

		// Add state history
		if history, exists := sst.stateHistory[sessionID]; exists && len(history) > 0 {
			rb.Section("  Transition History:")
			for _, trans := range history {
				if trans.From == trans.To && trans.From == 0 {
					rb.Section("    -> %s (%s) at %v",
						trans.To, trans.Reason, trans.Timestamp.Format(time.RFC3339Nano))
				} else {
					rb.Section("    %s -> %s (%s) at %v",
						trans.From, trans.To, trans.Reason, trans.Timestamp.Format(time.RFC3339Nano))
				}
			}
		}
	}

	// Add LeaseSet wait info
	rb.Append("\n" + sst.GetLeaseSetWaitDiagnostics())

	return rb.String()
}

// ProtocolDebugger provides enhanced protocol debugging capabilities.
type ProtocolDebugger struct {
	mu                 sync.RWMutex
	enabled            bool
	dumpDir            string              // Directory for hex dumps
	messageLog         []ProtocolMessage   // Log of all messages
	disconnectInfo     *DisconnectInfo     // Last disconnect information
	createSessionDumps []CreateSessionDump // CreateSession message dumps
}

// ProtocolMessage records an I2CP message for debugging.
type ProtocolMessage struct {
	Timestamp time.Time
	Direction string // "SENT" or "RECEIVED"
	Type      uint8
	TypeName  string
	Size      uint32
	HexDump   string // First 256 bytes as hex
	SessionID uint16 // If applicable
}

// DisconnectInfo captures disconnect message details.
type DisconnectInfo struct {
	Timestamp time.Time
	Reason    string
	RawBytes  []byte
	HexDump   string
}

// CreateSessionDump captures CreateSession message for analysis.
type CreateSessionDump struct {
	Timestamp       time.Time
	TotalSize       int
	DestinationSize int
	MappingSize     int
	TimestampValue  uint64
	SignatureSize   int
	HexDump         string
	FilePath        string // Path to dumped file
}

// NewProtocolDebugger creates a new protocol debugger.
func NewProtocolDebugger() *ProtocolDebugger {
	return &ProtocolDebugger{
		enabled:            false,
		dumpDir:            "/tmp/go-i2cp-debug",
		messageLog:         make([]ProtocolMessage, 0, 1000),
		createSessionDumps: make([]CreateSessionDump, 0, 10),
	}
}

// Enable enables protocol debugging.
func (pd *ProtocolDebugger) Enable() {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.enabled = true

	// Create dump directory
	if err := os.MkdirAll(pd.dumpDir, 0o755); err != nil {
		Error("Failed to create debug dump directory: %v", err)
	}
}

// Disable disables protocol debugging.
func (pd *ProtocolDebugger) Disable() {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.enabled = false
}

// IsEnabled returns whether debugging is enabled.
func (pd *ProtocolDebugger) IsEnabled() bool {
	pd.mu.RLock()
	defer pd.mu.RUnlock()
	return pd.enabled
}

// SetDumpDir sets the directory for hex dumps.
func (pd *ProtocolDebugger) SetDumpDir(dir string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()
	pd.dumpDir = dir
	if pd.enabled {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			Error("Failed to create debug dump directory: %v", err)
		}
	}
}

// LogMessage records a protocol message.
func (pd *ProtocolDebugger) LogMessage(direction string, msgType uint8, size uint32, data []byte, sessionID uint16) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if !pd.enabled {
		return
	}

	// Create hex dump (first 256 bytes)
	dumpLen := len(data)
	if dumpLen > 256 {
		dumpLen = 256
	}
	hexDump := hex.Dump(data[:dumpLen])

	msg := ProtocolMessage{
		Timestamp: time.Now(),
		Direction: direction,
		Type:      msgType,
		TypeName:  getMessageTypeName(msgType),
		Size:      size,
		HexDump:   hexDump,
		SessionID: sessionID,
	}

	pd.messageLog = append(pd.messageLog, msg)

	// Keep only last 1000 messages
	if len(pd.messageLog) > 1000 {
		pd.messageLog = pd.messageLog[len(pd.messageLog)-1000:]
	}

	// Log to console
	Info("[%s] I2CP %s (type %d): %d bytes, session %d",
		direction, msg.TypeName, msgType, size, sessionID)
}

// DumpCreateSessionMessage saves a CreateSession message for analysis.
func (pd *ProtocolDebugger) DumpCreateSessionMessage(data []byte, destSize, mappingSize int, timestamp uint64, sigSize int) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if !pd.enabled {
		return
	}

	ts := time.Now().Format("20060102-150405.000")
	filePath := pd.writeCreateSessionBinary(ts, data)
	pd.writeCreateSessionBreakdown(ts, data, destSize, mappingSize, timestamp, sigSize)
	pd.recordCreateSessionDump(data, destSize, mappingSize, timestamp, sigSize, filePath)
}

// writeCreateSessionBinary writes the raw binary CreateSession message to a file.
func (pd *ProtocolDebugger) writeCreateSessionBinary(ts string, data []byte) string {
	filename := fmt.Sprintf("CreateSession-%s.bin", ts)
	filePath := filepath.Join(pd.dumpDir, filename)
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		Error("Failed to dump CreateSession message: %v", err)
	} else {
		Info("CreateSession message dumped to: %s", filePath)
	}
	return filePath
}

// writeCreateSessionBreakdown writes a human-readable breakdown of the message.
func (pd *ProtocolDebugger) writeCreateSessionBreakdown(ts string, data []byte, destSize, mappingSize int, timestamp uint64, sigSize int) {
	breakdownFile := filepath.Join(pd.dumpDir, fmt.Sprintf("CreateSession-%s-breakdown.txt", ts))
	breakdown := formatCreateSessionBreakdown(data, destSize, mappingSize, timestamp, sigSize)
	if err := os.WriteFile(breakdownFile, []byte(breakdown), 0o644); err != nil {
		Error("Failed to write breakdown file: %v", err)
	}
}

// formatCreateSessionBreakdown formats the breakdown content for a CreateSession message.
func formatCreateSessionBreakdown(data []byte, destSize, mappingSize int, timestamp uint64, sigSize int) string {
	return fmt.Sprintf(
		`CreateSession Message Breakdown
================================
Timestamp: %v
Total Size: %d bytes

Expected I2CP Format:
  Destination: %d bytes (expected: 391 = 256 pubKey + 128 sigKey + 7 cert)
  Mapping: %d bytes
  Date: 8 bytes (value: %d = %v)
  Signature: %d bytes (expected: 64 for Ed25519)

Hex Dump (first 512 bytes):
%s

Full Hex:
%s
`,
		time.Now().Format(time.RFC3339),
		len(data),
		destSize,
		mappingSize,
		timestamp, time.UnixMilli(int64(timestamp)).Format(time.RFC3339),
		sigSize,
		hex.Dump(data[:min(512, len(data))]),
		hex.EncodeToString(data),
	)
}

// recordCreateSessionDump records the dump info in memory for later retrieval.
func (pd *ProtocolDebugger) recordCreateSessionDump(data []byte, destSize, mappingSize int, timestamp uint64, sigSize int, filePath string) {
	dump := CreateSessionDump{
		Timestamp:       time.Now(),
		TotalSize:       len(data),
		DestinationSize: destSize,
		MappingSize:     mappingSize,
		TimestampValue:  timestamp,
		SignatureSize:   sigSize,
		HexDump:         hex.Dump(data[:min(256, len(data))]),
		FilePath:        filePath,
	}
	pd.createSessionDumps = append(pd.createSessionDumps, dump)
}

// RecordDisconnect records disconnect message details.
func (pd *ProtocolDebugger) RecordDisconnect(reason string, rawBytes []byte) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if !pd.enabled {
		return
	}

	pd.disconnectInfo = &DisconnectInfo{
		Timestamp: time.Now(),
		Reason:    reason,
		RawBytes:  rawBytes,
		HexDump:   hex.Dump(rawBytes),
	}

	// Write disconnect info to file
	ts := time.Now().Format("20060102-150405.000")
	filename := filepath.Join(pd.dumpDir, fmt.Sprintf("Disconnect-%s.txt", ts))

	content := fmt.Sprintf(
		`Disconnect Message
==================
Timestamp: %v
Reason: %s

Raw bytes (%d bytes):
%s
`,
		pd.disconnectInfo.Timestamp.Format(time.RFC3339),
		reason,
		len(rawBytes),
		pd.disconnectInfo.HexDump,
	)

	if err := os.WriteFile(filename, []byte(content), 0o644); err != nil {
		Error("Failed to write disconnect dump: %v", err)
	}

	Error("❌ DISCONNECT received: %s", reason)
	if len(reason) == 0 && len(rawBytes) > 0 {
		Error("   Raw disconnect bytes: %x", rawBytes)
	}
}

// GetMessageLog returns recent message log.
func (pd *ProtocolDebugger) GetMessageLog(limit int) []ProtocolMessage {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if limit <= 0 || limit > len(pd.messageLog) {
		limit = len(pd.messageLog)
	}

	result := make([]ProtocolMessage, limit)
	copy(result, pd.messageLog[len(pd.messageLog)-limit:])
	return result
}

// GetDisconnectInfo returns the last disconnect information.
func (pd *ProtocolDebugger) GetDisconnectInfo() *DisconnectInfo {
	pd.mu.RLock()
	defer pd.mu.RUnlock()
	return pd.disconnectInfo
}

// DiagnosticReport generates a comprehensive debug report.
func (pd *ProtocolDebugger) DiagnosticReport() string {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if !pd.enabled {
		return "Protocol debugging is disabled"
	}

	rb := newReportBuilder()
	rb.Section("=== Protocol Debug Report ===")
	rb.Section("Dump directory: %s", pd.dumpDir)
	rb.Section("Messages logged: %d", len(pd.messageLog))
	rb.Section("")

	// Recent Messages section
	rb.Section("Recent Messages (last 20):")
	start := len(pd.messageLog) - 20
	if start < 0 {
		start = 0
	}
	for _, msg := range pd.messageLog[start:] {
		rb.Section("  [%s] %s %s (%d bytes)",
			msg.Timestamp.Format("15:04:05.000"),
			msg.Direction,
			msg.TypeName,
			msg.Size,
		)
	}

	// CreateSession Dumps section
	if len(pd.createSessionDumps) > 0 {
		rb.Section("\nCreateSession Dumps:")
		for i, dump := range pd.createSessionDumps {
			rb.Section("  %d. %v - %d bytes (dest:%d, map:%d, sig:%d)",
				i+1, dump.Timestamp.Format(time.RFC3339),
				dump.TotalSize, dump.DestinationSize, dump.MappingSize, dump.SignatureSize)
			rb.Section("     File: %s", dump.FilePath)
		}
	}

	// Last Disconnect section
	if pd.disconnectInfo != nil {
		rb.Section("\nLast Disconnect:")
		rb.Section("  Time: %v", pd.disconnectInfo.Timestamp.Format(time.RFC3339))
		rb.Section("  Reason: %s", pd.disconnectInfo.Reason)
		if len(pd.disconnectInfo.RawBytes) > 0 {
			rb.Section("  Raw: %x", pd.disconnectInfo.RawBytes)
		}
	}

	return rb.String()
}

// DebugConfig holds debugging configuration options.
type DebugConfig struct {
	EnableMessageStats     bool   // Enable message statistics tracking
	EnableStateTracking    bool   // Enable session state tracking
	EnableProtocolDebug    bool   // Enable protocol debugging
	DumpDirectory          string // Directory for debug dumps
	LogMessageHex          bool   // Log message hex dumps to console
	LogCreateSessionDetail bool   // Extra logging for CreateSession
}

// DefaultDebugConfig returns sensible debug defaults.
func DefaultDebugConfig() *DebugConfig {
	return &DebugConfig{
		EnableMessageStats:     true,
		EnableStateTracking:    true,
		EnableProtocolDebug:    true,
		DumpDirectory:          "/tmp/go-i2cp-debug",
		LogMessageHex:          false, // Don't spam console by default
		LogCreateSessionDetail: true,
	}
}

// EnableAllDebugging enables all debugging features on a client with default config.
func (c *Client) EnableAllDebugging() error {
	return c.EnableDebugging(DefaultDebugConfig())
}

// EnableDebugging enables debugging features based on the provided config.
func (c *Client) EnableDebugging(config *DebugConfig) error {
	if err := c.ensureInitialized(); err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	// Enable message statistics tracking if requested
	if config.EnableMessageStats {
		if c.messageStats == nil {
			c.messageStats = NewMessageStats()
		}
		c.messageStats.Enable()
	}

	// Enable session state tracking if requested
	if config.EnableStateTracking {
		if c.stateTracker == nil {
			c.stateTracker = NewSessionStateTracker()
		}
		c.stateTracker.Enable()
	}

	// Enable protocol debugging if requested
	if config.EnableProtocolDebug {
		if c.protocolDebugger == nil {
			c.protocolDebugger = NewProtocolDebugger()
		}
		if config.DumpDirectory != "" {
			c.protocolDebugger.SetDumpDir(config.DumpDirectory)
		}
		c.protocolDebugger.Enable()
	}

	Info("I2CP debugging enabled: stats=%v, state=%v, protocol=%v",
		config.EnableMessageStats, config.EnableStateTracking, config.EnableProtocolDebug)

	return nil
}

// DisableAllDebugging disables all debugging features.
func (c *Client) DisableAllDebugging() {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.messageStats != nil {
		c.messageStats.Disable()
	}
	if c.stateTracker != nil {
		c.stateTracker.Disable()
	}
	if c.protocolDebugger != nil {
		c.protocolDebugger.Disable()
	}
}

// GetStateTracker returns the session state tracker.
func (c *Client) GetStateTracker() *SessionStateTracker {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.stateTracker
}

// GetProtocolDebugger returns the protocol debugger.
func (c *Client) GetProtocolDebugger() *ProtocolDebugger {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.protocolDebugger
}

// PrintFullDiagnostics prints comprehensive diagnostics including all debug info.
func (c *Client) PrintFullDiagnostics() {
	if err := c.ensureInitialized(); err != nil {
		Error("Cannot print diagnostics: %v", err)
		return
	}

	Info("==========================================")
	Info("    I2CP FULL DIAGNOSTIC REPORT")
	Info("==========================================")

	// Basic diagnostics
	c.PrintDiagnostics()

	// Session state tracking
	if c.stateTracker != nil && c.stateTracker.IsEnabled() {
		Info("\n%s", c.stateTracker.DiagnosticReport())
	}

	// Protocol debug info
	if c.protocolDebugger != nil && c.protocolDebugger.IsEnabled() {
		Info("\n%s", c.protocolDebugger.DiagnosticReport())
	}

	Info("==========================================")
}
