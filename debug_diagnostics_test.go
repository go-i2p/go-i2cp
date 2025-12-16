package go_i2cp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSessionStateTracker tests the session state tracking functionality.
func TestSessionStateTracker(t *testing.T) {
	tracker := NewSessionStateTracker()

	// Test enable/disable
	if tracker.IsEnabled() {
		t.Error("Tracker should be disabled by default")
	}

	tracker.Enable()
	if !tracker.IsEnabled() {
		t.Error("Tracker should be enabled after Enable()")
	}

	// Test state setting
	tracker.SetState(1, SessionStatePending, "CreateSession sent")
	state, exists := tracker.GetState(1)
	if !exists {
		t.Error("State should exist for session 1")
	}
	if state != SessionStatePending {
		t.Errorf("Expected PENDING state, got %s", state)
	}

	// Test state transitions
	tracker.SetState(1, SessionStateCreated, "SessionStatus received")
	state, _ = tracker.GetState(1)
	if state != SessionStateCreated {
		t.Errorf("Expected CREATED state, got %s", state)
	}

	tracker.SetState(1, SessionStateAwaitingLeaseSet, "waiting for RequestVariableLeaseSet")
	state, _ = tracker.GetState(1)
	if state != SessionStateAwaitingLeaseSet {
		t.Errorf("Expected AWAITING_LEASESET state, got %s", state)
	}

	// Test diagnostic report
	report := tracker.DiagnosticReport()
	if len(report) == 0 {
		t.Error("Diagnostic report should not be empty")
	}
	t.Log("Diagnostic report:\n", report)

	// Test disable
	tracker.Disable()
	if tracker.IsEnabled() {
		t.Error("Tracker should be disabled after Disable()")
	}
}

// TestLeaseSetWaitTracking tests the LeaseSet wait tracking functionality.
func TestLeaseSetWaitTracking(t *testing.T) {
	tracker := NewSessionStateTracker()
	tracker.Enable()

	// Start waiting
	tracker.StartLeaseSetWait(1, 30*time.Second)

	// Check diagnostics while waiting
	diag := tracker.GetLeaseSetWaitDiagnostics()
	if len(diag) == 0 {
		t.Error("Wait diagnostics should not be empty")
	}
	t.Log("Wait diagnostics (before receive):\n", diag)

	// Simulate receiving RequestVariableLeaseSet
	time.Sleep(10 * time.Millisecond)
	tracker.RecordLeaseSetReceived(1, 3)

	// Check diagnostics after receive
	diag = tracker.GetLeaseSetWaitDiagnostics()
	t.Log("Wait diagnostics (after receive):\n", diag)
}

// TestProtocolDebugger tests the protocol debugging functionality.
func TestProtocolDebugger(t *testing.T) {
	debugger := NewProtocolDebugger()

	// Test enable/disable
	if debugger.IsEnabled() {
		t.Error("Debugger should be disabled by default")
	}

	// Create temp directory for dumps
	tmpDir := filepath.Join(os.TempDir(), "go-i2cp-test-debug")
	defer os.RemoveAll(tmpDir)

	debugger.SetDumpDir(tmpDir)
	debugger.Enable()

	if !debugger.IsEnabled() {
		t.Error("Debugger should be enabled after Enable()")
	}

	// Test message logging
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	debugger.LogMessage("SEND", I2CP_MSG_CREATE_SESSION, 5, testData, 0)
	debugger.LogMessage("RECV", I2CP_MSG_SESSION_STATUS, 3, []byte{0x00, 0x01, 0x00}, 0)

	// Test CreateSession dump
	createSessionData := make([]byte, 500)
	for i := range createSessionData {
		createSessionData[i] = byte(i % 256)
	}
	debugger.DumpCreateSessionMessage(createSessionData, 391, 45, 1234567890000, 64)

	// Check that dump file was created
	files, err := filepath.Glob(filepath.Join(tmpDir, "CreateSession-*.bin"))
	if err != nil {
		t.Errorf("Failed to glob dump files: %v", err)
	}
	if len(files) == 0 {
		t.Error("CreateSession dump file should have been created")
	}

	// Test disconnect recording
	debugger.RecordDisconnect("Test disconnect reason", []byte("disconnect data"))

	// Check disconnect info
	disconnectInfo := debugger.GetDisconnectInfo()
	if disconnectInfo == nil {
		t.Error("Disconnect info should not be nil")
	}
	if disconnectInfo.Reason != "Test disconnect reason" {
		t.Errorf("Expected disconnect reason 'Test disconnect reason', got '%s'", disconnectInfo.Reason)
	}

	// Test diagnostic report
	report := debugger.DiagnosticReport()
	if len(report) == 0 {
		t.Error("Diagnostic report should not be empty")
	}
	t.Log("Protocol debug report:\n", report)

	// Test message log retrieval
	messages := debugger.GetMessageLog(10)
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages in log, got %d", len(messages))
	}
}

// TestSessionStateString tests the SessionState String() method.
func TestSessionStateString(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{SessionStatePending, "PENDING"},
		{SessionStateCreated, "CREATED"},
		{SessionStateAwaitingLeaseSet, "AWAITING_LEASESET"},
		{SessionStateLeaseSetRequested, "LEASESET_REQUESTED"},
		{SessionStateLeaseSetSent, "LEASESET_SENT"},
		{SessionStateActive, "ACTIVE"},
		{SessionStateDestroying, "DESTROYING"},
		{SessionStateDestroyed, "DESTROYED"},
		{SessionStateRejected, "REJECTED"},
		{SessionStateDisconnected, "DISCONNECTED"},
		{SessionState(255), "UNKNOWN(255)"},
	}

	for _, test := range tests {
		result := test.state.String()
		if result != test.expected {
			t.Errorf("SessionState(%d).String() = %s, expected %s", test.state, result, test.expected)
		}
	}
}

// TestDebugConfig tests the debugging configuration.
func TestDebugConfig(t *testing.T) {
	config := DefaultDebugConfig()

	if !config.EnableMessageStats {
		t.Error("EnableMessageStats should be true by default")
	}
	if !config.EnableStateTracking {
		t.Error("EnableStateTracking should be true by default")
	}
	if !config.EnableProtocolDebug {
		t.Error("EnableProtocolDebug should be true by default")
	}
	if config.DumpDirectory == "" {
		t.Error("DumpDirectory should not be empty")
	}
}

// TestClientDebugIntegration tests enabling debugging on a client.
func TestClientDebugIntegration(t *testing.T) {
	client := NewClient(nil)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	defer client.Close()

	// Test enabling all debugging
	err := client.EnableAllDebugging()
	if err != nil {
		t.Errorf("EnableAllDebugging failed: %v", err)
	}

	// Verify debuggers are enabled
	tracker := client.GetStateTracker()
	if tracker == nil || !tracker.IsEnabled() {
		t.Error("State tracker should be enabled")
	}

	debugger := client.GetProtocolDebugger()
	if debugger == nil || !debugger.IsEnabled() {
		t.Error("Protocol debugger should be enabled")
	}

	stats := client.GetMessageStats()
	if stats == nil || !stats.IsEnabled() {
		t.Error("Message stats should be enabled")
	}

	// Test disabling
	client.DisableAllDebugging()

	if tracker.IsEnabled() {
		t.Error("State tracker should be disabled")
	}
	if debugger.IsEnabled() {
		t.Error("Protocol debugger should be disabled")
	}
	if stats.IsEnabled() {
		t.Error("Message stats should be disabled")
	}
}

// TestLeaseSetWaitTimeout tests the timeout tracking for LeaseSet waits.
func TestLeaseSetWaitTimeout(t *testing.T) {
	tracker := NewSessionStateTracker()
	tracker.Enable()

	// Start waiting with a very short timeout
	tracker.StartLeaseSetWait(1, 10*time.Millisecond)

	// Wait for timeout
	time.Sleep(20 * time.Millisecond)

	// Check diagnostics - should show timeout info
	diag := tracker.GetLeaseSetWaitDiagnostics()
	if len(diag) == 0 {
		t.Error("Diagnostics should show timeout info")
	}
	t.Log("Timeout diagnostics:\n", diag)

	// Check that diagnostic contains session info
	if len(diag) < 20 {
		t.Error("Diagnostics should contain substantial info")
	}
}

// BenchmarkStateTracking benchmarks the overhead of state tracking.
func BenchmarkStateTracking(b *testing.B) {
	tracker := NewSessionStateTracker()
	tracker.Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionID := uint16(i % 100)
		tracker.SetState(sessionID, SessionStateCreated, "test")
	}
}

// BenchmarkProtocolLogging benchmarks the overhead of protocol logging.
func BenchmarkProtocolLogging(b *testing.B) {
	debugger := NewProtocolDebugger()
	debugger.Enable()

	testData := make([]byte, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		debugger.LogMessage("SEND", I2CP_MSG_SEND_MESSAGE, 100, testData, uint16(i%100))
	}
}
