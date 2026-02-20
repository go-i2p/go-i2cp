package go_i2cp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMessageStats_EnableDisable verifies message statistics can be enabled and disabled
func TestMessageStats_EnableDisable(t *testing.T) {
	client := NewClient(nil)

	// Initially disabled
	if client.messageStats != nil && client.messageStats.IsEnabled() {
		t.Error("Message stats should be disabled by default")
	}

	// Enable
	client.EnableMessageStats()
	stats := client.GetMessageStats()
	if stats == nil {
		t.Fatal("GetMessageStats() returned nil after enabling")
	}
	if !stats.IsEnabled() {
		t.Error("Message stats should be enabled after EnableMessageStats()")
	}

	// Disable
	client.DisableMessageStats()
	if stats.IsEnabled() {
		t.Error("Message stats should be disabled after DisableMessageStats()")
	}
}

// TestMessageStats_RecordMessages verifies message recording functionality
func TestMessageStats_RecordMessages(t *testing.T) {
	stats := NewMessageStats()
	stats.Enable()

	// Record some messages
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)

	// Verify counts
	if count := stats.GetSentCount(I2CP_MSG_CREATE_SESSION); count != 1 {
		t.Errorf("Expected 1 CreateSession sent, got %d", count)
	}
	if count := stats.GetReceivedCount(I2CP_MSG_SESSION_STATUS); count != 1 {
		t.Errorf("Expected 1 SessionStatus received, got %d", count)
	}

	// Verify timestamps
	if lastSent, ok := stats.GetLastSent(I2CP_MSG_CREATE_SESSION); !ok {
		t.Error("Expected timestamp for sent CreateSession")
	} else if time.Since(lastSent) > time.Second {
		t.Error("Timestamp for sent message is too old")
	}

	if lastRecv, ok := stats.GetLastReceived(I2CP_MSG_SESSION_STATUS); !ok {
		t.Error("Expected timestamp for received SessionStatus")
	} else if time.Since(lastRecv) > time.Second {
		t.Error("Timestamp for received message is too old")
	}
}

// TestMessageStats_DiagnosticReport verifies diagnostic report generation
func TestMessageStats_DiagnosticReport(t *testing.T) {
	stats := NewMessageStats()
	stats.Enable()

	// Test case 1: No messages (should warn about no CreateSession)
	report := stats.DiagnosticReport()
	if report == "" {
		t.Error("DiagnosticReport() should return non-empty report")
	}
	t.Logf("Diagnostic report (no messages):\n%s", report)

	// Test case 2: CreateSession sent but no SessionStatus
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	report = stats.DiagnosticReport()
	if report == "" {
		t.Error("DiagnosticReport() should return non-empty report")
	}
	t.Logf("Diagnostic report (no response):\n%s", report)

	// Test case 3: Both CreateSession and SessionStatus
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)
	report = stats.DiagnosticReport()
	if report == "" {
		t.Error("DiagnosticReport() should return non-empty report")
	}
	t.Logf("Diagnostic report (success):\n%s", report)
}

// TestMessageStats_Summary verifies summary generation
func TestMessageStats_Summary(t *testing.T) {
	stats := NewMessageStats()
	stats.Enable()

	// Record various messages
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	stats.RecordSent(I2CP_MSG_SEND_MESSAGE, 200)
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)
	stats.RecordReceived(I2CP_MSG_PAYLOAD_MESSAGE, 150)

	summary := stats.Summary()
	if summary == "" {
		t.Error("Summary() should return non-empty summary")
	}
	t.Logf("Message statistics summary:\n%s", summary)
}

// TestMessageStats_Reset verifies statistics can be reset
func TestMessageStats_Reset(t *testing.T) {
	stats := NewMessageStats()
	stats.Enable()

	// Record some messages
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)

	// Verify counts
	if count := stats.GetSentCount(I2CP_MSG_CREATE_SESSION); count != 1 {
		t.Errorf("Expected 1 message before reset, got %d", count)
	}

	// Reset
	stats.Reset()

	// Verify counts are cleared
	if count := stats.GetSentCount(I2CP_MSG_CREATE_SESSION); count != 0 {
		t.Errorf("Expected 0 messages after reset, got %d", count)
	}
	if count := stats.GetReceivedCount(I2CP_MSG_SESSION_STATUS); count != 0 {
		t.Errorf("Expected 0 messages after reset, got %d", count)
	}
}

// TestConnectionState verifies connection state inspection
func TestConnectionState(t *testing.T) {
	client := NewClient(nil)

	state := client.GetConnectionState()
	if state == nil {
		t.Fatal("GetConnectionState() returned nil")
	}

	// Should not be connected initially
	if state.Connected {
		t.Error("Client should not be connected initially")
	}

	// Check other fields are initialized
	if state.SessionsActive < 0 {
		t.Error("SessionsActive should not be negative")
	}
}

// TestPrintDiagnostics verifies diagnostic printing doesn't panic
func TestPrintDiagnostics(t *testing.T) {
	client := NewClient(nil)
	client.EnableMessageStats()

	// Should not panic even without connection
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PrintDiagnostics() panicked: %v", r)
		}
	}()

	client.PrintDiagnostics()
}

// TestSessionStatusName verifies session status name helper
func TestSessionStatusName(t *testing.T) {
	tests := []struct {
		status   SessionStatus
		expected string
	}{
		{I2CP_SESSION_STATUS_CREATED, "CREATED"},
		{I2CP_SESSION_STATUS_DESTROYED, "DESTROYED"},
		{I2CP_SESSION_STATUS_UPDATED, "UPDATED"},
		{I2CP_SESSION_STATUS_INVALID, "INVALID"},
		{I2CP_SESSION_STATUS_REFUSED, "REFUSED"},
		{SessionStatus(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := getSessionStatusName(tt.status)
			if name != tt.expected {
				t.Errorf("getSessionStatusName(%d) = %q, want %q", tt.status, name, tt.expected)
			}
		})
	}
}

// TestMessageStats_ThreadSafety verifies concurrent access is safe
func TestMessageStats_ThreadSafety(t *testing.T) {
	stats := NewMessageStats()
	stats.Enable()

	done := make(chan bool)

	// Concurrent writers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
				stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)
			}
			done <- true
		}()
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = stats.GetSentCount(I2CP_MSG_CREATE_SESSION)
				_ = stats.GetReceivedCount(I2CP_MSG_SESSION_STATUS)
				_ = stats.Summary()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	// Verify counts are correct
	totalSent := stats.GetSentCount(I2CP_MSG_CREATE_SESSION)
	if totalSent != 1000 {
		t.Errorf("Expected 1000 messages sent, got %d", totalSent)
	}
}

// TestMessageStats_DisabledNoTracking verifies disabled stats don't track
func TestMessageStats_DisabledNoTracking(t *testing.T) {
	stats := NewMessageStats()
	// Don't enable stats

	// Record messages (should be ignored)
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)

	// Verify no tracking occurred
	if count := stats.GetSentCount(I2CP_MSG_CREATE_SESSION); count != 0 {
		t.Errorf("Disabled stats should not track, got count=%d", count)
	}
}

// TestClient_MessageStatsIntegration verifies stats integrate with client
func TestClient_MessageStatsIntegration(t *testing.T) {
	client := NewClient(nil)
	client.EnableMessageStats()

	// Simulate sending a message (without actual TCP connection)
	stream := NewStream(make([]byte, 0, 100))
	stream.WriteUint16(123) // session ID

	// This would normally send via TCP, but we just test the stats tracking
	// The actual sendMessage will fail without a connection, but stats should work

	stats := client.GetMessageStats()
	if stats == nil {
		t.Fatal("GetMessageStats() returned nil")
	}

	if !stats.IsEnabled() {
		t.Error("Stats should be enabled")
	}
}

// TestMessageStats_ConnectionStateIntegration verifies connection state tracking
func TestMessageStats_ConnectionStateIntegration(t *testing.T) {
	client := NewClient(nil)

	// Initially not connected
	state := client.GetConnectionState()
	if state.Connected {
		t.Error("Client should not be connected initially")
	}

	// Verify session counts
	if state.SessionsActive != 0 {
		t.Errorf("Expected 0 active sessions, got %d", state.SessionsActive)
	}
	if state.PrimarySessions != 0 {
		t.Errorf("Expected 0 primary sessions, got %d", state.PrimarySessions)
	}
	if state.SubSessions != 0 {
		t.Errorf("Expected 0 subsessions, got %d", state.SubSessions)
	}
}

// BenchmarkMessageStats_RecordMessage benchmarks message recording
func BenchmarkMessageStats_RecordMessage(b *testing.B) {
	stats := NewMessageStats()
	stats.Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	}
}

// BenchmarkMessageStats_GetCount benchmarks count retrieval
func BenchmarkMessageStats_GetCount(b *testing.B) {
	stats := NewMessageStats()
	stats.Enable()
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stats.GetSentCount(I2CP_MSG_CREATE_SESSION)
	}
}

// BenchmarkMessageStats_DiagnosticReport benchmarks report generation
func BenchmarkMessageStats_DiagnosticReport(b *testing.B) {
	stats := NewMessageStats()
	stats.Enable()
	stats.RecordSent(I2CP_MSG_CREATE_SESSION, 100)
	stats.RecordReceived(I2CP_MSG_SESSION_STATUS, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = stats.DiagnosticReport()
	}
}

// --- merged from debug_diagnostics_test.go ---

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
