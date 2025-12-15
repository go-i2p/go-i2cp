# I2CP Diagnostics Example

This example demonstrates go-i2cp's comprehensive diagnostic capabilities for troubleshooting I2CP protocol interactions.

## Purpose

This example is particularly useful for:

- **Debugging session creation timeouts** with Java I2P routers
- **Understanding I2CP message flow** between client and router
- **Identifying protocol issues** (missing messages, callbacks not invoked, etc.)
- **Learning go-i2cp diagnostic tools** for production troubleshooting

## What This Example Demonstrates

1. **Enabling Debug Logging** - Trace all I2CP protocol messages
2. **Message Statistics Tracking** - Track sent/received message counts by type
3. **Connection State Inspection** - Check router version, session count, etc.
4. **Diagnostic Report Generation** - Comprehensive troubleshooting report
5. **Session Creation Monitoring** - Detect and diagnose timeout issues
6. **Message Flow Analysis** - Verify request/response patterns

## Running the Example

### Prerequisites

- Running I2P router with I2CP enabled (default port 7654)
- Go 1.19+

### Run

```bash
cd examples/diagnostics
go run main.go
```

## Example Output

### Successful Session Creation

```
=== go-i2cp Diagnostics Example ===
Step 1: Enabling debug logging...
✓ Debug logging enabled - all I2CP messages will be traced

Step 2: Creating I2CP client with diagnostics enabled...
✓ Message statistics tracking enabled

Step 3: Connecting to I2P router...
DEBUG: >>> SENDING CreateSessionMessage to router
DEBUG: <<< CreateSessionMessage sent successfully, awaiting SessionCreated response
✓ Connected to I2P router

Step 4: Inspecting connection state...
Connection State:
  Connected:        true
  Router Version:   0.9.67
  Router Date:      2025-12-15 10:30:45
  Active Sessions:  0

Step 5: Creating I2CP session with diagnostic callbacks...
Step 6: Starting ProcessIO loop...
✓ ProcessIO loop running in background

Step 7: Sending CreateSession message to router...
DEBUG: Dispatching I2CP message type 20 (SessionStatus) to handler
DEBUG: <<< RECEIVED SessionStatus message from router
DEBUG: >>> Dispatching session status 0 (CREATED) to callback for session 1
DEBUG: >>> Invoking OnStatus callback for session 1 with status CREATED

Step 8: Waiting for SessionCreated response...
✓✓✓ Session created successfully! ✓✓✓
    Session ID: 1

Step 9: Printing diagnostic report...
=== I2CP Client Diagnostics ===
Connection State:
  Connected: true
  Router Version: 0.9.67
  Active Sessions: 1 (primary: 1, subsessions: 0)

=== I2CP Diagnostic Report (tracking for 2.3s) ===
✓ CreateSession sent: 1 time(s)
  Last sent: 2025-12-15T10:30:47Z (2s ago)

✓ SessionStatus received: 1 time(s)
  Last received: 2025-12-15T10:30:47Z (1s ago)

Message Flow:
  Sent:     3 messages (1245 bytes)
  Received: 2 messages (892 bytes)
```

### Session Creation Timeout (Diagnostic Mode)

```
Step 8: Waiting for SessionCreated response...
❌❌❌ Session creation TIMEOUT ❌❌❌

=== DIAGNOSTIC REPORT ===
=== I2CP Diagnostic Report (tracking for 30.1s) ===

✓ CreateSession sent: 1 time(s)
  Last sent: 2025-12-15T10:32:15Z (30s ago)

❌ ISSUE: SessionStatus response not received
   Possible causes:
   1. Router not responding (check router logs)
   2. ProcessIO not running (must be started before CreateSession)
   3. Network/connection issue
   4. Router rejected session (would show in router logs)

Message Flow:
  Sent:     2 messages (876 bytes)
  Received: 1 messages (345 bytes)

❌ WARNING: Messages sent but SessionStatus not received
```

## Diagnostic Output Interpretation

### ✓ Healthy Session Creation

- `CreateSession sent: 1 time(s)` - Request sent successfully
- `SessionStatus received: 1 time(s)` - Router responded
- `OnStatus callback invoked` - Application notified
- Message flow balanced (sent ≈ received)

### ❌ Common Issues Identified

| Diagnostic Output | Root Cause | Solution |
|-------------------|------------|----------|
| `No CreateSession message sent` | CreateSession not called | Call `client.CreateSession()` |
| `SessionStatus response not received` | ProcessIO not running | Start ProcessIO before CreateSession |
| `Messages sent but none received` | ProcessIO not running | Verify ProcessIO loop is active |
| `Session has no OnStatus callback` | Missing callback | Set `SessionCallbacks.OnStatus` |
| `Large clock skew detected` | Time sync issue | Sync system clock with NTP |

## Using Diagnostics in Your Application

### 1. Enable diagnostics during development/testing

```go
client := i2cp.NewClient(nil)
client.EnableMessageStats()  // Enable before Connect()
```

### 2. Print diagnostics when issues occur

```go
if err := client.CreateSession(ctx, session); err != nil {
    client.PrintDiagnostics()  // Shows detailed state
    log.Fatal(err)
}
```

### 3. Check message statistics programmatically

```go
stats := client.GetMessageStats()
createSent := stats.GetSentCount(i2cp.I2CP_MSG_CREATE_SESSION)
statusRecv := stats.GetReceivedCount(i2cp.I2CP_MSG_SESSION_STATUS)

if createSent > 0 && statusRecv == 0 {
    log.Println("Router not responding to CreateSession")
}
```

### 4. Inspect connection state

```go
state := client.GetConnectionState()
if !state.Connected {
    log.Printf("Not connected: %v", state.LastError)
}
```

## Debug Logging Output

When debug logging is enabled, you'll see detailed trace of I2CP protocol:

```
DEBUG: >>> SENDING CreateSessionMessage to router
DEBUG: <<< CreateSessionMessage sent successfully, awaiting SessionCreated response
DEBUG: ProcessIO: Waiting for message from router...
DEBUG: Dispatching I2CP message type 20 (SessionStatus) to handler
DEBUG: <<< RECEIVED SessionStatus message from router
DEBUG: >>> Dispatching session status 0 (CREATED) to callback for session 1
DEBUG: >>> Invoking OnStatus callback for session 1 with status CREATED
```

**Debug Log Prefixes:**
- `>>>` - Outgoing action (sending message, invoking callback)
- `<<<` - Incoming action (received message, processing response)
- `⏱` - Timing/waiting events
- `❌` - Errors or issues detected
- `✓` - Success confirmation

## Related Examples

- [session-creation-fix](../session-creation-fix/) - Demonstrates correct session creation patterns
- [context-usage](../context-usage/) - Shows context-aware operations with timeouts

## Troubleshooting Guide

### Issue: "ProcessIO error: context cancelled"

**Cause:** ProcessIO context cancelled while session creation in progress

**Solution:** Use separate contexts for ProcessIO and CreateSession:
```go
processIOCtx, cancel := context.WithCancel(context.Background())
defer cancel()

createCtx, createCancel := context.WithTimeout(context.Background(), 30*time.Second)
defer createCancel()
```

### Issue: "Session has no OnStatus callback registered"

**Cause:** SessionCallbacks.OnStatus not set

**Solution:** Always set OnStatus callback:
```go
session := i2cp.NewSession(client, i2cp.SessionCallbacks{
    OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
        log.Printf("Session %d status: %s", s.ID(), status)
    },
})
```

### Issue: Message statistics show 0 messages

**Cause:** EnableMessageStats() called after Connect()

**Solution:** Enable stats BEFORE connecting:
```go
client := i2cp.NewClient(nil)
client.EnableMessageStats()  // BEFORE Connect()
err := client.Connect(ctx)
```

## Performance Considerations

- **Message statistics** add minimal overhead (~0.1% CPU, negligible memory)
- **Debug logging** can be verbose - disable in production unless troubleshooting
- **Diagnostics** are thread-safe and can be enabled/disabled at runtime

## See Also

- [Main README](../../README.md) - Complete library documentation
- [CONTRIBUTING.md](../../CONTRIBUTING.md) - Development guidelines
- [Integration Tests](../../integration_test.go) - Test examples
