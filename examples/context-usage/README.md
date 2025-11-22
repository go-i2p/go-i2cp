# Context Usage Example

This example demonstrates context-aware operations in the go-i2cp library.

## Features Demonstrated

- **Connection with Timeout**: Using `context.WithTimeout` to prevent hanging connections
- **Session Creation with Cancellation**: Manual cancellation using `context.WithCancel`
- **Graceful Shutdown**: Proper cleanup using the `Close()` method
- **Background Processing**: Running I/O loops with context support

## What You'll Learn

- How to use `context.Context` for timeouts and cancellation
- Proper error handling for context-related errors
- Graceful shutdown patterns with resource cleanup
- Session lifecycle management
- Background task management with context

## Running the Example

```bash
cd examples/context-usage
go run context_usage.go
```

## Building the Example

```bash
cd examples/context-usage
go build
./context-usage
```

## Example Output

The example will demonstrate four scenarios:

1. **Connection with Timeout** - Shows how to connect with a 10-second timeout
2. **Session with Cancellation** - Demonstrates manual cancellation after 5 seconds
3. **Graceful Shutdown** - Shows proper cleanup of multiple sessions
4. **Background Processing** - Demonstrates I/O processing with context

Note: Most scenarios will fail to fully execute without a running I2P router, but they demonstrate proper API usage and error handling.

## Code Highlights

### Connection with Timeout
```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

err := client.Connect(ctx)
// Context will automatically cancel after 10 seconds
```

### Graceful Shutdown
```go
// Close will:
// 1. Destroy all sessions
// 2. Wait for pending operations (max 5 seconds)
// 3. Close TCP connection
err := client.Close()
```

### Context Cancellation
```go
ctx, cancel := context.WithCancel(context.Background())
go func() {
    time.Sleep(5 * time.Second)
    cancel() // Cancel after 5 seconds
}()

err := client.CreateSession(ctx, session)
// Will fail with context cancelled error
```

## Requirements

- Go 1.18 or later
- Optional: I2P router running on `127.0.0.1:7654` for full functionality

## Related Examples

- [Modern Crypto Demo](../modern-crypto/) - Demonstrates cryptographic operations
- [Examples Overview](../) - All available examples

## Further Reading

- [Context Package Documentation](https://pkg.go.dev/context)
- [I2CP Specification](https://geti2p.net/spec/i2cp)
- [go-i2cp Main Documentation](../../README.md)
