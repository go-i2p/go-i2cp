# Contributing to go-i2cp

Welcome to the go-i2cp project! This guide helps new contributors understand our codebase structure, coding conventions, and development workflows.

## Project Description

go-i2cp is a low-level Go implementation of the I2P Client Protocol (I2CP) for developing anonymous services and applications. The library provides cryptographically secure primitives for establishing I2P destinations and managing end-to-end encrypted communication sessions within the I2P anonymity network.

## Coding Style

Follow standard Go conventions:

- Use descriptive names with I2CP protocol references
- Use typed constants for protocol values (e.g., `I2CP_MSG_CREATE_SESSION`)
- Wrap errors with context: `fmt.Errorf("context: %w", err)`
- Document exported functions with I2CP spec references
- No suppressed errors (`_ = err` pattern)

**Example**:
```go
// I2CP 0.9.39+ CreateLeaseSet2Message
const I2CP_MSG_CREATE_LEASE_SET2 uint8 = 41

if err := c.sendMessage(msgType, stream, true); err != nil {
    return fmt.Errorf("failed to send CreateLeaseSet2Message for session %d: %w", sess.id, err)
}
```

## Project Structure

```
├── client.go              # Core I2CP client and message handlers
├── session.go             # Session management
├── constants.go           # I2CP protocol constants
├── tcp.go                 # TCP connection handling
├── stream.go              # I2CP message serialization
├── crypto.go              # Cryptographic wrappers
└── examples/              # Usage examples
```

## Testing

All contributions should include tests. We maintain **>70% test coverage**.

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run with race detector
go test -race ./...
```

Use table-driven tests for message parsing. Test both happy paths and error cases.

### Integration tests

Integration tests (`*_integration_test.go`) require a router with I2CP listening on
`127.0.0.1:7654`, so they hang out with the rest of the suite. Use the containerized
setup, which starts a go-i2p router and runs everything against it:

```bash
./run_docker_tests.sh                 # all tests
./run_docker_tests.sh -run TestSubsessionDestruction -v
```

Each test calls `waitForI2CPReadiness`, which waits once per test binary for the
router's tunnels to build (60s by default). Tune or skip that grace period:

```bash
GO_I2CP_TUNNEL_GRACE=10s go test -timeout 10m ./...   # shorter wait
go test -short ./...                                   # skip the wait entirely
```

Tunnels stay up for the life of the router, so the wait happens once, not per test.
If you start a router yourself, give it a couple of minutes before running tests, or
the first readiness gate absorbs the wait.

## Pull Request Checklist

Before submitting:

- [ ] Tests pass (`go test ./...`)
- [ ] No race conditions (`go test -race ./...`)
- [ ] I2CP spec section referenced in code comments
- [ ] Errors properly wrapped with context (no `_ = err`)
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] Godoc comments for exported functions

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/go-i2p/go-i2cp/discussions)
- **Bugs**: [Bug report template](https://github.com/go-i2p/go-i2cp/issues/new?template=bug_report.yml)
- **Features**: [Feature request template](https://github.com/go-i2p/go-i2cp/issues/new?template=feature_request.yml)
- **I2CP Spec**: https://geti2p.net/spec/i2cp

---

Thanks for contributing to go-i2cp!
