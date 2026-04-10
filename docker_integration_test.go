//go:build docker

package go_i2cp

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	testRouterImage     = "go-i2cp-test-router"
	testRouterContainer = "go-i2cp-test-router"
	testRouterHost      = "127.0.0.1"
	testRouterPort      = "7654"

	// Maximum time to wait for the I2CP TCP port to accept connections.
	portReadyTimeout = 2 * time.Minute

	// Maximum time to wait for the router to accept I2CP sessions,
	// indicating it has bootstrapped enough for protocol-level testing.
	i2cpReadyTimeout = 5 * time.Minute

	// Additional grace period after I2CP readiness before running tests,
	// giving the router time to build tunnels for end-to-end message tests.
	tunnelBuildGrace = 30 * time.Second
)

// TestMain manages the lifecycle of a go-i2p router Docker container for
// integration testing. It builds the router image from latest git, starts
// the container with I2CP exposed on the default port, waits for network
// integration, runs the full test suite, and tears down the container.
//
// Run with: go test -tags docker -v -timeout 15m ./...
func TestMain(m *testing.M) {
	os.Exit(runWithDockerRouter(m))
}

func runWithDockerRouter(m *testing.M) int {
	// Build the Docker image
	fmt.Println("==> Building go-i2p test router Docker image...")
	build := exec.Command("docker", "build",
		"-t", testRouterImage,
		"-f", "Dockerfile.testrouter",
		".",
	)
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build Docker image: %v\n", err)
		return 1
	}

	// Remove any stale container from a previous run
	_ = exec.Command("docker", "rm", "-f", testRouterContainer).Run()

	// Start the container
	fmt.Println("==> Starting go-i2p test router container...")
	run := exec.Command("docker", "run", "-d",
		"--name", testRouterContainer,
		"-p", fmt.Sprintf("%s:%s:%s", testRouterHost, testRouterPort, testRouterPort),
		testRouterImage,
	)
	out, err := run.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start container: %v\n%s\n", err, out)
		return 1
	}
	fmt.Printf("==> Container started: %s\n", string(out[:12]))

	// Ensure cleanup on exit
	defer func() {
		fmt.Println("==> Stopping and removing test router container...")
		_ = exec.Command("docker", "stop", "-t", "5", testRouterContainer).Run()
		_ = exec.Command("docker", "rm", "-f", testRouterContainer).Run()
	}()

	// Phase 1: Wait for the TCP port to accept connections
	fmt.Printf("==> Waiting for I2CP port %s:%s (timeout %v)...\n", testRouterHost, testRouterPort, portReadyTimeout)
	if !waitForTCPPort(testRouterHost, testRouterPort, portReadyTimeout) {
		fmt.Fprintln(os.Stderr, "Timeout waiting for I2CP TCP port to become available")
		dumpContainerLogs()
		return 1
	}
	fmt.Println("==> I2CP TCP port is accepting connections")

	// Phase 2: Wait for the router to accept I2CP protocol sessions
	fmt.Printf("==> Waiting for I2CP protocol readiness (timeout %v)...\n", i2cpReadyTimeout)
	if !waitForI2CPSession(testRouterHost+":"+testRouterPort, i2cpReadyTimeout) {
		fmt.Fprintln(os.Stderr, "WARNING: I2CP session creation did not succeed within timeout")
		fmt.Fprintln(os.Stderr, "         Tests will run anyway but some may fail")
		dumpContainerLogs()
	} else {
		fmt.Println("==> I2CP protocol is ready, router is accepting sessions")
	}

	// Phase 3: Grace period for tunnel building
	fmt.Printf("==> Allowing %v for tunnel establishment...\n", tunnelBuildGrace)
	time.Sleep(tunnelBuildGrace)

	// Run the full test suite
	fmt.Println("==> Running full test suite against Docker router...")
	return m.Run()
}

// waitForTCPPort polls the given host:port until a TCP connection succeeds or the timeout expires.
func waitForTCPPort(host, port string, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// waitForI2CPSession attempts to connect an I2CP client and create a session.
// Success indicates the router is bootstrapped enough to handle I2CP operations.
func waitForI2CPSession(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if tryI2CPConnect(addr) {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// tryI2CPConnect attempts a single I2CP connection and session creation.
func tryI2CPConnect(addr string) bool {
	client := NewClient(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		return false
	}
	defer client.Close()

	// Try creating a session to verify the router is fully operational
	session := NewSession(client, SessionCallbacks{
		OnStatus: func(s *Session, status SessionStatus) {},
	})

	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer sessionCancel()

	err = client.CreateSessionSync(sessionCtx, session)
	if err != nil {
		return false
	}

	// Session created successfully - router is ready
	_ = client.Close()
	return true
}

// dumpContainerLogs prints the last 50 lines of the container's logs for debugging.
func dumpContainerLogs() {
	fmt.Fprintln(os.Stderr, "--- Container logs (last 50 lines) ---")
	logs := exec.Command("docker", "logs", "--tail", "50", testRouterContainer)
	logs.Stdout = os.Stderr
	logs.Stderr = os.Stderr
	_ = logs.Run()
	fmt.Fprintln(os.Stderr, "--- End container logs ---")
}
