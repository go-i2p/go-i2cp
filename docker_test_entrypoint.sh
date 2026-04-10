#!/bin/bash
set -euo pipefail

# docker_test_entrypoint.sh
#
# Entrypoint for the go-i2cp Docker integration test container.
# Starts a go-i2p router in the background on 127.0.0.1:7654, waits for
# I2CP readiness, then runs the full go-i2cp test suite. The container's
# exit code reflects the test outcome.

PORT_READY_TIMEOUT=120   # seconds to wait for TCP port
I2CP_READY_TIMEOUT=300   # seconds to wait for I2CP session acceptance
TUNNEL_BUILD_GRACE=30    # seconds after I2CP ready before running tests
TEST_FLAGS="${*:---v -timeout 10m -count=1}"

ROUTER_LOG="/tmp/router.log"

echo "==> Starting go-i2p router on 127.0.0.1:7654..."
go-i2p --i2cp.address=127.0.0.1:7654 >"$ROUTER_LOG" 2>&1 &
ROUTER_PID=$!

# Ensure the router is stopped when the script exits
cleanup() {
    echo "==> Stopping router (PID $ROUTER_PID)..."
    kill "$ROUTER_PID" 2>/dev/null || true
    wait "$ROUTER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# --- Phase 1: wait for TCP port ---
echo "==> Waiting for I2CP TCP port (timeout ${PORT_READY_TIMEOUT}s)..."
elapsed=0
while ! nc -z 127.0.0.1 7654 2>/dev/null; do
    if ! kill -0 "$ROUTER_PID" 2>/dev/null; then
        echo "ERROR: router process died" >&2
        exit 1
    fi
    if [ "$elapsed" -ge "$PORT_READY_TIMEOUT" ]; then
        echo "ERROR: timeout waiting for I2CP TCP port" >&2
        exit 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
echo "==> I2CP TCP port is accepting connections (${elapsed}s)"

# --- Phase 2: wait for I2CP protocol readiness ---
# We compile a small probe that attempts to create an I2CP session.
echo "==> Compiling I2CP readiness probe..."
cat > /tmp/i2cp_probe.go << 'PROBE'
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	client := go_i2cp.NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	session := go_i2cp.NewSession(client, go_i2cp.SessionCallbacks{
		OnStatus: func(s *go_i2cp.Session, status go_i2cp.SessionStatus) {},
	})

	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()

	if err := client.CreateSessionSync(sctx, session); err != nil {
		fmt.Fprintf(os.Stderr, "session: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
PROBE

cd /go-i2cp
go build -o /tmp/i2cp_probe /tmp/i2cp_probe.go

echo "==> Waiting for I2CP session acceptance (timeout ${I2CP_READY_TIMEOUT}s)..."
elapsed=0
i2cp_ready=false
while [ "$elapsed" -lt "$I2CP_READY_TIMEOUT" ]; do
    if /tmp/i2cp_probe 2>/dev/null; then
        i2cp_ready=true
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
done

if [ "$i2cp_ready" = true ]; then
    echo "==> I2CP protocol ready (${elapsed}s)"
else
    echo "WARNING: I2CP session creation did not succeed within timeout" >&2
    echo "         Tests will run anyway but some may fail" >&2
fi

# --- Phase 3: grace period for tunnel building ---
echo "==> Allowing ${TUNNEL_BUILD_GRACE}s for tunnel establishment..."
sleep "$TUNNEL_BUILD_GRACE"

# --- Phase 4: run the test suite ---
echo "==> Running go-i2cp test suite..."
echo ""
cd /go-i2cp
# shellcheck disable=SC2086
go test $TEST_FLAGS ./... 2>&1 | tee /tmp/test_output.log
TEST_EXIT=${PIPESTATUS[0]}

echo ""
echo "========================================"
if [ "$TEST_EXIT" -eq 0 ]; then
    echo "  RESULT: ALL TESTS PASSED"
else
    echo "  RESULT: TESTS FAILED (exit code $TEST_EXIT)"
fi
echo "========================================"

# Print pass/fail summary from test output
PASSED=$(grep -c '^--- PASS:' /tmp/test_output.log 2>/dev/null || echo 0)
FAILED=$(grep -c '^--- FAIL:' /tmp/test_output.log 2>/dev/null || echo 0)
SKIPPED=$(grep -c '^--- SKIP:' /tmp/test_output.log 2>/dev/null || echo 0)
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "========================================"

if [ "$TEST_EXIT" -ne 0 ]; then
    echo ""
    echo "--- Failed tests ---"
    grep '^--- FAIL:' /tmp/test_output.log 2>/dev/null || true
    echo ""
    echo "--- Router log (last 30 lines) ---"
    tail -30 "$ROUTER_LOG" 2>/dev/null || true
    echo "--- End router log ---"
fi

exit "$TEST_EXIT"
