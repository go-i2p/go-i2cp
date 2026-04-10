#!/bin/bash
set -euo pipefail

# run_docker_tests.sh
#
# Build and run the full go-i2cp test suite inside a Docker container
# alongside a go-i2p router. No ports are exposed to the host, so this
# avoids interference with any locally-installed I2P or i2pd router.
#
# Usage:
#   ./run_docker_tests.sh                              # run all tests
#   ./run_docker_tests.sh -run TestSessionLifecycle     # run specific test
#   ./run_docker_tests.sh -v -timeout 20m              # custom flags
#
# The container exit code is propagated as this script's exit code.

IMAGE_NAME="go-i2cp-test-router"

echo "=== go-i2cp Docker Integration Tests ==="
echo ""
echo "This will:"
echo "  1. Build a Docker image with the go-i2p router (latest git) + go-i2cp source"
echo "  2. Start the router inside the container on 127.0.0.1:7654"
echo "  3. Wait for I2CP readiness"
echo "  4. Run the full test suite inside the container"
echo "  5. Report results and exit"
echo ""
echo "No ports are exposed to the host."
echo ""

# Check prerequisites
if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is not installed or not in PATH" >&2
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not running (or you lack permissions)" >&2
    echo "       Try: sudo systemctl start docker" >&2
    echo "       Or add your user to the docker group" >&2
    exit 1
fi

# Build the image
echo "==> Building Docker image..."
docker build -t "$IMAGE_NAME" -f Dockerfile.testrouter .

# Run the tests inside the container
echo "==> Starting test container..."
docker run --rm "$IMAGE_NAME" "$@"
