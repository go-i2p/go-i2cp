#!/bin/bash
set -euo pipefail

# run_docker_tests.sh - Run the full go-i2cp test suite against a go-i2p router in Docker.
#
# Usage:
#   ./run_docker_tests.sh              # run all tests
#   ./run_docker_tests.sh -run TestFoo # pass extra flags to go test
#
# This script is a convenience wrapper around:
#   go test -tags docker -v -timeout 15m ./...
#
# The build tag "docker" activates a TestMain that manages the router container.

EXTRA_FLAGS=("$@")

echo "=== go-i2cp Docker Integration Tests ==="
echo ""
echo "This will:"
echo "  1. Build a go-i2p router Docker image from latest git"
echo "  2. Start the router container with I2CP on localhost:7654"
echo "  3. Wait for the router to bootstrap and accept I2CP sessions"
echo "  4. Run the full test suite"
echo "  5. Tear down the container"
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

if ! command -v go &>/dev/null; then
    echo "ERROR: go is not installed or not in PATH" >&2
    exit 1
fi

# Run the tests with the docker build tag
exec go test -tags docker -v -count=1 -timeout 15m ./... "${EXTRA_FLAGS[@]}"
