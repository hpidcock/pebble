#!/bin/bash
# Integration test runner for container-based Pebble command tests.
#
# Usage:
#   ./main.sh [--pebblebin <path>]
#
# Each sub-directory contains a Containerfile and a test.sh that exercises one
# Pebble command. This script:
#   1. Builds the Pebble binary (CGO_ENABLED=0) if --pebblebin is not given.
#   2. Iterates over every sub-directory that contains a Containerfile.
#   3. Builds the OCI image with podman.
#   4. Runs the container and collects the exit code.
#   5. Reports a summary and exits non-zero if any test failed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PEBBLE_BIN=""
PASS=0
FAIL=0
FAILED_TESTS=()

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pebblebin)
            PEBBLE_BIN="$2"
            shift 2
            ;;
        --pebblebin=*)
            PEBBLE_BIN="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--pebblebin <path>]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Build Pebble binary if not provided
# ---------------------------------------------------------------------------

if [[ -z "$PEBBLE_BIN" ]]; then
    PEBBLE_BIN="$(mktemp -t pebble-container-test.XXXXXX)"
    echo "Building Pebble binary (CGO_ENABLED=0)..."
    CGO_ENABLED=0 GOOS=linux go build -o "$PEBBLE_BIN" "$REPO_ROOT/cmd/pebble"
    echo "Built Pebble binary at: $PEBBLE_BIN"
    # Clean up the temporary binary on exit.
    trap 'rm -f "$PEBBLE_BIN"' EXIT
else
    echo "Using pre-built Pebble binary at: $PEBBLE_BIN"
fi

PEBBLE_BIN="$(realpath "$PEBBLE_BIN")"

# ---------------------------------------------------------------------------
# Run each test directory
# ---------------------------------------------------------------------------

run_test() {
    local test_dir="$1"
    local name
    name="$(basename "$test_dir")"
    local tag="pebble-test-${name}"

    echo ""
    echo "=== $name ==="

    # Stage the binary into the build context directory, then clean it up
    # regardless of outcome.
    local staged="${test_dir}/pebble"
    cp "$PEBBLE_BIN" "$staged"

    cleanup_image() {
        rm -f "$staged"
        podman rmi --force "$tag" >/dev/null 2>&1 || true
    }
    trap cleanup_image RETURN

    # Build the image; suppress output unless it fails.
    local build_output
    local build_code=0
    build_output=$(podman build \
            --tag "$tag" \
            --file "${test_dir}/Containerfile" \
            "$test_dir" 2>&1) || build_code=$?
    if [[ "$build_code" -ne 0 ]]; then
        echo "$build_output"
        echo "FAIL: $name (podman build failed)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
        return
    fi

    # Run the container; capture output and exit code without aborting the
    # script on non-zero exit (we handle it ourselves).
    local output
    local code=0
    output=$(podman run --rm "$tag" 2>&1) || code=$?

    echo "$output"

    if [[ "$code" -eq 0 ]]; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name (container exited with code $code)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
    fi
}

for test_dir in "$SCRIPT_DIR"/*/; do
    if [[ -f "${test_dir}/Containerfile" ]]; then
        run_test "$test_dir"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - $t"
    done
fi

echo "================================"

[[ "$FAIL" -eq 0 ]]
