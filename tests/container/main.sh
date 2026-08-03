#!/bin/bash
# Integration test runner for container-based Pebble command tests.
#
# Usage:
#   ./main.sh [--pebblebin <path>] [--update-audit] [<test-name>]
#
# Each sub-directory contains a Containerfile, a test.sh, and an audit.txt.
# This script:
#   1. Builds the Pebble binary (CGO_ENABLED=0) if --pebblebin is not given.
#   2. Builds the shared base image (pebble-test-base) if not already present.
#   3. Iterates over every sub-directory that contains a Containerfile.
#   4. Builds the test image FROM pebble-test-base.
#   5. Runs the container (functional tests + audit in one pass).
#   6. Reports a summary and exits non-zero if any test failed.
#
# --update-audit:
#   Runs the container with the test directory bind-mounted to /audit and
#   UPDATE_AUDIT=1 so the golden file is written back to the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PEBBLE_BIN=""
SELECTED_TEST=""
UPDATE_AUDIT=0
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
        --update-audit)
            UPDATE_AUDIT=1
            shift
            ;;
        -*)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--pebblebin <path>] [--update-audit] [<test-name>]" >&2
            exit 1
            ;;
        *)
            if [[ -n "$SELECTED_TEST" ]]; then
                echo "Only one test name may be specified" >&2
                exit 1
            fi
            SELECTED_TEST="$1"
            shift
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
    trap 'rm -f "$PEBBLE_BIN"' EXIT
else
    echo "Using pre-built Pebble binary at: $PEBBLE_BIN"
fi

PEBBLE_BIN="$(realpath "$PEBBLE_BIN")"

# ---------------------------------------------------------------------------
# Build the shared base image (includes the pebble binary)
# ---------------------------------------------------------------------------

BASE_TAG="pebble-test-base"
echo ""
echo "=== base image ==="

# Stage the pebble binary into the base build context so it gets baked in.
cp "$PEBBLE_BIN" "${SCRIPT_DIR}/base/pebble"
trap 'rm -f "${SCRIPT_DIR}/base/pebble"' EXIT

base_build_output=$(podman build \
        --tag "$BASE_TAG" \
        --file "${SCRIPT_DIR}/base/Containerfile" \
        "${SCRIPT_DIR}/base" 2>&1) || {
    echo "$base_build_output"
    echo "FAIL: base image build failed"
    exit 1
}
rm -f "${SCRIPT_DIR}/base/pebble"
echo "Base image ready: $BASE_TAG"

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

    # In update mode we don't need audit.txt in the build context (the bind-
    # mount provides it at runtime).  In normal mode it must exist to be baked
    # into the image.
    if [[ "$UPDATE_AUDIT" -eq 0 ]] && [[ ! -f "${test_dir}/audit.txt" ]]; then
        echo "FAIL: $name (no audit.txt — run with --update-audit to create it)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
        return
    fi

    # In update mode, ensure audit.txt exists so the Containerfile COPY
    # succeeds (the container will overwrite it via the bind-mount).
    if [[ "$UPDATE_AUDIT" -eq 1 ]] && [[ ! -f "${test_dir}/audit.txt" ]]; then
        touch "${test_dir}/audit.txt"
    fi

    cleanup() {
        podman rmi --force "$tag" >/dev/null 2>&1 || true
    }
    trap cleanup RETURN

    # Build the test image; suppress output unless it fails.
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

    # Run the container.
    local output
    local code=0
    if [[ "$UPDATE_AUDIT" -eq 1 ]]; then
        # Bind-mount the test directory to /audit so the entrypoint can write
        # the golden file back to the host filesystem.
        output=$(podman run --rm \
            -e UPDATE_AUDIT=1 \
            -v "${test_dir}:/audit:z" \
            "$tag" 2>&1) || code=$?
    else
        output=$(podman run --rm "$tag" 2>&1) || code=$?
    fi

    echo "$output"

    if [[ "$code" -eq 0 ]]; then
        if [[ "$UPDATE_AUDIT" -eq 1 ]]; then
            echo "UPDATED: $name"
        else
            echo "PASS: $name"
        fi
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name (container exited with code $code)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$name")
    fi
}

if [[ -n "$SELECTED_TEST" ]]; then
    test_dir="$SCRIPT_DIR/$SELECTED_TEST"
    if [[ ! -f "${test_dir}/Containerfile" ]]; then
        echo "No test found for '${SELECTED_TEST}' (looked for ${test_dir}/Containerfile)" >&2
        exit 1
    fi
    run_test "$test_dir"
else
    for test_dir in "$SCRIPT_DIR"/*/; do
        # Skip the base directory — it's not a test.
        [[ "$(basename "$test_dir")" == "base" ]] && continue
        if [[ -f "${test_dir}/Containerfile" ]]; then
            run_test "$test_dir"
        fi
    done
fi

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
