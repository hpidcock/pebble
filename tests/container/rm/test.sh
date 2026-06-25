#!/bin/bash
# Integration tests for `pebble rm` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; echo "      reason: $2"; FAIL=$((FAIL + 1)); }

# assert_exit <expected> <actual> <test-name>
assert_exit() {
    if [ "$1" != "$2" ]; then
        fail "$3" "expected exit code $1, got $2"
        return 1
    fi
    return 0
}

# assert_contains <substring> <string> <test-name>
assert_contains() {
    if ! echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
    return 0
}

# assert_not_contains <substring> <string> <test-name>
assert_not_contains() {
    if echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output NOT to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
    return 0
}

# start_daemon <pebble_dir>
# Starts the pebble daemon in the background, stores its PID in DAEMON_PID,
# and polls for the socket to appear (up to 100 × 0.1 s = 10 s).
# Returns non-zero and calls fail() if the socket does not appear in time.
DAEMON_PID=
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"
    local name="${2:-start_daemon}"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "$name" "timed out waiting for pebble socket at $socket"
            stop_daemon
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon and clears DAEMON_PID.
stop_daemon() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble rm <remote-path> removes a regular file.
test_rm_removes_file() {
    local name="rm_removes_file"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-test.txt"

    # Create the file that will be removed via pebble rm.
    echo "hello" >"$target"

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ -e "$target" ]; then
        fail "$name" "file $target still exists after pebble rm"
        return
    fi
    pass "$name"
}

# pebble rm -r <remote-path> removes a directory and its contents recursively.
test_rm_removes_directory_recursive() {
    local name="rm_removes_directory_recursive"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-dir"

    # Create a directory with a file inside.
    mkdir -p "$target"
    echo "contents" >"${target}/file.txt"

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm -r "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ -e "$target" ]; then
        fail "$name" "directory $target still exists after pebble rm -r"
        return
    fi
    pass "$name"
}

# pebble rm on a path that does not exist must exit non-zero.
test_rm_nonexistent() {
    local name="rm_nonexistent"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-nonexistent-xyz"

    # Ensure the target really does not exist.
    rm -rf "$target"

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when removing non-existent path"
        return
    fi
    pass "$name"
}

# pebble rm (without -r) on a non-empty directory must exit non-zero.
test_rm_directory_without_r() {
    local name="rm_directory_without_r"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-nonemptydir"

    # Create a non-empty directory; pebble rm without -r cannot remove it.
    mkdir -p "$target"
    echo "contents" >"${target}/file.txt"

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; rm -rf "$target"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"
    rm -rf "$target"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when removing non-empty directory without -r"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_rm_removes_file
test_rm_removes_directory_recursive
test_rm_nonexistent
test_rm_directory_without_r

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
