#!/bin/bash
# Integration tests for `pebble pull`.
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
# Starts the pebble daemon in the background, saves the PID in DAEMON_PID, and
# polls for the socket to appear (100 × 0.1 s = 10 s timeout).
DAEMON_PID=
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
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

# pebble pull downloads a file from the daemon's filesystem to a local path.
test_pull_downloads_file() {
    local name="pull_downloads_file"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/pull-remote.txt"
    local local_path="/tmp/pull-local.txt"
    local expected_content="hello from pebble pull"

    rm -f "$local_path"
    echo "$expected_content" > "$remote"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f "$local_path" ]; then
        fail "$name" "local file $local_path does not exist after pull"
        return
    fi

    local actual_content
    actual_content=$(cat "$local_path")
    assert_contains "$expected_content" "$actual_content" "$name" || return

    pass "$name"
}

# pebble pull with a nonexistent remote path must exit non-zero.
test_pull_nonexistent_remote() {
    local name="pull_nonexistent_remote"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/nonexistent-xyz.txt"
    local local_path="/tmp/pull-out.txt"

    rm -f "$local_path"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when remote path does not exist"
        return
    fi
    pass "$name"
}

# pebble pull overwrites an existing local file with the remote content.
test_pull_overwrites_existing() {
    local name="pull_overwrites_existing"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/pull-remote2.txt"
    local local_path="/tmp/pull-existing.txt"
    local new_content="new content"

    echo "$new_content" > "$remote"
    echo "old content" > "$local_path"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    local actual_content
    actual_content=$(cat "$local_path")
    assert_contains "$new_content" "$actual_content" "$name" || return
    assert_not_contains "old content" "$actual_content" "$name" || return

    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_pull_downloads_file
test_pull_nonexistent_remote
test_pull_overwrites_existing

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
