#!/bin/bash
# Integration tests for `pebble notice` (fetch a single notice).
# Covers: lookup by ID, lookup by type+key, unknown ID error, and JSON format.
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
# Starts `pebble run` in the background, stores its PID in DAEMON_PID, and
# polls the socket until it appears (up to 10 s / 100 × 0.1 s).
# Returns 1 (and leaves DAEMON_PID unset) if the socket never appears.
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
# Sends SIGTERM to DAEMON_PID and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# Fetch a notice by its numeric ID.
test_notice_by_id() {
    local name="notice_by_id"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Record a custom notice; `pebble notify` prints "Recorded notice <id>\n".
    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Extract the notice ID from the last word of the "Recorded notice <id>" line.
    local notice_id
    notice_id=$(echo "$notify_out" | awk '{print $NF}')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from: $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice "$notice_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# Fetch a notice by type + key (2-arg variant).
test_notice_by_type_and_key() {
    local name="notice_by_type_and_key"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice custom myapp.com/test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# Fetching a notice with an ID that does not exist must exit non-zero.
test_notice_unknown_id() {
    local name="notice_unknown_id"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice 9999 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit for unknown notice ID, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# Fetch a notice with --format=json; output must contain the "key" field.
test_notice_format_json() {
    local name="notice_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notice_id
    notice_id=$(echo "$notify_out" | awk '{print $NF}')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from: $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice --format=json "$notice_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"key"' "$out" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_notice_by_id
test_notice_by_type_and_key
test_notice_unknown_id
test_notice_format_json

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
