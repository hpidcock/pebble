#!/bin/bash
# Integration tests for `pebble notices` and related argument variations.
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
# Starts the pebble daemon in the background, saves the PID to DAEMON_PID, and
# polls for the socket to appear (up to 100 × 0.1 s = 10 s).
# Returns non-zero and sets an error message in DAEMON_ERR on timeout.
DAEMON_PID=""
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"
    DAEMON_ERR=""

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            DAEMON_ERR="timed out waiting for pebble socket at $socket"
            kill "$DAEMON_PID" 2>/dev/null
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=""
    fi
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble notices with no notices present — should exit 0 and print the
# "No matching notices." message to stderr.
test_notices_empty() {
    local name="notices_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No matching notices." "$out" "$name" || return
    pass "$name"
}

# pebble notices after a notify — should list the notice key.
test_notices_lists_notice() {
    local name="notices_lists_notice"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# pebble notices --type=custom should include the custom notice;
# pebble notices --type=change-update should not include it.
test_notices_type_filter() {
    local name="notices_type_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out_custom code_custom=0
    out_custom=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=custom 2>&1) || code_custom=$?

    local out_change code_change=0
    out_change=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=change-update 2>&1) || code_change=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code_custom" "$name" || return
    assert_contains "myapp.com/test" "$out_custom" "$name" || return

    assert_exit 0 "$code_change" "$name" || return
    assert_not_contains "myapp.com/test" "$out_change" "$name" || return

    pass "$name"
}

# pebble notices --key=myapp.com/key1 should show key1 but not key2.
test_notices_key_filter() {
    local name="notices_key_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/key1 >/dev/null 2>&1
    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/key2 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --key=myapp.com/key1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/key1" "$out" "$name" || return
    assert_not_contains "myapp.com/key2" "$out" "$name" || return
    pass "$name"
}

# pebble notices --format=json should exit 0 and output a JSON object with a
# "notices" key.
test_notices_format_json() {
    local name="notices_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"notices"' "$out" "$name" || return
    pass "$name"
}

# pebble notices --timeout=1s with no matching notices should exit 0 within a
# reasonable time and print the "No matching notices after waiting" message.
test_notices_timeout() {
    local name="notices_timeout"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    # Run the notices command in the background so we can impose an outer
    # deadline independent of the --timeout flag itself.
    local out_file
    out_file=$(mktemp)
    PEBBLE="$pebble_dir" "$PEBBLE" notices --timeout=1s >"$out_file" 2>&1 &
    local notices_pid=$!

    # Wait up to 3 s for the command to finish.
    local waited=0
    while kill -0 "$notices_pid" 2>/dev/null; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 30 ]; then
            kill "$notices_pid" 2>/dev/null
            stop_daemon
            rm -rf "$pebble_dir" "$out_file"
            fail "$name" "pebble notices --timeout=1s did not finish within 3 s"
            return
        fi
    done

    wait "$notices_pid"
    local code=$?
    local out
    out=$(cat "$out_file")

    stop_daemon
    rm -rf "$pebble_dir" "$out_file"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No matching notices after waiting" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_notices_empty
test_notices_lists_notice
test_notices_type_filter
test_notices_key_filter
test_notices_format_json
test_notices_timeout

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
