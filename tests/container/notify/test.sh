#!/bin/bash
# Integration tests for `pebble notify` and related flag variations.
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
# Starts the pebble daemon in the background, saves the PID to DAEMON_PID,
# and polls for the Unix socket to appear (up to 100 × 0.1 s = 10 s).
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
            echo "      daemon log:" >&2
            cat "${pebble_dir}/daemon.log" >&2
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble notify <key>
# Expect exit 0 and output "Recorded notice <id>".
# Also verify the notice appears in `pebble notices`.
test_notify_records_notice() {
    local name="notify_records_notice"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1) || code=$?

    stop_daemon

    assert_exit 0 "$code" "$name" || { rm -rf "$pebble_dir"; return; }
    assert_contains "Recorded notice" "$out" "$name" || { rm -rf "$pebble_dir"; return; }

    # The notice ID follows "Recorded notice "; check it is non-empty.
    local notice_id
    notice_id=$(echo "$out" | grep -oP '(?<=Recorded notice )\S+')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from output: $out"
        rm -rf "$pebble_dir"
        return
    fi

    # Restart the daemon to verify the notice is persisted and listed.
    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket on second start"
        rm -rf "$pebble_dir"
        return
    fi

    local notices_out notices_code=0
    notices_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=custom 2>&1) || notices_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$notices_code" "$name" || return
    assert_contains "myapp.com/test" "$notices_out" "$name" || return

    pass "$name"
}

# pebble notify <key> <name=value>
# Data is passed as a positional name=value argument.
# Expect exit 0 and output containing a notice ID.
test_notify_with_data() {
    local name="notify_with_data"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test foo=bar 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "Recorded notice" "$out" "$name" || return

    pass "$name"
}

# pebble notify --repeat-after=1h <key>
# Expect exit 0 and output containing a notice ID.
test_notify_repeat_after() {
    local name="notify_repeat_after"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify --repeat-after=1h myapp.com/test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "Recorded notice" "$out" "$name" || return

    pass "$name"
}

# pebble notify  (no key argument)
# The key is required; expect a non-zero exit code.
test_notify_no_key() {
    local name="notify_no_key"
    local out code=0
    out=$("$PEBBLE" notify 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when key argument is omitted"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_notify_records_notice
test_notify_with_data
test_notify_repeat_after
test_notify_no_key

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
