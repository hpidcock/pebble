#!/bin/bash
# Integration tests for `pebble stop` and its argument variations.
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
# Starts `pebble run --create-dirs` in the background, saves its PID to
# DAEMON_PID, then polls (up to 100 × 0.1 s = 10 s) for the socket to appear.
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
            echo "timed out waiting for pebble socket at $socket" >&2
            kill "$DAEMON_PID" 2>/dev/null
            return 1
        fi
    done
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# write_layer <dir> <filename> <yaml>
# Writes the given YAML content to <dir>/layers/<filename>.
write_layer() {
    local dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${dir}/layers"
    printf '%s\n' "$yaml" >"${dir}/layers/${filename}"
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# stop_stops_service
# Write a layer with svc1 (startup: disabled), start the daemon, start svc1,
# then run `pebble stop svc1`, and assert the service becomes inactive.
test_stop_stops_service() {
    local name="stop_stops_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service first so there is something to stop.
    local start_code=0
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1 || start_code=$?
    if ! assert_exit 0 "$start_code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Now stop it.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" stop svc1 2>&1) || code=$?

    if ! assert_exit 0 "$code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Verify the service is now inactive.
    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc1 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "inactive" "$svc_out" "$name" || return
    pass "$name"
}

# stop_no_wait
# Start svc1, then run `pebble stop --no-wait svc1`; assert exit 0 and that
# the output contains a change ID (one or more digits).
test_stop_no_wait() {
    local name="stop_no_wait"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service so there is an active service to stop.
    local start_code=0
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1 || start_code=$?
    if ! assert_exit 0 "$start_code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" stop --no-wait svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    # --no-wait prints the change ID (a bare sequence of digits) to stdout.
    if ! echo "$out" | grep -qE '^[0-9]+$'; then
        fail "$name" "expected output to be a numeric change ID, got: $out"
        return
    fi
    pass "$name"
}

# stop_unknown_service
# Attempt to stop a service that does not exist in the plan; expect a
# non-zero exit code.
test_stop_unknown_service() {
    local name="stop_unknown_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Start the daemon with no layers (empty plan).
    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    local code=0
    PEBBLE="$pebble_dir" "$PEBBLE" stop doesnotexist >/dev/null 2>&1 || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when stopping unknown service, got exit 0"
        return
    fi
    pass "$name"
}

# stop_already_stopped
# Do NOT start svc1; run `pebble stop svc1` against an inactive service.
# Pebble treats stopping an already-stopped service as a no-op and exits 0.
test_stop_already_stopped() {
    local name="stop_already_stopped"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    # svc1 was never started; stopping it should be idempotent (exit 0).
    local code=0
    PEBBLE="$pebble_dir" "$PEBBLE" stop svc1 >/dev/null 2>&1 || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_stop_stops_service
test_stop_no_wait
test_stop_unknown_service
test_stop_already_stopped

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
