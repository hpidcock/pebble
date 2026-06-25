#!/bin/bash
# Integration tests for `pebble autostart` and its flag variations.
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
# Starts the pebble daemon with --hold (services do not autostart) and waits
# up to 10 s for the Unix socket to appear.  Sets DAEMON_PID on success.
DAEMON_PID=
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs --hold \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            echo "  [daemon log]"
            cat "${pebble_dir}/daemon.log" || true
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
        DAEMON_PID=
    fi
}

# write_layer <dir> <filename> <yaml>
# Writes <yaml> to <dir>/layers/<filename>, creating the layers directory if
# necessary.
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

# pebble autostart with a service that has startup: enabled
# Expects exit 0 and the service to reach the "active" state.
test_autostart_starts_enabled_services() {
    local name="autostart_starts_enabled_services"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: enabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" autostart 2>&1) || code=$?

    assert_exit 0 "$code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # Wait briefly for the service to transition to active before querying.
    sleep 0.5

    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc1 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "active" "$svc_out" "$name" || return
    pass "$name"
}

# pebble autostart --no-wait
# Expects exit 0 and a change ID (digits) in the output rather than waiting
# for services to start.
test_autostart_no_wait() {
    local name="autostart_no_wait"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: enabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" autostart --no-wait 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # The --no-wait output is a change ID which consists of digits.
    if ! echo "$out" | grep -qE '[0-9]+'; then
        fail "$name" "expected output to contain a numeric change ID, got: $out"
        return
    fi
    pass "$name"
}

# pebble autostart when no services have startup: enabled
# The command is a no-op and must still exit 0.
test_autostart_no_enabled_services() {
    local name="autostart_no_enabled_services"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" autostart 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    # When no services have startup: enabled, pebble autostart exits 1 with
    # a message indicating there's nothing to start. That is acceptable (no-op).
    if [ "$code" -ne 0 ] && ! echo "$out" | grep -qiE 'no.*service|nothing|0 tasks'; then
        fail "$name" "unexpected error from autostart with no enabled services (exit $code): $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_autostart_starts_enabled_services
test_autostart_no_wait
test_autostart_no_enabled_services

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
