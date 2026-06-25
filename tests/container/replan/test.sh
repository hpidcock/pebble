#!/bin/bash
# Integration tests for `pebble replan` and its flag variations.
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

# start_daemon_autostart <pebble_dir>
# Starts the pebble daemon without --hold so services with startup: enabled
# are started automatically.  Sets DAEMON_PID on success.
start_daemon_autostart() {
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
            echo "  [daemon log]"
            cat "${pebble_dir}/daemon.log" || true
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon / start_daemon_autostart and waits
# for it to exit.
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

# pebble replan starts a service whose startup is enabled.
# The daemon is started with --hold so autostart has not run; replan should
# bring svc1 up.
test_replan_starts_enabled_service() {
    local name="replan_starts_enabled_service"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" replan 2>&1) || code=$?

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

# pebble replan --no-wait exits immediately with a numeric change ID.
test_replan_no_wait() {
    local name="replan_no_wait"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" replan --no-wait 2>&1) || code=$?

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

# pebble replan starts a new service that was added to the plan dynamically.
# The daemon is started with --hold (no autostart); a layer enabling svc2 is
# pushed via `pebble add`, then replan brings svc2 up.
test_replan_starts_new_service() {
    local name="replan_starts_new_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Start with svc1 disabled so replan has nothing to do initially.
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

    # Dynamically add a new enabled service via `pebble add`.
    local layer_file
    layer_file=$(mktemp)
    printf 'services:\n    svc2:\n        override: replace\n        command: sleep 60\n        startup: enabled\n' >"$layer_file"

    local add_out add_code=0
    add_out=$(PEBBLE="$pebble_dir" "$PEBBLE" add add-svc2 "$layer_file" 2>&1) || add_code=$?
    rm -f "$layer_file"

    assert_exit 0 "$add_code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # Replan should now start svc2 (startup: enabled, not yet running).
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" replan 2>&1) || code=$?

    assert_exit 0 "$code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    sleep 0.5

    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc2 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "active" "$svc_out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_replan_starts_enabled_service
test_replan_no_wait
test_replan_starts_new_service

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
