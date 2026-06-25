#!/bin/bash
# Integration tests for `pebble services` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
PASS=0
FAIL=0
DAEMON_PID=

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
# Starts the pebble daemon in the background, waits up to 10 s for its socket.
# Sets DAEMON_PID. Returns 1 (and calls fail) on timeout.
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs >/tmp/daemon.log 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "${CURRENT_TEST:-daemon}" "timed out waiting for pebble socket at $socket"
            kill "$DAEMON_PID" 2>/dev/null
            DAEMON_PID=
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the background daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# write_layer <pebble_dir> <filename> <yaml>
# Creates <pebble_dir>/layers/<filename> with the given YAML content.
write_layer() {
    local pebble_dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${pebble_dir}/layers"
    printf '%s\n' "$yaml" >"${pebble_dir}/layers/${filename}"
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# No layers loaded; daemon returns an empty services list.
# The CLI prints "Plan has no services." to stderr and exits 0.
test_services_empty() {
    local name="services_empty"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # stdout is empty; "Plan has no services." goes to stderr, both merged by 2>&1
    assert_contains "Plan has no services." "$out" "$name" || return
    pass "$name"
}

# A layer with one service is present; `pebble services` must list it.
test_services_lists_service() {
    local name="services_lists_service"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: sleep 60'

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "svc1" "$out" "$name" || return
    pass "$name"
}

# After `pebble start svc1` the services table must show "active" status.
test_services_shows_started() {
    local name="services_shows_started"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: sleep 60'

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    # Start the service and wait briefly for it to become active.
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1
    sleep 0.5

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "active" "$out" "$name" || return
    pass "$name"
}

# --format=json must produce output containing the "services" key.
test_services_format_json() {
    local name="services_format_json"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: sleep 60'

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"services"' "$out" "$name" || return
    pass "$name"
}

# --format=yaml must produce output containing the "services:" key.
test_services_format_yaml() {
    local name="services_format_yaml"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: sleep 60'

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services --format=yaml 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "services:" "$out" "$name" || return
    pass "$name"
}

# `pebble services svc1` with two services defined must list only svc1.
test_services_specific_service() {
    local name="services_specific_service"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: sleep 60
    svc2:
        override: replace
        command: sleep 60'

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "svc1" "$out" "$name" || return
    assert_not_contains "svc2" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_services_empty
test_services_lists_service
test_services_shows_started
test_services_format_json
test_services_format_yaml
test_services_specific_service

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
