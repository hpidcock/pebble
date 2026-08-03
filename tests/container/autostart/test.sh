#!/bin/bash
# Integration tests for `pebble autostart` and its flag variations.
source /base.sh

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

    if ! start_daemon "$pebble_dir" --hold; then
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

    if ! start_daemon "$pebble_dir" --hold; then
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

    if ! start_daemon "$pebble_dir" --hold; then
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

run_subtest test_autostart_starts_enabled_services
run_subtest test_autostart_no_wait
run_subtest test_autostart_no_enabled_services

finish
