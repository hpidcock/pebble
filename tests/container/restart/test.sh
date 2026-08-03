#!/bin/bash
# Integration tests for `pebble restart` and its argument variations.
source /base.sh

# pebble restart <service>
# Starts svc1, calls `pebble restart svc1`, expects exit 0 and the service
# to still be active afterwards.
test_restart_restarts_service() {
    local name="restart_restarts_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" \
"services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service before restarting it.
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" restart svc1 2>&1) || code=$?

    if ! assert_exit 0 "$code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc1 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "active" "$svc_out" "$name" || return
    pass "$name"
}

# pebble restart --no-wait <service>
# Starts svc1, then calls `pebble restart --no-wait svc1`; expects exit 0
# and the output to contain a numeric change ID.
test_restart_no_wait() {
    local name="restart_no_wait"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" \
"services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service before restarting it.
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" restart --no-wait svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # --no-wait prints "Restart task started (change <ID>)" — verify a digit appears.
    if ! echo "$out" | grep -qE '[0-9]'; then
        fail "$name" "expected output to contain a numeric change ID, got: $out"
        return
    fi
    pass "$name"
}

# pebble restart <unknown-service>
# Expects a non-zero exit code when the service does not exist.
test_restart_unknown_service() {
    local name="restart_unknown_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" restart doesnotexist 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for unknown service, got 0"
        return
    fi
    pass "$name"
}

run_subtest test_restart_restarts_service
run_subtest test_restart_no_wait
run_subtest test_restart_unknown_service

finish
