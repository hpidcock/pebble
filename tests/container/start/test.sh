#!/bin/bash
# Integration tests for `pebble start` and its argument variations.
source /base.sh

# start_starts_service
# Write a layer with svc1 (startup: disabled), start the daemon, run
# `pebble start svc1`, and assert the service becomes active.
test_start_starts_service() {
    local name="start_starts_service"
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

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start svc1 2>&1) || code=$?

    if ! assert_exit 0 "$code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Verify the service is now active.
    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services svc1 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "active" "$svc_out" "$name" || return
    pass "$name"
}

# start_no_wait
# Run `pebble start --no-wait svc1`; assert exit 0 and that the output
# contains a change ID (one or more digits).
test_start_no_wait() {
    local name="start_no_wait"
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

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start --no-wait svc1 2>&1) || code=$?

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

# start_unknown_service
# Attempt to start a service that does not exist in the plan; expect a
# non-zero exit code.
test_start_unknown_service() {
    local name="start_unknown_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Start the daemon with no layers (empty plan).
    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    local code=0
    PEBBLE="$pebble_dir" "$PEBBLE" start doesnotexist >/dev/null 2>&1 || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when starting unknown service, got exit 0"
        return
    fi
    pass "$name"
}

# start_already_started
# Start svc1, then call `pebble start svc1` again.  Pebble treats starting an
# already-running service as a no-op and exits 0.
test_start_already_started() {
    local name="start_already_started"
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

    # First start.
    local code1=0
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1 || code1=$?
    if ! assert_exit 0 "$code1" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Second start — idempotent, must still exit 0.
    local code2=0
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1 || code2=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code2" "$name" || return
    pass "$name"
}

run_subtest test_start_starts_service
run_subtest test_start_no_wait
run_subtest test_start_unknown_service
run_subtest test_start_already_started

finish
