#!/bin/bash
# Integration tests for `pebble replan` and its flag variations.
source /base.sh

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

    if ! start_daemon "$pebble_dir" --hold; then
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

    if ! start_daemon "$pebble_dir" --hold; then
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

    if ! start_daemon "$pebble_dir" --hold; then
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

run_subtest test_replan_starts_enabled_service
run_subtest test_replan_no_wait
run_subtest test_replan_starts_new_service

finish
