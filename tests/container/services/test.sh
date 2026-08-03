#!/bin/bash
# Integration tests for `pebble services` and its argument variations.
source /base.sh

# No layers loaded; daemon returns an empty services list.
# The CLI prints "Plan has no services." to stderr and exits 0.
test_services_empty() {
    local name="services_empty"
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

run_subtest test_services_empty
run_subtest test_services_lists_service
run_subtest test_services_shows_started
run_subtest test_services_format_json
run_subtest test_services_format_yaml
run_subtest test_services_specific_service

finish
