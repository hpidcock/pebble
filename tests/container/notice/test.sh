#!/bin/bash
# Integration tests for `pebble notice` (fetch a single notice).
# Covers: lookup by ID, lookup by type+key, unknown ID error, and JSON format.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# Fetch a notice by its numeric ID.
test_notice_by_id() {
    local name="notice_by_id"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Record a custom notice; `pebble notify` prints "Recorded notice <id>\n".
    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Extract the notice ID from the last word of the "Recorded notice <id>" line.
    local notice_id
    notice_id=$(echo "$notify_out" | awk '{print $NF}')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from: $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice "$notice_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# Fetch a notice by type + key (2-arg variant).
test_notice_by_type_and_key() {
    local name="notice_by_type_and_key"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice custom myapp.com/test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# Fetching a notice with an ID that does not exist must exit non-zero.
test_notice_unknown_id() {
    local name="notice_unknown_id"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice 9999 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit for unknown notice ID, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# Fetch a notice with --format=json; output must contain the "key" field.
test_notice_format_json() {
    local name="notice_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notify_out
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1)
    local notify_code=$?
    if [ "$notify_code" -ne 0 ]; then
        fail "$name" "pebble notify failed (exit $notify_code): $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local notice_id
    notice_id=$(echo "$notify_out" | awk '{print $NF}')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from: $notify_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notice --format=json "$notice_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"key"' "$out" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_notice_by_id
run_subtest test_notice_by_type_and_key
run_subtest test_notice_unknown_id
run_subtest test_notice_format_json

finish
