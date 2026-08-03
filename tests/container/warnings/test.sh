#!/bin/bash
# Integration tests for `pebble warnings` and its flag variations.
source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# With no warnings issued the command must exit 0 and print "No warnings."
# to stderr; stdout is empty.
test_warnings_empty() {
    local name="warnings_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No warnings." "$out" "$name" || return
    pass "$name"
}

# --all must also exit 0 with an empty warnings list.
test_warnings_all_flag() {
    local name="warnings_all_flag"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings --all 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No warnings." "$out" "$name" || return
    pass "$name"
}

# --format=json must exit 0 and emit a JSON object with a "warnings" key.
test_warnings_format_json() {
    local name="warnings_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"warnings"' "$out" "$name" || return
    pass "$name"
}

# --format=yaml must exit 0 and emit YAML with a "warnings:" key.
test_warnings_format_yaml() {
    local name="warnings_format_yaml"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings --format=yaml 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "warnings:" "$out" "$name" || return
    pass "$name"
}

# --verbose must exit 0 regardless of whether warnings exist.  With no
# actual warnings the output is still "No warnings." on stderr.
test_warnings_verbose() {
    local name="warnings_verbose"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings --verbose 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_not_contains "error" "$out" "$name" || return
    pass "$name"
}

# --abs-time must exit 0 regardless of whether warnings exist.
test_warnings_abs_time() {
    local name="warnings_abs_time"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings --abs-time 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_not_contains "error" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_warnings_empty
run_subtest test_warnings_all_flag
run_subtest test_warnings_format_json
run_subtest test_warnings_format_yaml
run_subtest test_warnings_verbose
run_subtest test_warnings_abs_time

finish
