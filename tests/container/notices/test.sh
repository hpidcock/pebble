#!/bin/bash
# Integration tests for `pebble notices` and related argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble notices with no notices present — should exit 0 and print the
# "No matching notices." message to stderr.
test_notices_empty() {
    local name="notices_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No matching notices." "$out" "$name" || return
    pass "$name"
}

# pebble notices after a notify — should list the notice key.
test_notices_lists_notice() {
    local name="notices_lists_notice"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/test" "$out" "$name" || return
    pass "$name"
}

# pebble notices --type=custom should include the custom notice;
# pebble notices --type=change-update should not include it.
test_notices_type_filter() {
    local name="notices_type_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out_custom code_custom=0
    out_custom=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=custom 2>&1) || code_custom=$?

    local out_change code_change=0
    out_change=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=change-update 2>&1) || code_change=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code_custom" "$name" || return
    assert_contains "myapp.com/test" "$out_custom" "$name" || return

    assert_exit 0 "$code_change" "$name" || return
    assert_not_contains "myapp.com/test" "$out_change" "$name" || return

    pass "$name"
}

# pebble notices --key=myapp.com/key1 should show key1 but not key2.
test_notices_key_filter() {
    local name="notices_key_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/key1 >/dev/null 2>&1
    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/key2 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --key=myapp.com/key1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "myapp.com/key1" "$out" "$name" || return
    assert_not_contains "myapp.com/key2" "$out" "$name" || return
    pass "$name"
}

# pebble notices --format=json should exit 0 and output a JSON object with a
# "notices" key.
test_notices_format_json() {
    local name="notices_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"notices"' "$out" "$name" || return
    pass "$name"
}

# pebble notices --timeout=1s with no matching notices should exit 0 within a
# reasonable time and print the "No matching notices after waiting" message.
test_notices_timeout() {
    local name="notices_timeout"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "$DAEMON_ERR"
        rm -rf "$pebble_dir"
        return
    fi

    # Run the notices command in the background so we can impose an outer
    # deadline independent of the --timeout flag itself.
    local out_file
    out_file=$(mktemp)
    PEBBLE="$pebble_dir" "$PEBBLE" notices --timeout=1s >"$out_file" 2>&1 &
    local notices_pid=$!

    # Wait up to 3 s for the command to finish.
    local waited=0
    while kill -0 "$notices_pid" 2>/dev/null; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 30 ]; then
            kill "$notices_pid" 2>/dev/null
            stop_daemon
            rm -rf "$pebble_dir" "$out_file"
            fail "$name" "pebble notices --timeout=1s did not finish within 3 s"
            return
        fi
    done

    wait "$notices_pid"
    local code=$?
    local out
    out=$(cat "$out_file")

    stop_daemon
    rm -rf "$pebble_dir" "$out_file"

    assert_exit 0 "$code" "$name" || return
    assert_contains "No matching notices after waiting" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_notices_empty
run_subtest test_notices_lists_notice
run_subtest test_notices_type_filter
run_subtest test_notices_key_filter
run_subtest test_notices_format_json
run_subtest test_notices_timeout

finish
