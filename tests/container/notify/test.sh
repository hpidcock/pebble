#!/bin/bash
# Integration tests for `pebble notify` and related flag variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble notify <key>
# Expect exit 0 and output "Recorded notice <id>".
# Also verify the notice appears in `pebble notices`.
test_notify_records_notice() {
    local name="notify_records_notice"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1) || code=$?

    stop_daemon

    assert_exit 0 "$code" "$name" || { rm -rf "$pebble_dir"; return; }
    assert_contains "Recorded notice" "$out" "$name" || { rm -rf "$pebble_dir"; return; }

    # The notice ID follows "Recorded notice "; check it is non-empty.
    local notice_id
    notice_id=$(echo "$out" | grep -oP '(?<=Recorded notice )\S+')
    if [ -z "$notice_id" ]; then
        fail "$name" "could not extract notice ID from output: $out"
        rm -rf "$pebble_dir"
        return
    fi

    # Restart the daemon to verify the notice is persisted and listed.
    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket on second start"
        rm -rf "$pebble_dir"
        return
    fi

    local notices_out notices_code=0
    notices_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notices --type=custom 2>&1) || notices_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$notices_code" "$name" || return
    assert_contains "myapp.com/test" "$notices_out" "$name" || return

    pass "$name"
}

# pebble notify <key> <name=value>
# Data is passed as a positional name=value argument.
# Expect exit 0 and output containing a notice ID.
test_notify_with_data() {
    local name="notify_with_data"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test foo=bar 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "Recorded notice" "$out" "$name" || return

    pass "$name"
}

# pebble notify --repeat-after=1h <key>
# Expect exit 0 and output containing a notice ID.
test_notify_repeat_after() {
    local name="notify_repeat_after"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify --repeat-after=1h myapp.com/test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "Recorded notice" "$out" "$name" || return

    pass "$name"
}

# pebble notify  (no key argument)
# The key is required; expect a non-zero exit code.
test_notify_no_key() {
    local name="notify_no_key"
    local out code=0
    out=$("$PEBBLE" notify 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when key argument is omitted"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_notify_records_notice
run_subtest test_notify_with_data
run_subtest test_notify_repeat_after
run_subtest test_notify_no_key

finish
