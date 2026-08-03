#!/bin/bash
# Integration tests for `pebble stop-checks` and related behaviour.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# stop_checks_stops_check
# A check configured with startup: enabled is active when the daemon starts.
# After `pebble stop-checks chk1` the check must be inactive (status
# "inactive", not "up").
stop_checks_stops_check() {
    local name="stop_checks_stops_check"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "
checks:
    chk1:
        override: replace
        startup: enabled
        exec:
            command: /bin/true
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Stop the check explicitly.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" stop-checks chk1 2>&1) || code=$?

    assert_exit 0 "$code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # Verify the check is now inactive via `pebble checks`.
    local checks_out checks_code=0
    checks_out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks 2>&1) || checks_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$checks_code" "$name" || return
    assert_contains "chk1" "$checks_out" "$name" || return
    assert_contains "inactive" "$checks_out" "$name" || return
    pass "$name"
}

# stop_checks_idempotent
# A check configured with startup: disabled is already inactive when the daemon
# starts.  Running `pebble stop-checks chk1` must exit 0 (no-op).
stop_checks_idempotent() {
    local name="stop_checks_idempotent"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "
checks:
    chk1:
        override: replace
        startup: disabled
        exec:
            command: /bin/true
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # The check is already inactive; stopping it again must still exit 0.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" stop-checks chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # The command prints either "Checks stopped: ..." or "Checks already stopped."
    assert_contains "Checks" "$out" "$name" || return
    pass "$name"
}

# stop_checks_unknown
# Passing a check name that does not exist must exit non-zero.
stop_checks_unknown() {
    local name="stop_checks_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" stop-checks doesnotexist 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for unknown check name, got 0"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest stop_checks_stops_check
run_subtest stop_checks_idempotent
run_subtest stop_checks_unknown

finish
