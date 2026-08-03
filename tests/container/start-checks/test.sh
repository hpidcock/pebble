#!/bin/bash
# Integration tests for `pebble start-checks` and related behaviour.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# start_checks_starts_check
# A check configured with startup: disabled is inactive until explicitly
# started.  After `pebble start-checks chk1` the check must be active (status
# "up", not "inactive").
start_checks_starts_check() {
    local name="start_checks_starts_check"
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

    # Start the check explicitly.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start-checks chk1 2>&1) || code=$?

    assert_exit 0 "$code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # Verify the check is now active via `pebble checks`.
    local checks_out checks_code=0
    checks_out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks 2>&1) || checks_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$checks_code" "$name" || return
    assert_contains "chk1" "$checks_out" "$name" || return
    assert_not_contains "inactive" "$checks_out" "$name" || return
    pass "$name"
}

# start_checks_idempotent
# A check configured with startup: enabled is already active when the daemon
# starts.  Running `pebble start-checks chk1` again must exit 0 (no-op).
start_checks_idempotent() {
    local name="start_checks_idempotent"
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

    # The check is already active; starting it again must still exit 0.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start-checks chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # The command prints either "Checks started: ..." or "Checks already started."
    assert_contains "Checks" "$out" "$name" || return
    pass "$name"
}

# start_checks_unknown
# Passing a check name that does not exist must exit non-zero.
start_checks_unknown() {
    local name="start_checks_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start-checks doesnotexist 2>&1) || code=$?

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

run_subtest start_checks_starts_check
run_subtest start_checks_idempotent
run_subtest start_checks_unknown

finish
