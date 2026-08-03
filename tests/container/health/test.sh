#!/bin/bash
# Integration tests for `pebble health` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# A single healthy exec check should cause `pebble health` to print "healthy"
# and exit 0.
test_health_all_healthy() {
    local name="health_all_healthy"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" \
'checks:
    chk1:
        override: replace
        threshold: 1
        exec:
            command: /bin/true
'

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    # Allow time for the check to run and register as healthy.
    sleep 1

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" health 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "healthy" "$out" "$name" || return
    pass "$name"
}

# A check whose command always fails should tip over after hitting the
# threshold and make `pebble health` print "unhealthy" and exit 1.
test_health_unhealthy() {
    local name="health_unhealthy"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" \
'checks:
    chk1:
        override: replace
        threshold: 1
        period: 200ms
        exec:
            command: /bin/false
'

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    # Wait long enough for the check to fail and reach threshold.
    sleep 2

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" health 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 1 "$code" "$name" || return
    assert_contains "unhealthy" "$out" "$name" || return
    pass "$name"
}

# With a mixed layer (healthy alive check, failing ready check), filtering by
# --level=alive should report healthy (exit 0) because only alive checks are
# considered.
test_health_level_filter() {
    local name="health_level_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" \
'checks:
    chk-alive:
        override: replace
        level: alive
        threshold: 1
        period: 200ms
        exec:
            command: /bin/true
    chk-ready:
        override: replace
        level: ready
        threshold: 1
        period: 200ms
        exec:
            command: /bin/false
'

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    # Wait for the ready check to fail and the alive check to succeed.
    sleep 2

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" health --level=alive 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    # Only alive-level checks are considered; they all pass → exit 0.
    assert_exit 0 "$code" "$name" || return
    assert_contains "healthy" "$out" "$name" || return
    pass "$name"
}

# When the daemon has no checks configured, `pebble health` should report
# healthy and exit 0 (vacuously true).
test_health_no_checks() {
    local name="health_no_checks"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" health 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "healthy" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_health_all_healthy
run_subtest test_health_unhealthy
run_subtest test_health_level_filter
run_subtest test_health_no_checks

finish
