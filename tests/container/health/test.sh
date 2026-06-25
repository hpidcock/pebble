#!/bin/bash
# Integration tests for `pebble health` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE_BIN=/usr/local/bin/pebble
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; echo "      reason: $2"; FAIL=$((FAIL + 1)); }

# assert_exit <expected> <actual> <test-name>
assert_exit() {
    if [ "$1" != "$2" ]; then
        fail "$3" "expected exit code $1, got $2"
        return 1
    fi
    return 0
}

# assert_contains <substring> <string> <test-name>
assert_contains() {
    if ! echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
    return 0
}

# assert_not_contains <substring> <string> <test-name>
assert_not_contains() {
    if echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output NOT to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
    return 0
}

# start_daemon <pebble_dir>
# Starts the pebble daemon in the background, saves its PID in DAEMON_PID,
# and polls up to 10 s for the Unix socket to appear.
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE_BIN" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            echo "      daemon log:" >&2
            cat "${pebble_dir}/daemon.log" >&2
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# write_layer <pebble_dir> <filename> <yaml>
# Writes YAML content to <pebble_dir>/layers/<filename>.
write_layer() {
    local pebble_dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${pebble_dir}/layers"
    printf '%s' "$yaml" >"${pebble_dir}/layers/${filename}"
}

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" health 2>&1) || code=$?

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" health 2>&1) || code=$?

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" health --level=alive 2>&1) || code=$?

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" health 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "healthy" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_health_all_healthy
test_health_unhealthy
test_health_level_filter
test_health_no_checks

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
