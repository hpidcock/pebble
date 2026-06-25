#!/bin/bash
# Integration tests for `pebble changes` and its format variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
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
# Starts `pebble run --create-dirs` in the background, saves its PID to
# DAEMON_PID, then polls (up to 100 × 0.1 s = 10 s) for the socket to appear.
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            echo "timed out waiting for pebble socket at $socket" >&2
            kill "$DAEMON_PID" 2>/dev/null
            return 1
        fi
    done
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# write_layer <dir> <filename> <yaml>
# Writes the given YAML content to <dir>/layers/<filename>.
write_layer() {
    local dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${dir}/layers"
    printf '%s\n' "$yaml" >"${dir}/layers/${filename}"
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# changes_lists_after_start
# Write a layer with svc1 (sleep 60), start the daemon, run `pebble start svc1`,
# then run `pebble changes` and assert the output contains a numeric change ID
# and the status "Done".
test_changes_lists_after_start() {
    local name="changes_lists_after_start"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    # Trigger a change by starting svc1.
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" changes 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # The ID column of the first data row must be all digits.
    if ! echo "$out" | grep -qE '^[0-9]+'; then
        fail "$name" "expected a numeric change ID in output, got: $out"
        return
    fi
    assert_contains "Done" "$out" "$name" || return
    pass "$name"
}

# changes_format_json
# Same setup; `pebble changes --format=json` must exit 0 and contain the
# top-level key "changes".
test_changes_format_json() {
    local name="changes_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" changes --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"changes"' "$out" "$name" || return
    pass "$name"
}

# changes_format_yaml
# Same setup; `pebble changes --format=yaml` must exit 0 and contain the
# top-level key "changes:".
test_changes_format_yaml() {
    local name="changes_format_yaml"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" changes --format=yaml 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "changes:" "$out" "$name" || return
    pass "$name"
}

# changes_empty
# Start a fresh daemon with no operations performed; `pebble changes` must
# exit 0 and indicate that no changes were found.
test_changes_empty() {
    local name="changes_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" changes 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "no changes found" "$out" "$name" || return
    pass "$name"
}

# changes_abs_time
# Same setup; `pebble changes --abs-time` must exit 0 and the output must
# contain a full RFC 3339 timestamp (a date, a "T", and a time-zone suffix).
test_changes_abs_time() {
    local name="changes_abs_time"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: sleep 60
        startup: disabled
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" changes --abs-time 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # Expect an RFC 3339 date+time, e.g. 2026-06-25T12:34:56Z or ...+00:00
    if ! echo "$out" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
        fail "$name" "expected an RFC 3339 timestamp in output, got: $out"
        return
    fi
    if ! echo "$out" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:[0-9]{2}|Z)'; then
        fail "$name" "expected timestamp to include a timezone suffix (+/- or Z), got: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_changes_lists_after_start
test_changes_format_json
test_changes_format_yaml
test_changes_empty
test_changes_abs_time

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
