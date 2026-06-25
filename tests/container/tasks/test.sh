#!/bin/bash
# Integration tests for `pebble tasks` and its format variations.
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

# tasks_shows_tasks
# Write a layer with svc1, start the daemon, run `pebble start svc1`, capture
# the change ID from `pebble changes`, then run `pebble tasks <id>` and assert
# the output contains "Done".
test_tasks_shows_tasks() {
    local name="tasks_shows_tasks"
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

    # Extract the change ID: first field of the first data row (skip header).
    local change_id
    change_id=$(PEBBLE="$pebble_dir" "$PEBBLE" changes 2>&1 | awk 'NR==2{print $1}')

    if [ -z "$change_id" ]; then
        fail "$name" "could not determine change ID from 'pebble changes'"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" tasks "$change_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "Done" "$out" "$name" || return
    pass "$name"
}

# tasks_format_json
# Same setup; `pebble tasks --format=json <id>` must exit 0 and the output
# (a serialised Change object) must contain the key "tasks".
test_tasks_format_json() {
    local name="tasks_format_json"
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

    local change_id
    change_id=$(PEBBLE="$pebble_dir" "$PEBBLE" changes 2>&1 | awk 'NR==2{print $1}')

    if [ -z "$change_id" ]; then
        fail "$name" "could not determine change ID from 'pebble changes'"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" tasks --format=json "$change_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"tasks"' "$out" "$name" || return
    pass "$name"
}

# tasks_unknown_change
# Run `pebble tasks 99999` (a change ID that cannot exist in a fresh daemon);
# assert that the command exits with a non-zero status.
test_tasks_unknown_change() {
    local name="tasks_unknown_change"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "daemon did not start"
        rm -rf "$pebble_dir"
        return
    fi

    local code=0
    PEBBLE="$pebble_dir" "$PEBBLE" tasks 99999 >/dev/null 2>&1 || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit for unknown change ID, got exit 0"
        return
    fi
    pass "$name"
}

# tasks_abs_time
# Same setup; `pebble tasks --abs-time <id>` must exit 0 and the output must
# contain a full RFC 3339 timestamp (YYYY-MM-DDT pattern).
test_tasks_abs_time() {
    local name="tasks_abs_time"
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

    local change_id
    change_id=$(PEBBLE="$pebble_dir" "$PEBBLE" changes 2>&1 | awk 'NR==2{print $1}')

    if [ -z "$change_id" ]; then
        fail "$name" "could not determine change ID from 'pebble changes'"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" tasks --abs-time "$change_id" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if ! echo "$out" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
        fail "$name" "expected RFC 3339 timestamp (YYYY-MM-DDT) in output, got: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_tasks_shows_tasks
test_tasks_format_json
test_tasks_unknown_change
test_tasks_abs_time

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
