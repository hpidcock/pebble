#!/bin/bash
# Integration tests for `pebble ls` and its argument/flag variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
PASS=0
FAIL=0
DAEMON_PID=""

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
# Starts the pebble daemon in the background, saves its PID in DAEMON_PID, and
# polls for the Unix socket for up to 10 s (100 × 0.1 s).  Sets DAEMON_PID=""
# and returns 1 on timeout so the caller can bail cleanly.
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
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon whose PID was stored in DAEMON_PID and clears the variable.
stop_daemon() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=""
    fi
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble ls <path>
# Lists files/dirs under /tmp via the running daemon; expects exit 0 and
# at least some output (the directory is never empty in a running container).
test_ls_lists_directory() {
    local name="ls_lists_directory"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ -z "$out" ]; then
        fail "$name" "expected non-empty output from 'pebble ls /tmp'"
        return
    fi
    pass "$name"
}

# pebble ls -l <file>
# Long-format listing of a known file; expects exit 0, the filename in output,
# and permission bits (indicated by the presence of "-" in the mode column).
test_ls_long_format() {
    local name="ls_long_format"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    touch /tmp/testfile-ls

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls -l /tmp/testfile-ls 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "testfile-ls" "$out" "$name" || return
    # Permission bits always contain "-" (e.g. "-rw-r--r--").
    assert_contains "-" "$out" "$name" || return
    pass "$name"
}

# pebble ls -d <path>
# Lists the directory entry itself rather than its contents; expects exit 0
# and "tmp" in the output.
test_ls_directory_itself() {
    local name="ls_directory_itself"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls -d /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "tmp" "$out" "$name" || return
    pass "$name"
}

# pebble ls --format=json <path>
# JSON output must contain the top-level "files" key.
test_ls_format_json() {
    local name="ls_format_json"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls --format=json /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"files"' "$out" "$name" || return
    pass "$name"
}

# pebble ls --format=yaml <path>
# YAML output must contain the top-level "files:" key.
test_ls_format_yaml() {
    local name="ls_format_yaml"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls --format=yaml /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "files:" "$out" "$name" || return
    pass "$name"
}

# pebble ls <nonexistent-path>
# Must exit non-zero when the path does not exist.
test_ls_nonexistent() {
    local name="ls_nonexistent"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls /nonexistent-path-xyz 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for non-existent path, got 0"
        return
    fi
    pass "$name"
}

# pebble ls /tmp/pebble-glob-*
# Glob pattern on the last path element; expects exit 0, matching filenames
# in output, and the non-matching filename absent from output.
test_ls_glob() {
    local name="ls_glob"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    touch /tmp/pebble-glob-aaa.txt
    touch /tmp/pebble-glob-bbb.txt
    touch /tmp/pebble-noglob.txt

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" ls '/tmp/pebble-glob-*' 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "pebble-glob-aaa.txt" "$out" "$name" || return
    assert_contains "pebble-glob-bbb.txt" "$out" "$name" || return
    assert_not_contains "pebble-noglob.txt" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_ls_lists_directory
test_ls_long_format
test_ls_directory_itself
test_ls_format_json
test_ls_format_yaml
test_ls_nonexistent
test_ls_glob

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
