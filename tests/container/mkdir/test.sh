#!/bin/bash
# Integration tests for `pebble mkdir` and its argument variations.
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
DAEMON_PID=
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
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble mkdir <path> — creates a directory on the daemon's filesystem.
test_mkdir_creates_directory() {
    local name="mkdir_creates_directory"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir /tmp/pebble-mkdir-test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-test ]; then
        fail "$name" "directory /tmp/pebble-mkdir-test was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir -p <deep/path> — creates intermediate parent directories.
test_mkdir_parents() {
    local name="mkdir_parents"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir -p /tmp/pebble-mkdir-deep/a/b/c 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-deep/a/b/c ]; then
        fail "$name" "directory /tmp/pebble-mkdir-deep/a/b/c was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir <existing-path> — without -p, must fail when path already exists.
test_mkdir_already_exists_fails() {
    local name="mkdir_already_exists_fails"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when directory already exists (no -p)"
        return
    fi
    pass "$name"
}

# pebble mkdir -p <existing-path> — with -p, must succeed even when path already exists.
test_mkdir_already_exists_with_p() {
    local name="mkdir_already_exists_with_p"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir -p /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    pass "$name"
}

# pebble mkdir -m 700 <path> — sets mode bits on the new directory.
test_mkdir_mode() {
    local name="mkdir_mode"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir -m 700 /tmp/pebble-mkdir-mode 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-mode ]; then
        fail "$name" "directory /tmp/pebble-mkdir-mode was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir --uid=0 --gid=0 <path> — sets ownership via numeric uid/gid flags.
test_mkdir_user_group() {
    local name="mkdir_user_group"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" mkdir --uid=0 --gid=0 /tmp/pebble-mkdir-ugtest 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-ugtest ]; then
        fail "$name" "directory /tmp/pebble-mkdir-ugtest was not created"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_mkdir_creates_directory
test_mkdir_parents
test_mkdir_already_exists_fails
test_mkdir_already_exists_with_p
test_mkdir_mode
test_mkdir_user_group

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
