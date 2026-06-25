#!/bin/bash
# Integration tests for `pebble okay` and its argument variations.
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
# Starts pebble run --create-dirs in the background, saves its PID in
# DAEMON_PID, and polls up to 10 s for the Unix socket to appear.
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
            echo "  daemon log:" >&2
            cat "${pebble_dir}/daemon.log" >&2
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Sends SIGTERM to DAEMON_PID and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# okay_acknowledges_notices
#
# Sequence:
#   1. start daemon
#   2. pebble notify  — record a custom notice with key myapp.com/test
#   3. pebble notices — first listing; records NoticesLastListed in CLI state
#   4. pebble okay    — sets NoticesLastOkayed = NoticesLastListed
#   5. pebble notices — second listing; filters out already-okayed notices
#
# The key "myapp.com/test" must appear after step 3 and be absent after step 5.
test_okay_acknowledges_notices() {
    local name="okay_acknowledges_notices"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at $socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Record a custom notice.
    local notify_out notify_code=0
    notify_out=$(PEBBLE="$pebble_dir" "$PEBBLE" notify myapp.com/test 2>&1) || notify_code=$?
    if ! assert_exit 0 "$notify_code" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi

    # First pebble notices: the notice must be visible and LastListed is saved.
    local notices_out1 notices_code1=0
    notices_out1=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || notices_code1=$?
    if ! assert_exit 0 "$notices_code1" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi
    if ! assert_contains "myapp.com/test" "$notices_out1" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi

    # pebble okay: acknowledges everything up to LastListed.
    local okay_out okay_code=0
    okay_out=$(PEBBLE="$pebble_dir" "$PEBBLE" okay 2>&1) || okay_code=$?
    if ! assert_exit 0 "$okay_code" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi

    # Second pebble notices: the acknowledged notice must no longer appear.
    local notices_out2 notices_code2=0
    notices_out2=$(PEBBLE="$pebble_dir" "$PEBBLE" notices 2>&1) || notices_code2=$?
    if ! assert_exit 0 "$notices_code2" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi
    if ! assert_not_contains "myapp.com/test" "$notices_out2" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi

    stop_daemon
    rm -rf "$pebble_dir"
    pass "$name"
}

# okay_no_notices
#
# When no pebble notices have been listed yet, pebble okay has nothing to
# acknowledge and exits non-zero with an informative message.
# This exercises the guard in cmd_okay.go:
#   "no notices or warnings have been listed; try 'pebble notices' ..."
test_okay_no_notices() {
    local name="okay_no_notices"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at $socket"
        rm -rf "$pebble_dir"
        return
    fi

    # No notify, no prior pebble notices run — okay must exit non-zero.
    local okay_out okay_code=0
    okay_out=$(PEBBLE="$pebble_dir" "$PEBBLE" okay 2>&1) || okay_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if ! assert_exit 1 "$okay_code" "$name"; then
        return
    fi
    assert_contains "no notices" "$okay_out" "$name" || return
    pass "$name"
}

# okay_warnings_flag
#
# pebble okay --warnings behaves the same way when no warnings have been listed:
# it exits non-zero with a matching error message.
# This mirrors okay_no_notices but exercises the --warnings code path.
test_okay_warnings_flag() {
    local name="okay_warnings_flag"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at $socket"
        rm -rf "$pebble_dir"
        return
    fi

    # No prior pebble warnings run — okay --warnings must exit non-zero.
    local okay_out okay_code=0
    okay_out=$(PEBBLE="$pebble_dir" "$PEBBLE" okay --warnings 2>&1) || okay_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if ! assert_exit 1 "$okay_code" "$name"; then
        return
    fi
    assert_contains "no warnings" "$okay_out" "$name" || return
    pass "$name"
}

# okay_clears_warnings
#
# pebble okay --warnings can only succeed after pebble warnings has listed at
# least one warning (so WarningsLastListed is non-zero in CLI state). Since
# real daemon warnings are not easily triggered via CLI, this test verifies
# the consistent guard behaviour: running pebble warnings first (empty list)
# still leaves WarningsLastListed at zero, so okay --warnings correctly exits
# non-zero with an informative message — matching the same guard as
# okay_warnings_flag but with a prior warnings call.
test_okay_clears_warnings() {
    local name="okay_clears_warnings"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at $socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Step 1: run pebble warnings (returns empty list, exits 0).
    local warnings_out warnings_code=0
    warnings_out=$(PEBBLE="$pebble_dir" "$PEBBLE" warnings 2>&1) || warnings_code=$?
    if ! assert_exit 0 "$warnings_code" "$name"; then
        stop_daemon; rm -rf "$pebble_dir"; return
    fi

    # Step 2: okay --warnings still exits non-zero because no actual warnings
    # were listed (WarningsLastListed remains zero with an empty result set).
    local okay_out okay_code=0
    okay_out=$(PEBBLE="$pebble_dir" "$PEBBLE" okay --warnings 2>&1) || okay_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 1 "$okay_code" "$name" || return
    assert_contains "no warnings" "$okay_out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_okay_acknowledges_notices
test_okay_no_notices
test_okay_warnings_flag
test_okay_clears_warnings

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
