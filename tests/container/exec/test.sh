#!/bin/bash
# Integration tests for `pebble exec` and its argument variations.
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
# Starts the pebble daemon in the background, saves its PID in DAEMON_PID, and
# polls for the socket to appear (up to 100 × 0.1 s = 10 s).
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
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# write_layer <dir> <filename> <yaml>
# Writes YAML content to <dir>/layers/<filename>.
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

# pebble exec -- echo hello-exec
# Assert exit 0 and that "hello-exec" appears in the output.
exec_runs_command() {
    local name="exec_runs_command"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I -- echo hello-exec 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "hello-exec" "$out" "$name" || return
    pass "$name"
}

# pebble exec --env MYVAR=hello-env -- /bin/sh -c 'echo $MYVAR'
# Assert exit 0 and that "hello-env" appears in the output.
exec_env_var() {
    local name="exec_env_var"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I --env MYVAR=hello-env -- /bin/sh -c 'echo $MYVAR' 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "hello-env" "$out" "$name" || return
    pass "$name"
}

# pebble exec -w /tmp -- pwd
# Assert exit 0 and that "/tmp" appears in the output.
exec_working_dir() {
    local name="exec_working_dir"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I -w /tmp -- pwd 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "/tmp" "$out" "$name" || return
    pass "$name"
}

# pebble exec --timeout=1s -- sleep 10
# Assert non-zero exit (the command is killed by the timeout).
exec_timeout() {
    local name="exec_timeout"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I --timeout=1s -- sleep 10 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when command is killed by timeout, got 0"
        return
    fi
    pass "$name"
}

# pebble exec -- /bin/sh -c 'exit 42'
# Assert that the exit code is exactly 42.
exec_exit_code() {
    local name="exec_exit_code"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local code=0
    PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I -- /bin/sh -c 'exit 42' >/dev/null 2>&1 || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 42 "$code" "$name" || return
    pass "$name"
}

# pebble exec --context=svc1 -- /bin/sh -c 'echo $SVC_VAR'
# A layer defines svc1 with environment variable SVC_VAR=from-context.
# Assert exit 0 and that "from-context" appears in the output.
exec_with_context() {
    local name="exec_with_context"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" "
services:
    svc1:
        override: replace
        command: /bin/sh -c 'while true; do sleep 1; done'
        environment:
            SVC_VAR: from-context
"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Start svc1 and wait briefly for it to be running.
    PEBBLE="$pebble_dir" "$PEBBLE" start svc1 >/dev/null 2>&1
    sleep 0.5

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I --context=svc1 -- /bin/sh -c 'echo $SVC_VAR' 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "from-context" "$out" "$name" || return
    pass "$name"
}

# pebble exec --uid=0 --gid=0 -- id
# Assert exit 0 and that "uid=0" appears in the output.
exec_user_group() {
    local name="exec_user_group"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" exec -T -I --uid=0 --gid=0 -- id 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "uid=0" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

exec_runs_command
exec_env_var
exec_working_dir
exec_timeout
exec_exit_code
exec_with_context
exec_user_group

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
