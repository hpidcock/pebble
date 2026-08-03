#!/bin/bash
source /base.sh

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

run_subtest exec_runs_command
run_subtest exec_env_var
run_subtest exec_working_dir
run_subtest exec_timeout
run_subtest exec_exit_code
run_subtest exec_with_context
run_subtest exec_user_group

finish
