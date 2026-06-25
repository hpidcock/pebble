#!/bin/bash
# Integration tests for `pebble run` and its flag variations.
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

# wait_for_socket <socket-path> <test-name>
# Polls up to 10 s (100 × 0.1 s) for the Unix socket to appear.
# Returns non-zero and calls fail() on timeout.
wait_for_socket() {
    local socket="$1"
    local name="$2"
    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "$name" "timed out waiting for pebble socket at $socket"
            return 1
        fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# Start daemon with --create-dirs; verify that the Unix socket appears.
run_socket_appears() {
    local name="run_socket_appears"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs >/tmp/daemon.log 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$pebble_dir"
        return
    fi

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null
    rm -rf "$pebble_dir"

    pass "$name"
}

# Start daemon with --create-dirs using a path that doesn't exist yet;
# assert the directory was created.
run_create_dirs() {
    local name="run_create_dirs"
    local base
    base=$(mktemp -d)
    local pebble_dir="${base}/newdir"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs >/tmp/daemon.log 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$base"
        return
    fi

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null

    if [ ! -d "$pebble_dir" ]; then
        fail "$name" "pebble directory ${pebble_dir} was not created"
        rm -rf "$base"
        return
    fi

    rm -rf "$base"
    pass "$name"
}

# Start daemon with --hold; define a startup: enabled service that touches a
# file; wait 1 s; assert the file does NOT exist (services were held back).
run_hold() {
    local name="run_hold"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"
    local touch_file="${pebble_dir}/was-started"

    # Write the layer before starting the daemon.
    mkdir -p "${pebble_dir}/layers"
    cat >"${pebble_dir}/layers/001-layer.yaml" <<EOF
services:
    hold-svc:
        override: replace
        command: touch ${touch_file}
        startup: enabled
EOF

    PEBBLE="$pebble_dir" "$PEBBLE" run --hold >/tmp/daemon.log 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$pebble_dir"
        return
    fi

    # Give the daemon a moment; services must NOT have been autostarted.
    sleep 1

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null

    if [ -f "$touch_file" ]; then
        fail "$name" "service ran despite --hold (file ${touch_file} exists)"
        rm -rf "$pebble_dir"
        return
    fi

    rm -rf "$pebble_dir"
    pass "$name"
}

# Start daemon with --http=:14329; curl the health endpoint and assert HTTP 200.
run_http() {
    local name="run_http"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs --http=:14329 >/tmp/daemon.log 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$pebble_dir"
        return
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:14329/v1/health)
    local curl_exit=$?

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null
    rm -rf "$pebble_dir"

    if [ "$curl_exit" -ne 0 ]; then
        fail "$name" "curl failed with exit code $curl_exit"
        return
    fi

    assert_exit "200" "$http_code" "$name" || return
    pass "$name"
}

# Start daemon with --verbose and a service that echoes a distinctive string;
# wait up to 5 s for the string to appear in the daemon's combined output.
run_verbose() {
    local name="run_verbose"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"
    local log_file="${pebble_dir}/daemon.log"

    mkdir -p "${pebble_dir}/layers"
    cat >"${pebble_dir}/layers/001-layer.yaml" <<EOF
services:
    verbose-svc:
        override: replace
        command: /bin/sh -c "while true; do echo hello-verbose; sleep 1; done"
        startup: enabled
EOF

    PEBBLE="$pebble_dir" "$PEBBLE" run --verbose >"$log_file" 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$pebble_dir"
        return
    fi

    # Wait up to 5 s for the service output to show up in the log.
    local waited=0
    local found=0
    while [ "$waited" -lt 50 ]; do
        if grep -qF "hello-verbose" "$log_file" 2>/dev/null; then
            found=1
            break
        fi
        sleep 0.1
        waited=$((waited + 1))
    done

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null
    rm -rf "$pebble_dir"

    if [ "$found" -eq 0 ]; then
        fail "$name" "'hello-verbose' did not appear in daemon output within 5 s"
        return
    fi

    pass "$name"
}

# Start daemon with --args svc1 -c "echo hello-args; sleep 60" ; and a layer
# defining svc1 with command /bin/sh; assert "hello-args" appears in output.
run_args() {
    local name="run_args"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"
    local log_file="${pebble_dir}/daemon.log"

    mkdir -p "${pebble_dir}/layers"
    cat >"${pebble_dir}/layers/001-layer.yaml" <<EOF
services:
    svc1:
        override: replace
        command: /bin/sh
        startup: enabled
EOF

    PEBBLE="$pebble_dir" "$PEBBLE" run --verbose \
        --args svc1 -c "echo hello-args; sleep 60" \; \
        >"$log_file" 2>&1 &
    local daemon_pid=$!

    if ! wait_for_socket "$socket" "$name"; then
        kill "$daemon_pid" 2>/dev/null
        wait "$daemon_pid" 2>/dev/null
        rm -rf "$pebble_dir"
        return
    fi

    # Wait up to 5 s for "hello-args" to appear in the daemon log.
    local waited=0
    local found=0
    while [ "$waited" -lt 50 ]; do
        if grep -qF "hello-args" "$log_file" 2>/dev/null; then
            found=1
            break
        fi
        sleep 0.1
        waited=$((waited + 1))
    done

    kill "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null
    rm -rf "$pebble_dir"

    if [ "$found" -eq 0 ]; then
        fail "$name" "'hello-args' did not appear in daemon output within 5 s"
        return
    fi

    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_socket_appears
run_create_dirs
run_hold
run_http
run_verbose
run_args

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
