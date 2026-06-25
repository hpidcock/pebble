#!/bin/bash
# Integration tests for `pebble logs` and its flag variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
PASS=0
FAIL=0
DAEMON_PID=

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
# Starts the pebble daemon in the background (services with startup: enabled
# will autostart) and waits up to 10 s for its Unix socket to appear.
# Sets DAEMON_PID on success; returns 1 on timeout.
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
            echo "  [daemon log]"
            cat "${pebble_dir}/daemon.log" || true
            kill "$DAEMON_PID" 2>/dev/null
            DAEMON_PID=
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

# write_layer <dir> <filename> <yaml>
# Writes <yaml> to <dir>/layers/<filename>, creating the layers directory if
# necessary.
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

# pebble logs svc1 — basic output test.
# The service echoes a known string on startup; logs must contain it.
test_logs_shows_service_output() {
    local name="logs_shows_service_output"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "echo hello-logs; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for the service to produce output.
    sleep 2

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" logs svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "hello-logs" "$out" "$name" || return
    pass "$name"
}

# pebble logs -n 1 svc1 — only the last line should be returned.
# The service prints three lines on startup; with -n 1 only the last one
# ("line3") must appear and the first ("line1") must not.
test_logs_n_limits_lines() {
    local name="logs_n_limits_lines"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "echo line1; echo line2; echo line3; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for the service to produce output.
    sleep 2

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" logs -n 1 svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "line3" "$out" "$name" || return
    assert_not_contains "line1" "$out" "$name" || return
    pass "$name"
}

# pebble logs --format=json svc1 — JSON output must contain the "service" key.
test_logs_format_json() {
    local name="logs_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "echo hello-logs; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for the service to produce output.
    sleep 2

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" logs --format=json svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"service"' "$out" "$name" || return
    pass "$name"
}

# pebble logs -f svc1 — follow mode.
# Run with `timeout 3` so the follow is terminated after a fixed interval.
# The output must contain the service's echo, and the exit code must be 124
# (the code timeout(1) returns when it kills the command).
test_logs_follow() {
    local name="logs_follow"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "echo hello-logs; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for the service to produce output before attaching the follower.
    sleep 1

    local out code=0
    out=$(PEBBLE="$pebble_dir" timeout 3 "$PEBBLE" logs -f svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    # timeout(1) exits with 124 when it terminates the child via SIGTERM.
    assert_exit 124 "$code" "$name" || return
    assert_contains "hello-logs" "$out" "$name" || return
    pass "$name"
}

# pebble logs -n all svc1 — "-n all" must show all lines, even those beyond
# the default 30-line limit, while "-n 30" must not show early lines.
# The service prints 100 lines on startup; line1 is well outside the last 30,
# so it must appear only with "-n all".
test_logs_all() {
    local name="logs_all"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "i=1; while [ $i -le 100 ]; do echo line$i; i=$((i+1)); done; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for the service to produce output.
    sleep 2

    local out_n30 out_all code_n30=0 code_all=0
    out_n30=$(PEBBLE="$pebble_dir" "$PEBBLE" logs -n 30 svc1 2>&1) || code_n30=$?
    out_all=$(PEBBLE="$pebble_dir" "$PEBBLE" logs -n all svc1 2>&1) || code_all=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code_n30" "$name" || return
    assert_exit 0 "$code_all" "$name" || return
    # "-n all" must include line1 (early line well outside the last 30).
    if ! echo "$out_all" | grep -qE '\] line1$'; then
        fail "$name" "expected '-n all' output to contain 'line1' as a full line, got: $out_all"
        return
    fi
    # "-n 30" must NOT include line1 (only the last 30 lines are returned).
    if echo "$out_n30" | grep -qE '\] line1$'; then
        fail "$name" "expected '-n 30' output NOT to contain 'line1' as a full line, got: $out_n30"
        return
    fi
    pass "$name"
}

# pebble logs svc1 / svc2 — output must be scoped to the requested service.
# Two services each echo a unique string; querying one must not show the
# other's output.
test_logs_multiple_services() {
    local name="logs_multiple_services"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "echo hello-svc1; sleep 60"
        startup: enabled
    svc2:
        override: replace
        command: /bin/sh -c "echo hello-svc2; sleep 60"
        startup: enabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Wait for both services to produce output.
    sleep 2

    local out1 out2 code1=0 code2=0
    out1=$(PEBBLE="$pebble_dir" "$PEBBLE" logs svc1 2>&1) || code1=$?
    out2=$(PEBBLE="$pebble_dir" "$PEBBLE" logs svc2 2>&1) || code2=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code1" "$name" || return
    assert_exit 0 "$code2" "$name" || return
    assert_contains "hello-svc1" "$out1" "$name" || return
    assert_not_contains "hello-svc2" "$out1" "$name" || return
    assert_contains "hello-svc2" "$out2" "$name" || return
    assert_not_contains "hello-svc1" "$out2" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_logs_shows_service_output
test_logs_n_limits_lines
test_logs_format_json
test_logs_follow
test_logs_all
test_logs_multiple_services

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
