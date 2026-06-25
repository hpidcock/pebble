#!/bin/bash
# Integration tests for `pebble signal` and its argument variations.
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
# Writes YAML content to <dir>/layers/<filename>, creating the directory if
# needed.
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

# Send SIGUSR1 to a running service and confirm the service receives it.
# The service command traps SIGUSR1 and touches a sentinel file; we poll for
# that file to confirm delivery.
test_signal_sends_sigusr1() {
    local name="signal_sends_sigusr1"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Write a small script that traps SIGUSR1 and touches the sentinel.
    # Using a script file ensures the shell process is the direct child of
    # pebble (not a sub-shell of /bin/sh -c), so signal delivery is reliable.
    cat >/tmp/svc1-signal-handler.sh <<'SCRIPT'
#!/bin/sh
trap 'touch /tmp/got-sigusr1' USR1
while true; do sleep 0.1; done
SCRIPT
    chmod +x /tmp/svc1-signal-handler.sh

    write_layer "$pebble_dir" "001-svc1.yaml" \
'services:
    svc1:
        override: replace
        command: /tmp/svc1-signal-handler.sh
        startup: disabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start svc1 2>&1) || code=$?
    if [ "$code" -ne 0 ]; then
        fail "$name" "pebble start svc1 exited $code: $out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Send SIGUSR1 via `pebble signal`.
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" signal SIGUSR1 svc1 2>&1)
    code=$?

    if ! assert_exit 0 "$code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Poll for the sentinel file for up to 5 s.
    local waited=0
    while [ ! -f /tmp/got-sigusr1 ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 50 ]; then
            fail "$name" "sentinel file /tmp/got-sigusr1 did not appear within 5 s"
            stop_daemon
            rm -rf "$pebble_dir"
            return
        fi
    done

    rm -f /tmp/got-sigusr1
    stop_daemon
    rm -rf "$pebble_dir"
    pass "$name"
}

# Sending a signal to a service name that does not exist must fail.
test_signal_unknown_service() {
    local name="signal_unknown_service"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" signal SIGUSR1 doesnotexist 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for unknown service, got 0"
        return
    fi
    pass "$name"
}

# Sending an unrecognised signal name must fail.
test_signal_invalid_signal() {
    local name="signal_invalid_signal"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-svc1.yaml" \
'services:
    svc1:
        override: replace
        command: /bin/sh -c "trap '"'"'touch /tmp/got-sigusr1'"'"' USR1; sleep 60"
        startup: disabled'

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Start the service so signal has a valid target.
    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" start svc1 2>&1) || code=$?
    if [ "$code" -ne 0 ]; then
        fail "$name" "pebble start svc1 exited $code: $out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    out=$(PEBBLE="$pebble_dir" "$PEBBLE" signal NOTASIGNAL svc1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for invalid signal name, got 0"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_signal_sends_sigusr1
test_signal_unknown_service
test_signal_invalid_signal

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
