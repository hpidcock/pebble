#!/bin/bash
# Integration tests for `pebble signal` and its argument variations.
source /base.sh

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

run_subtest test_signal_sends_sigusr1
run_subtest test_signal_unknown_service
run_subtest test_signal_invalid_signal

finish
