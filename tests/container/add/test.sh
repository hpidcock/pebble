#!/bin/bash
# Integration tests for `pebble add` and its flag variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE=/usr/local/bin/pebble
PASS=0
FAIL=0
DAEMON_PID=
CURRENT_TEST=

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
# Starts the pebble daemon in the background, waits up to 10 s for its socket.
# Sets DAEMON_PID. Returns 1 (and calls fail) on timeout.
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs >/tmp/daemon.log 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "${CURRENT_TEST:-daemon}" "timed out waiting for pebble socket at $socket"
            kill "$DAEMON_PID" 2>/dev/null
            DAEMON_PID=
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the background daemon started by start_daemon and waits for it to exit.
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

# Start daemon with no pre-existing layers, dynamically add a layer via
# `pebble add`, and assert that `pebble services` lists the new service.
test_add_appends_layer() {
    local name="add_appends_layer"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    # Write the layer YAML to a temp file and pass its path to `pebble add`.
    local layer_file
    layer_file=$(mktemp)
    cat >"$layer_file" <<'EOF'
services:
    svc1:
        override: replace
        command: sleep 60
EOF

    local add_out add_code=0
    add_out=$(PEBBLE="$pebble_dir" "$PEBBLE" add mylabel "$layer_file" 2>&1) || add_code=$?

    rm -f "$layer_file"

    assert_exit 0 "$add_code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }
    assert_contains "mylabel" "$add_out" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services 2>&1) || svc_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "svc1" "$svc_out" "$name" || return
    pass "$name"
}

# Add a layer with a label, then add another layer with the same label using
# --combine.  The combined layer replaces the first one rather than appending,
# so `pebble plan` must still reference "mylabel" exactly once, and
# `pebble services` must still show svc1 (with the updated command).
test_add_combine() {
    local name="add_combine"
    CURRENT_TEST="$name"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    # First layer: svc1 runs "sleep 60".
    local layer1
    layer1=$(mktemp)
    cat >"$layer1" <<'EOF'
services:
    svc1:
        override: replace
        command: sleep 60
EOF

    local add1_out add1_code=0
    add1_out=$(PEBBLE="$pebble_dir" "$PEBBLE" add mylabel "$layer1" 2>&1) || add1_code=$?
    rm -f "$layer1"

    assert_exit 0 "$add1_code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # Second layer: same label, --combine, svc1 now runs "sleep 120".
    local layer2
    layer2=$(mktemp)
    cat >"$layer2" <<'EOF'
services:
    svc1:
        override: replace
        command: sleep 120
EOF

    local add2_out add2_code=0
    add2_out=$(PEBBLE="$pebble_dir" "$PEBBLE" add --combine mylabel "$layer2" 2>&1) || add2_code=$?
    rm -f "$layer2"

    assert_exit 0 "$add2_code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # `pebble plan` output should contain the updated command (combined, not appended).
    local plan_out plan_code=0
    plan_out=$(PEBBLE="$pebble_dir" "$PEBBLE" plan 2>&1) || plan_code=$?

    assert_exit 0 "$plan_code" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # The updated command must be visible in the plan, and the old one must not.
    assert_contains "sleep 120" "$plan_out" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }
    assert_not_contains "sleep 60" "$plan_out" "$name" || { stop_daemon; rm -rf "$pebble_dir"; return; }

    # svc1 must still appear in services.
    local svc_out svc_code=0
    svc_out=$(PEBBLE="$pebble_dir" "$PEBBLE" services 2>&1) || svc_code=0

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$svc_code" "$name" || return
    assert_contains "svc1" "$svc_out" "$name" || return
    pass "$name"
}

# `pebble add` with no arguments must exit non-zero.
test_add_no_label() {
    local name="add_no_label"
    CURRENT_TEST="$name"

    local out code=0
    out=$("$PEBBLE" add 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when no label is given"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_add_appends_layer
test_add_combine
test_add_no_label

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
