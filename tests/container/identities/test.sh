#!/bin/bash
# Integration tests for `pebble identities` (list all identities).
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

# start_daemon <pebble_dir> [--identities=<file>]
# Starts `pebble run` in the background, saves the PID in DAEMON_PID, and
# polls for the socket for up to 10 s (100 × 0.1 s).
DAEMON_PID=
start_daemon() {
    local pebble_dir="$1"
    shift
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs "$@" \
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
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# write_identities_file <path>
# Writes a minimal identities YAML file containing a single user "bob".
write_identities_file() {
    cat >"$1" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble identities — no identities seeded; command must exit 0.
test_identities_empty() {
    local name="identities_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    pass "$name"
}

# pebble identities — one identity seeded; output must contain "bob".
test_identities_lists() {
    local name="identities_lists"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local id_file="${pebble_dir}/identities.yaml"
    write_identities_file "$id_file"

    if ! start_daemon "$pebble_dir" "--identities=${id_file}"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "bob" "$out" "$name" || return
    pass "$name"
}

# pebble identities --format=json — output must contain the "identities" key.
test_identities_format_json() {
    local name="identities_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local id_file="${pebble_dir}/identities.yaml"
    write_identities_file "$id_file"

    if ! start_daemon "$pebble_dir" "--identities=${id_file}"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"identities"' "$out" "$name" || return
    pass "$name"
}

# pebble identities --format=yaml — output must contain the "identities:" key.
test_identities_format_yaml() {
    local name="identities_format_yaml"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local id_file="${pebble_dir}/identities.yaml"
    write_identities_file "$id_file"

    if ! start_daemon "$pebble_dir" "--identities=${id_file}"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities --format=yaml 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "identities:" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_identities_empty
test_identities_lists
test_identities_format_json
test_identities_format_yaml

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
