#!/bin/bash
# Integration tests for `pebble remove-identities` and its argument variations.
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
# Starts the pebble daemon in the background, stores its PID in DAEMON_PID,
# and polls for the socket to appear (up to 100 × 0.1 s = 10 s).
# Returns 1 (and sets the test to fail) if the socket never appears.
# The caller must pass the test name as $3 for the timeout failure message.
start_daemon() {
    local pebble_dir="$1"
    local extra_args="${2:-}"
    local test_name="${3:-start_daemon}"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs $extra_args \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "$test_name" "timed out waiting for pebble socket at $socket"
            stop_daemon
            return 1
        fi
    done
    return 0
}

# stop_daemon
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    if [ -n "${DAEMON_PID:-}" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# remove_identities_removes — seed bob, start daemon, remove bob, assert gone.
remove_identities_removes() {
    local name="remove_identities_removes"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Write the seed identities file that the daemon will load on startup.
    local seed_file="${pebble_dir}/seed-identities.yaml"
    cat >"$seed_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    start_daemon "$pebble_dir" "--identities=${seed_file}" "$name" || { rm -rf "$pebble_dir"; return; }

    # Write the removal YAML: bob must be null to signal removal.
    local remove_file="${pebble_dir}/remove.yaml"
    cat >"$remove_file" <<'EOF'
identities:
    bob: null
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" remove-identities --from="$remove_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      output: $out"
        rm -rf "$pebble_dir"
        return
    fi
    assert_contains "Removed" "$out" "$name" || { rm -rf "$pebble_dir"; return; }

    # Start daemon again (without seed) and confirm bob is gone.
    start_daemon "$pebble_dir" "" "$name" || { rm -rf "$pebble_dir"; return; }
    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?
    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_not_contains "bob" "$list_out" "$name" || return

    pass "$name"
}

# remove_identities_unknown — no identities seeded; removing "nobody" must fail.
remove_identities_unknown() {
    local name="remove_identities_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" "" "$name" || { rm -rf "$pebble_dir"; return; }

    local remove_file="${pebble_dir}/remove.yaml"
    cat >"$remove_file" <<'EOF'
identities:
    nobody: null
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" remove-identities --from="$remove_file" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when removing a non-existent identity, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# remove_identities_no_from — omitting --from must produce a non-zero exit.
remove_identities_no_from() {
    local name="remove_identities_no_from"
    local out code=0
    out=$("$PEBBLE" remove-identities 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when --from is omitted, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

remove_identities_removes
remove_identities_unknown
remove_identities_no_from

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
