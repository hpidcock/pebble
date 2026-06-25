#!/bin/bash
# Integration tests for `pebble update-identities` and related commands.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

PEBBLE_BIN=/usr/local/bin/pebble
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

# start_daemon <pebble_dir> [extra_args...]
# Starts the pebble daemon in the background with optional extra arguments,
# saves the PID in DAEMON_PID, and polls for the unix socket (100 × 0.1 s).
start_daemon() {
    local pebble_dir="$1"
    shift
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE_BIN" run --create-dirs "$@" \
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
# Kills the daemon started by start_daemon and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# update-identities (no --replace) updates an existing identity.
# Seed bob as admin on daemon start, then update bob's access to metrics.
update_identities_updates() {
    local name="update_identities_updates"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Write the seed identities file for --identities on daemon startup.
    local seed_file="${pebble_dir}/seed.yaml"
    cat >"$seed_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    start_daemon "$pebble_dir" --identities="$seed_file"
    if [ $? -ne 0 ]; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    # Write a new file that changes bob's access from admin to metrics.
    local update_file="${pebble_dir}/update.yaml"
    cat >"$update_file" <<'EOF'
identities:
    bob:
        access: metrics
        local:
            user-id: 42
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" update-identities --from="$update_file" 2>&1) || code=$?
    if ! assert_exit 0 "$code" "$name"; then
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    # Verify the identity was actually updated by inspecting it.
    local identity_out identity_code=0
    identity_out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" identity bob 2>&1) || identity_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$identity_code" "$name" || return
    assert_contains "metrics" "$identity_out" "$name" || return
    pass "$name"
}

# update-identities --replace adds a new identity when none exist.
# Start daemon with no identities, then replace-add alice.
update_identities_replace_adds() {
    local name="update_identities_replace_adds"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir"
    if [ $? -ne 0 ]; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local alice_file="${pebble_dir}/alice.yaml"
    cat >"$alice_file" <<'EOF'
identities:
    alice:
        access: read
        local:
            user-id: 1000
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" update-identities --replace --from="$alice_file" 2>&1) || code=$?
    assert_exit 0 "$code" "$name" || return

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_contains "alice" "$list_out" "$name" || return
    pass "$name"
}

# update-identities --replace with a null identity removes it.
# Seed bob, then replace with bob: null to remove him.
update_identities_replace_removes() {
    local name="update_identities_replace_removes"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    local seed_file="${pebble_dir}/seed.yaml"
    cat >"$seed_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    start_daemon "$pebble_dir" --identities="$seed_file"
    if [ $? -ne 0 ]; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local remove_file="${pebble_dir}/remove.yaml"
    cat >"$remove_file" <<'EOF'
identities:
    bob: null
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" update-identities --replace --from="$remove_file" 2>&1) || code=$?
    assert_exit 0 "$code" "$name" || return

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    # Exit code may be non-zero when there are no identities ("No identities." message), that's fine.
    assert_not_contains "bob" "$list_out" "$name" || return
    pass "$name"
}

# update-identities without --from must fail with a non-zero exit code.
update_identities_no_from() {
    local name="update_identities_no_from"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir"
    if [ $? -ne 0 ]; then
        fail "$name" "timed out waiting for pebble socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" update-identities 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when --from is omitted, got 0"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

update_identities_updates
update_identities_replace_adds
update_identities_replace_removes
update_identities_no_from

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
