#!/bin/bash
# Integration tests for `pebble add-identities` and related variations.
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
# Starts the pebble daemon in the background, stores the PID in DAEMON_PID,
# and polls for the socket to appear (up to 100 × 0.1 s = 10 s).
# Caller must pass the test name as $2 so that a timeout failure is reported
# under the right name.
DAEMON_PID=
start_daemon() {
    local pebble_dir="$1"
    local test_name="$2"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
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
# Kills and waits for the daemon started by start_daemon.
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

# add_identities_adds — daemon starts with no identities; add "bob" via YAML
# file and confirm it appears in `pebble identities` output.
add_identities_adds() {
    local name="add_identities_adds"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Re-start daemon to query identities.
    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_contains "bob" "$list_out" "$name" || return
    pass "$name"
}

# add_identities_multiple — add two identities ("bob" and "alice") in one
# invocation; confirm both appear in `pebble identities`.
add_identities_multiple() {
    local name="add_identities_multiple"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
    alice:
        access: read
        local:
            user-id: 43
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Re-start daemon to query identities.
    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_contains "bob" "$list_out" "$name" || return
    assert_contains "alice" "$list_out" "$name" || return
    pass "$name"
}

# add_identities_duplicate — add "bob", then try to add "bob" again; the
# second invocation must exit non-zero because add-identities requires that
# named identities do not already exist.
add_identities_duplicate() {
    local name="add_identities_duplicate"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" "$name" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    # First add — must succeed.
    local out1 code1=0
    out1=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code1=$?

    if ! assert_exit 0 "$code1" "$name"; then
        stop_daemon
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Second add of the same identity — must fail.
    local out2 code2=0
    out2=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code2=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code2" -eq 0 ]; then
        fail "$name" "expected non-zero exit when adding duplicate identity, got exit 0; output: $out2"
        return
    fi
    pass "$name"
}

# add_identities_no_from — run `pebble add-identities` without --from; must
# exit non-zero because --from is a required flag.
add_identities_no_from() {
    local name="add_identities_no_from"
    local out code=0
    out=$("$PEBBLE" add-identities 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when --from is omitted, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

add_identities_adds
add_identities_multiple
add_identities_duplicate
add_identities_no_from

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
