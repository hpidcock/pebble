#!/bin/bash
# Integration tests for `pebble identity` (show a single identity).
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

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

# pebble identity bob — must exit 0 and display the access level "admin".
test_identity_shows() {
    local name="identity_shows"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identity bob 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "admin" "$out" "$name" || return
    pass "$name"
}

# pebble identity nobody — daemon has no identities; must exit non-zero.
test_identity_unknown() {
    local name="identity_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identity nobody 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for unknown identity, got 0"
        return
    fi
    pass "$name"
}

# pebble identity --format=json bob — output must contain the "access" key.
test_identity_format_json() {
    local name="identity_format_json"
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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" identity --format=json bob 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"access"' "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_identity_shows
run_subtest test_identity_unknown
run_subtest test_identity_format_json

finish
