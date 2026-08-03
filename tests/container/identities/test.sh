#!/bin/bash
# Integration tests for `pebble identities` (list all identities).
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

run_subtest test_identities_empty
run_subtest test_identities_lists
run_subtest test_identities_format_json
run_subtest test_identities_format_yaml

finish
