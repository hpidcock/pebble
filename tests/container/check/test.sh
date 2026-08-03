#!/bin/bash
# Integration tests for `pebble check` (singular — show details for one check).
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Layer YAML used by most subtests
# ---------------------------------------------------------------------------

LAYER_YAML='checks:
    chk1:
        override: replace
        level: alive
        exec:
            command: /bin/true'

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble check chk1 (default text format)
# Asserts exit 0 and that the check name appears in the output.
check_shows_check() {
    local name="check_shows_check"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$LAYER_YAML"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" check chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "chk1" "$out" "$name" || return
    pass "$name"
}

# pebble check --format=json chk1
# Asserts exit 0 and that the JSON output contains the "name" key.
check_format_json() {
    local name="check_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$LAYER_YAML"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" check --format=json chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    # The JSON response must contain a "name" key and the check name itself.
    assert_contains '"name"' "$out" "$name" || return
    assert_contains "chk1" "$out" "$name" || return
    pass "$name"
}

# pebble check --format=yaml chk1
# Asserts exit 0 and that the YAML output contains the check name.
check_format_yaml() {
    local name="check_format_yaml"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$LAYER_YAML"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" check --format=yaml chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "chk1" "$out" "$name" || return
    pass "$name"
}

# pebble check doesnotexist
# The check does not exist; asserts a non-zero exit code.
check_unknown() {
    local name="check_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$LAYER_YAML"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" check doesnotexist 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for unknown check, got 0; output: $out"
        return
    fi
    pass "$name"
}

# pebble check --refresh chk1
# Runs the check immediately via the refresh path; asserts exit 0 and that the
# check name appears in the output.
check_refresh() {
    local name="check_refresh"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$LAYER_YAML"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" check --refresh chk1 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "chk1" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest check_shows_check
run_subtest check_format_json
run_subtest check_format_yaml
run_subtest check_unknown
run_subtest check_refresh

finish
