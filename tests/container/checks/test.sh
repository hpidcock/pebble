#!/bin/bash
# Integration tests for `pebble checks` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble checks with no checks defined.
# Exits 0; prints "Plan has no health checks." to stderr.
test_checks_empty() {
    local name="checks_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "no health checks" "$out" "$name" || return
    pass "$name"
}

# pebble checks lists a check defined in a layer.
test_checks_lists_check() {
    local name="checks_lists_check"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$(cat <<'EOF'
checks:
    chk1:
        override: replace
        level: alive
        exec:
            command: /bin/true
EOF
)"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "chk1" "$out" "$name" || return
    pass "$name"
}

# pebble checks --format=json outputs JSON containing a "checks" key.
test_checks_format_json() {
    local name="checks_format_json"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$(cat <<'EOF'
checks:
    chk1:
        override: replace
        level: alive
        exec:
            command: /bin/true
EOF
)"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks --format=json 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains '"checks"' "$out" "$name" || return
    pass "$name"
}

# pebble checks --format=yaml outputs YAML containing a "checks:" key.
test_checks_format_yaml() {
    local name="checks_format_yaml"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$(cat <<'EOF'
checks:
    chk1:
        override: replace
        level: alive
        exec:
            command: /bin/true
EOF
)"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks --format=yaml 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "checks:" "$out" "$name" || return
    pass "$name"
}

# pebble checks --level=ready shows only ready-level checks.
test_checks_level_filter() {
    local name="checks_level_filter"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-checks.yaml" "$(cat <<'EOF'
checks:
    chk-alive:
        override: replace
        level: alive
        exec:
            command: /bin/true
    chk-ready:
        override: replace
        level: ready
        exec:
            command: /bin/true
EOF
)"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" checks --level=ready 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "chk-ready" "$out" "$name" || return
    assert_not_contains "chk-alive" "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_checks_empty
run_subtest test_checks_lists_check
run_subtest test_checks_format_json
run_subtest test_checks_format_yaml
run_subtest test_checks_level_filter

finish
