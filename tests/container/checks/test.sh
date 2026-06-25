#!/bin/bash
# Integration tests for `pebble checks` and its argument variations.
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
# Starts pebble run in the background, saves the PID in DAEMON_PID, and polls
# for the socket for up to 10 s (100 × 0.1 s).
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
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
# Kills the daemon saved in DAEMON_PID and waits for it to exit.
stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
}

# write_layer <dir> <filename> <yaml>
# Writes <yaml> to <dir>/layers/<filename>, creating the directory as needed.
write_layer() {
    local dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${dir}/layers"
    printf '%s\n' "$yaml" >"${dir}/layers/${filename}"
}

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

test_checks_empty
test_checks_lists_check
test_checks_format_json
test_checks_format_yaml
test_checks_level_filter

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
