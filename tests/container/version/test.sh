#!/bin/bash
# Integration tests for `pebble version` and its argument variations.
source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble version (text, default)
# Expect two lines: "client  <ver>" and "server  -" (can't reach daemon).
test_version_default() {
    local name="version_default"
    local out
    out=$("$PEBBLE" version 2>&1)
    local code=$?

    # The command exits non-zero because it cannot contact a server, but it
    # should still print the client version line.
    assert_contains "client" "$out" "$name" || return
    assert_contains "server" "$out" "$name" || return
    pass "$name"
}

# pebble version --client
# Only prints the bare version string, no server contact, exit 0.
test_version_client_flag() {
    local name="version_client_flag"
    local out
    out=$("$PEBBLE" version --client 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    # The output must be a single non-empty line matching a version like "v1.x.y"
    local lines
    lines=$(echo "$out" | grep -c .)
    if [ "$lines" -ne 1 ]; then
        fail "$name" "expected exactly 1 line of output, got $lines: $out"
        return
    fi
    assert_contains "v" "$out" "$name" || return
    # Must NOT contain "client" or "server" label (those only appear in text table mode)
    assert_not_contains "client" "$out" "$name" || return
    assert_not_contains "server" "$out" "$name" || return
    pass "$name"
}

# pebble version --format=json --client
# Must produce valid JSON with a "client" key; must not contain "server".
test_version_json_client() {
    local name="version_json_client"
    local out
    out=$("$PEBBLE" version --format=json --client 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains '"client"' "$out" "$name" || return
    assert_not_contains '"server"' "$out" "$name" || return
    pass "$name"
}

# pebble version --format=yaml --client
# Must produce YAML with a "client" key; must not contain "server".
test_version_yaml_client() {
    local name="version_yaml_client"
    local out
    out=$("$PEBBLE" version --format=yaml --client 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "client:" "$out" "$name" || return
    assert_not_contains "server:" "$out" "$name" || return
    pass "$name"
}

# pebble --version  (global flag, not the subcommand)
# Prints just the version string to stdout and exits 0.
test_version_global_flag() {
    local name="version_global_flag"
    local out
    out=$("$PEBBLE" --version 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "v" "$out" "$name" || return
    pass "$name"
}

# pebble version with a live daemon
# Starts the daemon in the background, waits for the socket to appear, then
# runs `pebble version` and asserts both client and server versions are present
# and non-empty.
test_version_with_server() {
    local name="version_with_server"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local socket="${pebble_dir}/.pebble.socket"

    # Start the daemon in the background; redirect its output to a log file so
    # it doesn't pollute the subtest output.
    PEBBLE="$pebble_dir" "$PEBBLE" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    local daemon_pid=$!

    # Wait up to 10 s for the socket to appear.
    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "$name" "timed out waiting for pebble socket at $socket"
            kill "$daemon_pid" 2>/dev/null
            rm -rf "$pebble_dir"
            return
        fi
    done

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" version 2>&1) || code=$?

    kill "$daemon_pid" 2>/dev/null
    wait "$daemon_pid" 2>/dev/null
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "client" "$out" "$name" || return
    assert_contains "server" "$out" "$name" || return
    # The server version must not be "-" (the placeholder used when unreachable).
    if echo "$out" | grep -qF "server	-"; then
        fail "$name" "server version shows '-', daemon may not have responded: $out"
        return
    fi
    pass "$name"
}

# pebble version <extra-arg>  → must fail with "too many arguments"
test_version_extra_args_error() {
    local name="version_extra_args_error"
    local out
    out=$("$PEBBLE" version unexpected-arg 2>&1)
    local code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for extra args"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_version_default
run_subtest test_version_client_flag
run_subtest test_version_json_client
run_subtest test_version_yaml_client
run_subtest test_version_global_flag
run_subtest test_version_with_server
run_subtest test_version_extra_args_error

finish
