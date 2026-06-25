#!/bin/bash
# Integration tests for `pebble plan` and its interactions with layers.
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

# start_daemon <pebble_dir>
# Starts `pebble run` in the background, stores the PID in DAEMON_PID, and
# polls for the Unix socket to appear (up to 100 × 0.1 s = 10 s).
# Caller must set TEST_NAME before calling so that timeout failures are
# attributed correctly.
start_daemon() {
    local pebble_dir="$1"
    local socket="${pebble_dir}/.pebble.socket"

    PEBBLE="$pebble_dir" "$PEBBLE_BIN" run --create-dirs \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!

    local waited=0
    while [ ! -S "$socket" ]; do
        sleep 0.1
        waited=$((waited + 1))
        if [ "$waited" -ge 100 ]; then
            fail "$TEST_NAME" "timed out waiting for pebble socket at $socket"
            kill "$DAEMON_PID" 2>/dev/null
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

# write_layer <pebble_dir> <filename> <yaml>
# Writes <yaml> to <pebble_dir>/layers/<filename>, creating the directory if
# needed.
write_layer() {
    local dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${dir}/layers"
    printf '%s' "$yaml" >"${dir}/layers/${filename}"
}

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble plan with no layers
# The daemon serialises an empty Plan as "{}\n" (all top-level fields carry
# omitempty). We therefore accept either the literal string "{}" or a YAML
# document that contains "services:" — either is a valid empty-plan response.
test_plan_empty() {
    TEST_NAME="plan_empty"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" plan 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$TEST_NAME" || return

    # An empty plan is emitted as "{}" by the yaml marshaller.
    # Accept either "{}" or a document that at least contains "services:".
    if ! echo "$out" | grep -qF "{}" && ! echo "$out" | grep -qF "services:"; then
        fail "$TEST_NAME" "expected '{}' or 'services:' in output, got: $out"
        return
    fi

    pass "$TEST_NAME"
}

# pebble plan reflects a layer written to the layers directory before startup.
# We write a layer that defines svc1 (command: sleep 60) and assert that both
# the service name and its command appear in the plan output.
test_plan_shows_services() {
    TEST_NAME="plan_shows_services"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    write_layer "$pebble_dir" "001-base.yaml" \
"services:
    svc1:
        override: replace
        command: sleep 60
"

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" plan 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$TEST_NAME" || return
    assert_contains "svc1" "$out" "$TEST_NAME" || return
    assert_contains "sleep 60" "$out" "$TEST_NAME" || return

    pass "$TEST_NAME"
}

# pebble plan reflects a layer added dynamically via `pebble add`.
# Start the daemon with no layers, use `pebble add` to push a layer that
# defines svc2, then verify `pebble plan` output contains svc2.
test_plan_reflects_added_layer() {
    TEST_NAME="plan_reflects_added_layer"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    # Write the layer YAML to a temp file so `pebble add` can read it.
    local layer_file
    layer_file=$(mktemp)
    printf '%s' \
"services:
    svc2:
        override: replace
        command: sleep 60
" >"$layer_file"

    local add_out add_code=0
    add_out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" add svc2-layer "$layer_file" 2>&1) || add_code=$?
    rm -f "$layer_file"

    if [ "$add_code" -ne 0 ]; then
        fail "$TEST_NAME" "pebble add exited $add_code: $add_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE_BIN" plan 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$TEST_NAME" || return
    assert_contains "svc2" "$out" "$TEST_NAME" || return

    pass "$TEST_NAME"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

test_plan_empty
test_plan_shows_services
test_plan_reflects_added_layer

echo ""
echo "Results: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
