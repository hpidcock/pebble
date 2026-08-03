#!/bin/bash
# Integration tests for `pebble plan` and its interactions with layers.
source /base.sh

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" plan 2>&1) || code=$?

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
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" plan 2>&1) || code=$?

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
    add_out=$(PEBBLE="$pebble_dir" "$PEBBLE" add svc2-layer "$layer_file" 2>&1) || add_code=$?
    rm -f "$layer_file"

    if [ "$add_code" -ne 0 ]; then
        fail "$TEST_NAME" "pebble add exited $add_code: $add_out"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" plan 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$TEST_NAME" || return
    assert_contains "svc2" "$out" "$TEST_NAME" || return

    pass "$TEST_NAME"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_plan_empty
run_subtest test_plan_shows_services
run_subtest test_plan_reflects_added_layer

finish
