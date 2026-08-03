#!/bin/bash
# Integration tests for `pebble help` and its argument variations.
source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble help
# Prints the short command summary and exits 0.
test_help_default() {
    local name="help_default"
    local out
    out=$("$PEBBLE" help 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "Usage" "$out" "$name" || return
    assert_contains "pebble" "$out" "$name" || return
    pass "$name"
}

# pebble help --all
# Prints the full command listing and exits 0.
# All three command names below must appear in the expanded output.
test_help_all() {
    local name="help_all"
    local out
    out=$("$PEBBLE" help --all 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "version" "$out" "$name" || return
    assert_contains "run"     "$out" "$name" || return
    assert_contains "services" "$out" "$name" || return
    pass "$name"
}

# pebble help version
# Prints help for the version subcommand and exits 0.
# The output describes the command itself and mentions the --client flag.
test_help_specific_command() {
    local name="help_specific_command"
    local out
    out=$("$PEBBLE" help version 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "version" "$out" "$name" || return
    assert_contains "client"  "$out" "$name" || return
    pass "$name"
}

# pebble help completelyfakecommand
# An unknown command name must cause a non-zero exit.
test_help_unknown_command() {
    local name="help_unknown_command"
    local out
    out=$("$PEBBLE" help completelyfakecommand 2>&1)
    local code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit for unknown command, got 0"
        return
    fi
    pass "$name"
}

# pebble --help  (global flag, not the subcommand)
# Prints the top-level usage text and exits 0.
test_help_flag() {
    local name="help_flag"
    local out
    out=$("$PEBBLE" --help 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "pebble" "$out" "$name" || return
    pass "$name"
}

# pebble version --help
# Prints help for the version subcommand via the per-command --help flag.
# Must exit 0 and mention both "version" and "client".
test_help_command_help_flag() {
    local name="help_command_help_flag"
    local out
    out=$("$PEBBLE" version --help 2>&1)
    local code=$?

    assert_exit 0 "$code" "$name" || return
    assert_contains "version" "$out" "$name" || return
    assert_contains "client"  "$out" "$name" || return
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_help_default
run_subtest test_help_all
run_subtest test_help_specific_command
run_subtest test_help_unknown_command
run_subtest test_help_flag
run_subtest test_help_command_help_flag

finish
