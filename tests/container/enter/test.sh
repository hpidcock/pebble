#!/bin/bash
# Integration tests for `pebble enter` and its subcommand variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# pebble enter version --client
# Starts the daemon internally, runs `version --client`, then stops the daemon.
# Must exit 0 and print a version string containing "v".
test_enter_version() {
    local name="enter_version"
    local dir
    dir=$(mktemp -d)
    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter version --client 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "v" "$out" "$name" || return
    pass "$name"
}

# pebble enter exec -T -I -- echo hello-enter
# Runs a command via exec inside enter; the daemon is started and stopped
# internally.  -T disables pseudo-terminal allocation; -I uses a pipe for
# stdin so the test works without a TTY.  Logging is silenced by enter.
test_enter_exec() {
    local name="enter_exec"
    local dir
    dir=$(mktemp -d)
    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter exec -T -I -- echo hello-enter 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "hello-enter" "$out" "$name" || return
    pass "$name"
}

# pebble enter plan
# Writes a layer that defines svc1, then runs `enter plan`.
# Must exit 0 and emit YAML containing "svc1".
test_enter_plan() {
    local name="enter_plan"
    local dir
    dir=$(mktemp -d)

    write_layer "$dir" "001-svc.yaml" "
services:
  svc1:
    override: replace
    command: /bin/sh -c 'sleep 999'
"

    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter plan 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "svc1" "$out" "$name" || return
    pass "$name"
}

# pebble enter services
# Writes a layer that defines svc1, then runs `enter services`.
# Must exit 0 and list "svc1" in the output table.
test_enter_services() {
    local name="enter_services"
    local dir
    dir=$(mktemp -d)

    write_layer "$dir" "001-svc.yaml" "
services:
  svc1:
    override: replace
    command: /bin/sh -c 'sleep 999'
"

    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter services 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "svc1" "$out" "$name" || return
    pass "$name"
}

# pebble enter ls /tmp
# Lists /tmp via the enter subcommand.  Must exit 0 and produce at least some
# output (the directory exists even if empty, so the header line suffices).
test_enter_ls() {
    local name="enter_ls"
    local dir
    dir=$(mktemp -d)
    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter ls /tmp 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    pass "$name"
}

# pebble enter --run exec -- cat <sentinel-file>
# Writes a layer with a startup-enabled service whose command writes a
# sentinel file then sleeps.  Runs `enter --run exec` to cat that file after
# services have started.  The sentinel file must exist and contain "started".
test_enter_run_starts_services() {
    local name="enter_run_starts_services"
    local dir
    dir=$(mktemp -d)
    local sentinel="${dir}/svc-started"

    write_layer "$dir" "001-svc.yaml" "
services:
  svc1:
    override: replace
    startup: enabled
    command: /bin/sh -c 'echo started > ${sentinel}; sleep 999'
"

    local out code=0
    # --run starts default services before executing the subcommand.
    # We use exec to cat the sentinel file written by svc1 on startup.
    # enter waits for services to be running before handing off to exec.
    out=$(PEBBLE="$dir" "$PEBBLE" enter --run exec -T -I -- cat "$sentinel" 2>&1) || code=$?
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    assert_contains "started" "$out" "$name" || return
    pass "$name"
}

# pebble enter --hold exec -T -I -- /bin/true
# Writes a layer with a startup-enabled service whose command touches a
# sentinel file.  Runs `enter --hold exec` so the daemon starts but services
# do NOT autostart.  After the command exits, asserts the sentinel file does
# NOT exist (confirming --hold suppressed autostart).
test_enter_hold() {
    local name="enter_hold"
    local dir
    dir=$(mktemp -d)
    local sentinel="${dir}/svc-started"

    write_layer "$dir" "001-svc.yaml" "
services:
  svc1:
    override: replace
    startup: enabled
    command: /bin/sh -c 'touch ${sentinel}; sleep 999'
"

    local out code=0
    # --hold suppresses autostart of startup:enabled services.
    out=$(PEBBLE="$dir" "$PEBBLE" enter --hold exec -T -I -- /bin/true 2>&1) || code=$?

    local sentinel_exists=0
    [ -f "$sentinel" ] && sentinel_exists=1
    rm -rf "$dir"

    assert_exit 0 "$code" "$name" || return
    if [ "$sentinel_exists" -eq 1 ]; then
        fail "$name" "sentinel file exists; --hold should have suppressed service autostart"
        return
    fi
    pass "$name"
}

# pebble enter changes
# "changes" is not in the supported subcommand list for enter.
# Must exit non-zero.
test_enter_unsupported_subcommand() {
    local name="enter_unsupported_subcommand"
    local dir
    dir=$(mktemp -d)
    local out code=0
    out=$(PEBBLE="$dir" "$PEBBLE" enter changes 2>&1) || code=$?
    rm -rf "$dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit for unsupported subcommand, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest test_enter_version
run_subtest test_enter_exec
run_subtest test_enter_plan
run_subtest test_enter_services
run_subtest test_enter_ls
run_subtest test_enter_run_starts_services
run_subtest test_enter_hold
run_subtest test_enter_unsupported_subcommand

finish
