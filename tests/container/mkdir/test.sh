#!/bin/bash
source /base.sh

# pebble mkdir <path> — creates a directory on the daemon's filesystem.
test_mkdir_creates_directory() {
    local name="mkdir_creates_directory"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir /tmp/pebble-mkdir-test 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-test ]; then
        fail "$name" "directory /tmp/pebble-mkdir-test was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir -p <deep/path> — creates intermediate parent directories.
test_mkdir_parents() {
    local name="mkdir_parents"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir -p /tmp/pebble-mkdir-deep/a/b/c 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-deep/a/b/c ]; then
        fail "$name" "directory /tmp/pebble-mkdir-deep/a/b/c was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir <existing-path> — without -p, must fail when path already exists.
test_mkdir_already_exists_fails() {
    local name="mkdir_already_exists_fails"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when directory already exists (no -p)"
        return
    fi
    pass "$name"
}

# pebble mkdir -p <existing-path> — with -p, must succeed even when path already exists.
test_mkdir_already_exists_with_p() {
    local name="mkdir_already_exists_with_p"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir -p /tmp 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    pass "$name"
}

# pebble mkdir -m 700 <path> — sets mode bits on the new directory.
test_mkdir_mode() {
    local name="mkdir_mode"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir -m 700 /tmp/pebble-mkdir-mode 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-mode ]; then
        fail "$name" "directory /tmp/pebble-mkdir-mode was not created"
        return
    fi
    pass "$name"
}

# pebble mkdir --uid=0 --gid=0 <path> — sets ownership via numeric uid/gid flags.
test_mkdir_user_group() {
    local name="mkdir_user_group"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || {
        fail "$name" "daemon did not start in time"
        rm -rf "$pebble_dir"
        return
    }

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" mkdir --uid=0 --gid=0 /tmp/pebble-mkdir-ugtest 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return
    if [ ! -d /tmp/pebble-mkdir-ugtest ]; then
        fail "$name" "directory /tmp/pebble-mkdir-ugtest was not created"
        return
    fi
    pass "$name"
}

run_subtest test_mkdir_creates_directory
run_subtest test_mkdir_parents
run_subtest test_mkdir_already_exists_fails
run_subtest test_mkdir_already_exists_with_p
run_subtest test_mkdir_mode
run_subtest test_mkdir_user_group

finish
