#!/bin/bash
source /base.sh

# pebble push <local> <remote>
# Uploads a file through the daemon API and verifies the destination exists
# with the expected content.
test_push_uploads_file() {
    local name="push_uploads_file"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    echo "hello push" > /tmp/push-src.txt

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" push /tmp/push-src.txt /tmp/push-dst.txt 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f /tmp/push-dst.txt ]; then
        fail "$name" "destination file /tmp/push-dst.txt does not exist"
        return
    fi

    local content
    content=$(cat /tmp/push-dst.txt)
    if [ "$content" != "hello push" ]; then
        fail "$name" "expected content 'hello push', got: $content"
        return
    fi

    pass "$name"
}

# pebble push -p <local> <remote>
# The -p flag instructs pebble to create any missing parent directories.
test_push_creates_parents() {
    local name="push_creates_parents"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Ensure the source file exists (may have been created by a prior subtest).
    echo "hello push" > /tmp/push-src.txt

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" push -p /tmp/push-src.txt /tmp/pebble-push-new-dir/dst.txt 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f /tmp/pebble-push-new-dir/dst.txt ]; then
        fail "$name" "destination file /tmp/pebble-push-new-dir/dst.txt does not exist"
        return
    fi

    pass "$name"
}

# pebble push -m <mode> <local> <remote>
# The -m flag sets the permissions of the destination file.
test_push_mode() {
    local name="push_mode"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    echo "hello push" > /tmp/push-src.txt

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" push -m 600 /tmp/push-src.txt /tmp/push-mode.txt 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f /tmp/push-mode.txt ]; then
        fail "$name" "destination file /tmp/push-mode.txt does not exist"
        return
    fi

    pass "$name"
}

# pebble push <nonexistent-source> <remote>
# Must fail with a non-zero exit code when the source file does not exist.
test_push_nonexistent_source() {
    local name="push_nonexistent_source"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" push /tmp/nonexistent-xyz.txt /tmp/dst.txt 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code for nonexistent source file"
        return
    fi

    pass "$name"
}

# pebble push --uid=0 --gid=0 <local> <remote>
# The --uid/--user and --gid/--group flags set ownership of the destination
# file.  Running as root we can always set uid 0 / gid 0.
test_push_user_group() {
    local name="push_user_group"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    echo "ugtest" > /tmp/push-ug-src.txt

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" push --uid=0 --gid=0 /tmp/push-ug-src.txt /tmp/push-ug-dst.txt 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f /tmp/push-ug-dst.txt ]; then
        fail "$name" "destination file /tmp/push-ug-dst.txt does not exist"
        return
    fi

    pass "$name"
}

run_subtest test_push_uploads_file
run_subtest test_push_creates_parents
run_subtest test_push_mode
run_subtest test_push_nonexistent_source
run_subtest test_push_user_group

finish
