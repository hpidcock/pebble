#!/bin/bash
source /base.sh

# pebble pull downloads a file from the daemon's filesystem to a local path.
test_pull_downloads_file() {
    local name="pull_downloads_file"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/pull-remote.txt"
    local local_path="/tmp/pull-local.txt"
    local expected_content="hello from pebble pull"

    rm -f "$local_path"
    echo "$expected_content" > "$remote"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ ! -f "$local_path" ]; then
        fail "$name" "local file $local_path does not exist after pull"
        return
    fi

    local actual_content
    actual_content=$(cat "$local_path")
    assert_contains "$expected_content" "$actual_content" "$name" || return

    pass "$name"
}

# pebble pull with a nonexistent remote path must exit non-zero.
test_pull_nonexistent_remote() {
    local name="pull_nonexistent_remote"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/nonexistent-xyz.txt"
    local local_path="/tmp/pull-out.txt"

    rm -f "$local_path"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when remote path does not exist"
        return
    fi
    pass "$name"
}

# pebble pull overwrites an existing local file with the remote content.
test_pull_overwrites_existing() {
    local name="pull_overwrites_existing"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local remote="/tmp/pull-remote2.txt"
    local local_path="/tmp/pull-existing.txt"
    local new_content="new content"

    echo "$new_content" > "$remote"
    echo "old content" > "$local_path"

    if ! start_daemon "$pebble_dir"; then
        fail "$name" "timed out waiting for pebble socket at ${pebble_dir}/.pebble.socket"
        stop_daemon
        rm -rf "$pebble_dir"
        return
    fi

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" pull "$remote" "$local_path" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    local actual_content
    actual_content=$(cat "$local_path")
    assert_contains "$new_content" "$actual_content" "$name" || return
    assert_not_contains "old content" "$actual_content" "$name" || return

    pass "$name"
}

run_subtest test_pull_downloads_file
run_subtest test_pull_nonexistent_remote
run_subtest test_pull_overwrites_existing

finish
