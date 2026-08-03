#!/bin/bash
source /base.sh

# pebble rm <remote-path> removes a regular file.
test_rm_removes_file() {
    local name="rm_removes_file"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-test.txt"

    # Create the file that will be removed via pebble rm.
    echo "hello" >"$target"

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ -e "$target" ]; then
        fail "$name" "file $target still exists after pebble rm"
        return
    fi
    pass "$name"
}

# pebble rm -r <remote-path> removes a directory and its contents recursively.
test_rm_removes_directory_recursive() {
    local name="rm_removes_directory_recursive"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-dir"

    # Create a directory with a file inside.
    mkdir -p "$target"
    echo "contents" >"${target}/file.txt"

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm -r "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$code" "$name" || return

    if [ -e "$target" ]; then
        fail "$name" "directory $target still exists after pebble rm -r"
        return
    fi
    pass "$name"
}

# pebble rm on a path that does not exist must exit non-zero.
test_rm_nonexistent() {
    local name="rm_nonexistent"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-nonexistent-xyz"

    # Ensure the target really does not exist.
    rm -rf "$target"

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when removing non-existent path"
        return
    fi
    pass "$name"
}

# pebble rm (without -r) on a non-empty directory must exit non-zero.
test_rm_directory_without_r() {
    local name="rm_directory_without_r"
    local pebble_dir
    pebble_dir=$(mktemp -d)
    local target="/tmp/pebble-rm-nonemptydir"

    # Create a non-empty directory; pebble rm without -r cannot remove it.
    mkdir -p "$target"
    echo "contents" >"${target}/file.txt"

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; rm -rf "$target"; return; }

    local out
    local code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" rm "$target" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"
    rm -rf "$target"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit code when removing non-empty directory without -r"
        return
    fi
    pass "$name"
}

run_subtest test_rm_removes_file
run_subtest test_rm_removes_directory_recursive
run_subtest test_rm_nonexistent
run_subtest test_rm_directory_without_r

finish
