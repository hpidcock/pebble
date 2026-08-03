#!/bin/bash
# Integration tests for `pebble add-identities` and related variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# add_identities_adds — daemon starts with no identities; add "bob" via YAML
# file and confirm it appears in `pebble identities` output.
add_identities_adds() {
    local name="add_identities_adds"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Re-start daemon to query identities.
    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_contains "bob" "$list_out" "$name" || return
    pass "$name"
}

# add_identities_multiple — add two identities ("bob" and "alice") in one
# invocation; confirm both appear in `pebble identities`.
add_identities_multiple() {
    local name="add_identities_multiple"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
    alice:
        access: read
        local:
            user-id: 43
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Re-start daemon to query identities.
    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_contains "bob" "$list_out" "$name" || return
    assert_contains "alice" "$list_out" "$name" || return
    pass "$name"
}

# add_identities_duplicate — add "bob", then try to add "bob" again; the
# second invocation must exit non-zero because add-identities requires that
# named identities do not already exist.
add_identities_duplicate() {
    local name="add_identities_duplicate"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local id_file="${pebble_dir}/identities.yaml"
    cat >"$id_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    # First add — must succeed.
    local out1 code1=0
    out1=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code1=$?

    if ! assert_exit 0 "$code1" "$name"; then
        stop_daemon
        echo "      daemon log:"; cat "${pebble_dir}/daemon.log"
        rm -rf "$pebble_dir"
        return
    fi

    # Second add of the same identity — must fail.
    local out2 code2=0
    out2=$(PEBBLE="$pebble_dir" "$PEBBLE" add-identities --from="$id_file" 2>&1) || code2=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code2" -eq 0 ]; then
        fail "$name" "expected non-zero exit when adding duplicate identity, got exit 0; output: $out2"
        return
    fi
    pass "$name"
}

# add_identities_no_from — run `pebble add-identities` without --from; must
# exit non-zero because --from is a required flag.
add_identities_no_from() {
    local name="add_identities_no_from"
    local out code=0
    out=$("$PEBBLE" add-identities 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when --from is omitted, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest add_identities_adds
run_subtest add_identities_multiple
run_subtest add_identities_duplicate
run_subtest add_identities_no_from

finish
