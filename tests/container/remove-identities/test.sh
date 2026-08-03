#!/bin/bash
# Integration tests for `pebble remove-identities` and its argument variations.
# Each subtest is a function; the framework at the bottom runs them all and
# exits non-zero if any fail.
set -u

source /base.sh

# ---------------------------------------------------------------------------
# Subtests
# ---------------------------------------------------------------------------

# remove_identities_removes — seed bob, start daemon, remove bob, assert gone.
remove_identities_removes() {
    local name="remove_identities_removes"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    # Write the seed identities file that the daemon will load on startup.
    local seed_file="${pebble_dir}/seed-identities.yaml"
    cat >"$seed_file" <<'EOF'
identities:
    bob:
        access: admin
        local:
            user-id: 42
EOF

    start_daemon "$pebble_dir" "--identities=${seed_file}" || { rm -rf "$pebble_dir"; return; }

    # Write the removal YAML: bob must be null to signal removal.
    local remove_file="${pebble_dir}/remove.yaml"
    cat >"$remove_file" <<'EOF'
identities:
    bob: null
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" remove-identities --from="$remove_file" 2>&1) || code=$?

    stop_daemon

    if ! assert_exit 0 "$code" "$name"; then
        echo "      output: $out"
        rm -rf "$pebble_dir"
        return
    fi
    assert_contains "Removed" "$out" "$name" || { rm -rf "$pebble_dir"; return; }

    # Start daemon again (without seed) and confirm bob is gone.
    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }
    local list_out list_code=0
    list_out=$(PEBBLE="$pebble_dir" "$PEBBLE" identities 2>&1) || list_code=$?
    stop_daemon
    rm -rf "$pebble_dir"

    assert_exit 0 "$list_code" "$name" || return
    assert_not_contains "bob" "$list_out" "$name" || return

    pass "$name"
}

# remove_identities_unknown — no identities seeded; removing "nobody" must fail.
remove_identities_unknown() {
    local name="remove_identities_unknown"
    local pebble_dir
    pebble_dir=$(mktemp -d)

    start_daemon "$pebble_dir" || { rm -rf "$pebble_dir"; return; }

    local remove_file="${pebble_dir}/remove.yaml"
    cat >"$remove_file" <<'EOF'
identities:
    nobody: null
EOF

    local out code=0
    out=$(PEBBLE="$pebble_dir" "$PEBBLE" remove-identities --from="$remove_file" 2>&1) || code=$?

    stop_daemon
    rm -rf "$pebble_dir"

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when removing a non-existent identity, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# remove_identities_no_from — omitting --from must produce a non-zero exit.
remove_identities_no_from() {
    local name="remove_identities_no_from"
    local out code=0
    out=$("$PEBBLE" remove-identities 2>&1) || code=$?

    if [ "$code" -eq 0 ]; then
        fail "$name" "expected non-zero exit when --from is omitted, got exit 0; output: $out"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_subtest remove_identities_removes
run_subtest remove_identities_unknown
run_subtest remove_identities_no_from

finish
