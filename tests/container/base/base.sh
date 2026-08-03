#!/bin/bash
# base.sh — shared test harness for Pebble container integration tests.
#
# Every test.sh sources this file:
#
#   source /base.sh
#
# It provides:
#   - Assertion helpers (assert_exit, assert_contains, assert_not_contains,
#     assert_not_empty)
#   - Daemon lifecycle helpers (start_daemon, start_daemon_autostart,
#     stop_daemon, wait_for_socket)
#   - Layer/identity file helpers (write_layer, write_identities)
#   - run_subtest <fn> — runs a subtest function with audit tracing and
#     compare/update logic built in
#   - finish — prints the final results summary and exits non-zero on failure
#
# Audit behaviour is controlled by the UPDATE_AUDIT environment variable:
#   UPDATE_AUDIT=0 (default) — compare each subtest's syscall summary against
#                               the golden block in /audit.txt
#   UPDATE_AUDIT=1            — write/update each subtest's golden block to
#                               /audit/audit.txt (bind-mounted from host)
set -uo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

# The real pebble binary. In normal mode $PEBBLE is the real binary.
# In audit mode run_subtest temporarily replaces it with pebble-trace so that
# only pebble invocations are straced.
PEBBLE=/usr/local/bin/pebble
PEBBLE_REAL=/usr/local/bin/pebble
PEBBLE_TRACE=/usr/local/bin/pebble-trace

PASS=0
FAIL=0
DAEMON_PID=

_AUDIT_LOG=/tmp/audit-raw.log
_AWK_SCRIPT=/usr/local/share/summarise-audit.awk
_UPDATE_AUDIT="${UPDATE_AUDIT:-0}"

if [[ "$_UPDATE_AUDIT" == "1" ]]; then
    _GOLDEN=/audit/audit.txt
else
    _GOLDEN=/audit.txt
fi

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; echo "      reason: $2"; FAIL=$((FAIL + 1)); }

# assert_exit <expected> <actual> <test-name>
assert_exit() {
    if [[ "$1" != "$2" ]]; then
        fail "$3" "expected exit code $1, got $2"
        return 1
    fi
}

# assert_contains <substring> <string> <test-name>
assert_contains() {
    if ! echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
}

# assert_not_contains <substring> <string> <test-name>
assert_not_contains() {
    if echo "$2" | grep -qF "$1"; then
        fail "$3" "expected output NOT to contain $(printf '%q' "$1"), got: $2"
        return 1
    fi
}

# assert_not_empty <string> <test-name>
assert_not_empty() {
    if [[ -z "$1" ]]; then
        fail "$2" "expected a non-empty value"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Daemon lifecycle helpers
# ---------------------------------------------------------------------------

# wait_for_socket <socket-path> <test-name>
# Polls up to 10 s for a Unix socket to appear. Returns 1 on timeout.
wait_for_socket() {
    local socket="$1"
    local name="$2"
    local waited=0
    while [[ ! -S "$socket" ]]; do
        sleep 0.1
        waited=$((waited + 1))
        if [[ "$waited" -ge 100 ]]; then
            fail "$name" "timed out waiting for pebble socket at $socket"
            return 1
        fi
    done
}

# start_daemon <pebble_dir> [extra_args...]
# Starts `pebble run --create-dirs` in the background (with any extra args),
# waits for the socket, and sets DAEMON_PID. Returns 1 on timeout.
start_daemon() {
    local pebble_dir="$1"; shift
    PEBBLE="$pebble_dir" "$PEBBLE_REAL" run --create-dirs "$@" \
        >"${pebble_dir}/daemon.log" 2>&1 &
    DAEMON_PID=$!
    wait_for_socket "${pebble_dir}/.pebble.socket" "start_daemon" || {
        kill "$DAEMON_PID" 2>/dev/null; DAEMON_PID=; return 1
    }
}

# start_daemon_autostart <pebble_dir> [extra_args...]
# Like start_daemon but without --hold, so startup:enabled services autostart.
start_daemon_autostart() {
    start_daemon "$@"
}

# stop_daemon
# Kills and waits for the daemon recorded in DAEMON_PID.
stop_daemon() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        DAEMON_PID=
    fi
}

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

# write_layer <pebble_dir> <filename> <yaml>
# Writes YAML to <pebble_dir>/layers/<filename>, creating the dir if needed.
write_layer() {
    local dir="$1"
    local filename="$2"
    local yaml="$3"
    mkdir -p "${dir}/layers"
    printf '%s\n' "$yaml" > "${dir}/layers/${filename}"
}

# write_identities <path> <yaml>
# Writes an identities YAML file to the given path.
write_identities() {
    local path="$1"
    local yaml="$2"
    printf '%s\n' "$yaml" > "$path"
}

# ---------------------------------------------------------------------------
# Audit internals
# ---------------------------------------------------------------------------

_audit_summarise() {
    local name="$1"
    gawk -v BLOCK="$name" -f "$_AWK_SCRIPT" "$_AUDIT_LOG"
}

_audit_read_golden() {
    local name="$1"
    [[ ! -f "$_GOLDEN" ]] && return
    gawk -v block="$name" '
        /^# begin / { if ($3 == block) { p=1; print; next } }
        p           { print }
        /^# end /   { if ($3 == block) { p=0 } }
    ' "$_GOLDEN"
}

_audit_write_golden() {
    local name="$1"
    local summary="$2"
    local tmp
    tmp=$(mktemp)
    if [[ -f "$_GOLDEN" ]]; then
        gawk -v block="$name" '
            /^# begin / { if ($3 == block) { skip=1 } }
            !skip        { print }
            /^# end /   { if ($3 == block) { skip=0 } }
        ' "$_GOLDEN" > "$tmp"
    fi
    printf '%s\n' "$summary" >> "$tmp"
    mv "$tmp" "$_GOLDEN"
}

_audit_sort_golden() {
    [[ ! -f "$_GOLDEN" ]] && return
    python3 - "$_GOLDEN" <<'PYEOF'
import sys, re
golden = sys.argv[1]
with open(golden) as f:
    content = f.read()
blocks = re.split(r'(?=^# begin )', content, flags=re.MULTILINE)
non_blocks = [b for b in blocks if not b.startswith('# begin')]
test_blocks = sorted(
    [b.rstrip('\n') for b in blocks if b.startswith('# begin')],
    key=lambda b: re.match(r'# begin (\S+)', b).group(1)
)
result = ''.join(non_blocks).rstrip('\n')
if result:
    result += '\n'
result += '\n'.join(test_blocks) + '\n'
with open(golden, 'w') as f:
    f.write(result)
PYEOF
}

# ---------------------------------------------------------------------------
# run_subtest <function_name>
# Runs a subtest function with audit tracing active.
#
# 1. Points $PEBBLE at pebble-trace so all pebble invocations are straced.
# 2. Writes a "# begin <name>" marker to the audit log.
# 3. Calls the function.
# 4. Writes a "# end <name>" marker.
# 5. Restores $PEBBLE to the real binary.
# 6. Summarises the block and compares/updates the golden file.
# ---------------------------------------------------------------------------
run_subtest() {
    local name="$1"

    # Activate audit tracing for this subtest.
    PEBBLE="$PEBBLE_TRACE"
    export AUDIT_LOG="$_AUDIT_LOG"

    printf '# begin %s\n' "$name" >> "$_AUDIT_LOG"
    "$name"
    printf '# end %s\n' "$name" >> "$_AUDIT_LOG"

    # Restore real binary for any code between subtests.
    PEBBLE="$PEBBLE_REAL"

    local summary
    summary=$(_audit_summarise "$name")

    if [[ "$_UPDATE_AUDIT" == "1" ]]; then
        _audit_write_golden "$name" "$summary"
        echo "AUDIT UPDATED [$name]"
    else
        local golden_block
        golden_block=$(_audit_read_golden "$name")
        if [[ -z "$golden_block" ]]; then
            echo "AUDIT FAIL [$name]: no golden block — run with --update-audit" >&2
            FAIL=$((FAIL + 1))
            return
        fi
        if [[ "$summary" != "$golden_block" ]]; then
            echo "AUDIT FAIL [$name]: syscall summary differs from golden" >&2
            diff <(printf '%s\n' "$golden_block") <(printf '%s\n' "$summary") >&2
            FAIL=$((FAIL + 1))
        else
            echo "AUDIT PASS [$name]"
        fi
    fi
}

# ---------------------------------------------------------------------------
# finish
# Prints the final results summary and exits with the appropriate code.
# Call this at the end of every test.sh.
# ---------------------------------------------------------------------------
finish() {
    if [[ "$_UPDATE_AUDIT" == "1" ]]; then
        _audit_sort_golden
        echo "AUDIT: updated $_GOLDEN"
    fi

    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]]
}
