#!/bin/bash
# pebble-trace — thin strace wrapper around /usr/local/bin/pebble.
#
# Installed as /usr/local/bin/pebble-trace in every test image.
# The audit entrypoint sets PEBBLE=/usr/local/bin/pebble-trace so that every
# pebble invocation in test.sh is automatically traced.
#
# Strace output is written to a per-invocation temp file and then appended to
# $AUDIT_LOG so concurrent calls don't interleave their output.
_strace_tmp=$(mktemp /tmp/strace-XXXXXX.log)
strace -qqf \
    -e trace=openat,open,creat,socket,connect,bind,unlink,unlinkat,mkdir,mkdirat,rename,renameat \
    -o "$_strace_tmp" \
    -- /usr/local/bin/pebble "$@"
_exit=$?
cat "$_strace_tmp" >> "${AUDIT_LOG:-/tmp/audit-raw.log}"
rm -f "$_strace_tmp"
exit "$_exit"
