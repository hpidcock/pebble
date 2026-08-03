#!/usr/bin/awk -f
# summarise-audit.awk — Reduce raw strace output to a stable golden summary.
#
# Usage:
#   awk -f summarise-audit.awk [-v PEBBLE_DIR=/path] < audit-raw.log
#
# Reads strace output (written with -qqf, one line per syscall, PID-prefixed),
# normalises all variable parts (paths, random suffixes, temp dirs), deduplicates,
# sorts, and prints one canonical line per unique syscall+args combination.
#
# Variable normalisation tokens:
#   $PEBBLE_DIR  — the pebble state directory (supplied via -v PEBBLE_DIR=)
#   $TMPDIR      — any mktemp-style /tmp/tmp.XXXX directory
#   $HOME        — any /home/<user> prefix
#   $USR_BIN     — /usr/local/bin (where the pebble binary lives in containers)

# When BLOCK is set (via -v BLOCK=<name>), only lines between
# "# begin <name>" and "# end <name>" markers are processed, and the
# output is wrapped in matching begin/end comment lines.
BEGIN {
    count = 0
    in_block = (BLOCK == "") ? 1 : 0  # if no BLOCK, process everything
}

# ---------------------------------------------------------------------------
# norm_path: normalise a filesystem path to a stable token.
# ---------------------------------------------------------------------------
function norm_path(p,    r) {
    r = p
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", r)

    # Pebble socket — matches any pebble dir before the socket filename.
    if (r ~ /\/\.pebble\.socket$/) {
        return "$PEBBLE_DIR/.pebble.socket"
    }

    # Pebble state file with random atomic-write suffix (.pebble.state.XXXX~).
    if (r ~ /\/\.pebble\.state(\.[A-Za-z0-9]+)?~?$/) {
        sub(/\/\.pebble\.state.*$/, "/$PEBBLE_DIR/.pebble.state", r)
        return "$PEBBLE_DIR/.pebble.state"
    }

    # Specific pebble-dir-relative bare names that appear as relative openat/unlink
    # targets (no leading slash) because the kernel resolves them relative to a
    # dirfd pointing inside the pebble dir.
    if (r == ".pebble.state" || r ~ /^\.pebble\.state/) return "$PEBBLE_DIR/.pebble.state"
    if (r == "daemon.log")   return "$PEBBLE_DIR/daemon.log"
    if (r == "identity")     return "$PEBBLE_DIR/identity"
    if (r == "key.pem")      return "$PEBBLE_DIR/identity/key.pem"

    # PEBBLE_DIR prefix (supplied at runtime).
    if (PEBBLE_DIR != "" && index(r, PEBBLE_DIR) == 1) {
        return "$PEBBLE_DIR" substr(r, length(PEBBLE_DIR) + 1)
    }

    # Atomic-write temp files: any path ending in .<alphanum>~ (pebble
    # writes destination files atomically via a uniquely-named temp file).
    # Strip the random suffix so the normalised name is the intended target.
    gsub(/\.[A-Za-z0-9]+~$/, "", r)

    # mktemp-style temp directories: /tmp/tmp.XXXXX or /tmp/word.XXXXX
    gsub(/\/tmp\/[A-Za-z0-9._-]+/, "$TMPDIR", r)

    # Home directory prefix.
    gsub(/\/home\/[^\/]+/, "$HOME", r)

    # Container pebble binary location.
    gsub(/\/usr\/local\/bin/, "$USR_BIN", r)

    # /proc/sys paths that are stable (not /proc/self which is filtered earlier).
    # Leave them as-is.

    return r
}

# ---------------------------------------------------------------------------
# strip_noise_flags: remove implementation-detail flags.
# ---------------------------------------------------------------------------
function strip_noise_flags(f,    r) {
    r = f
    gsub(/\|O_CLOEXEC/,    "", r); gsub(/O_CLOEXEC\|/,    "", r); gsub(/O_CLOEXEC/,    "", r)
    gsub(/\|SOCK_CLOEXEC/, "", r); gsub(/SOCK_CLOEXEC\|/, "", r); gsub(/SOCK_CLOEXEC/, "", r)
    gsub(/\|SOCK_NONBLOCK/,"",  r); gsub(/SOCK_NONBLOCK\|/,"", r); gsub(/SOCK_NONBLOCK/,"", r)
    # Remove trailing pipe left behind after stripping.
    gsub(/\|$/, "", r); gsub(/^\|/, "", r)
    return r
}

# ---------------------------------------------------------------------------
# emit: deduplicate into seen[] and append to lines[].
# ---------------------------------------------------------------------------
function emit(entry) {
    if (entry == "") return
    if (!seen[entry]) {
        seen[entry] = 1
        lines[count++] = entry
    }
}

# ---------------------------------------------------------------------------
# Per-line processing
# ---------------------------------------------------------------------------
{
    line = $0

    # Handle begin/end block markers (written by the audit runner).
    if (line ~ /^# begin /) {
        if (BLOCK != "" && $3 == BLOCK) in_block = 1
        next
    }
    if (line ~ /^# end /) {
        if (BLOCK != "" && $3 == BLOCK) in_block = 0
        next
    }
    if (!in_block) next

    # Strip PID prefix.
    sub(/^[0-9]+[[:space:]]+/, "", line)

    # Skip strace meta lines.
    if (line ~ /^\+\+\+/ || line ~ /^---/) next
    if (line ~ /<unfinished \.\.\.\>/ || line ~ /^<\.\.\. /) next

    # Strip return-value suffix (handles both " = N" and " = -1 ERRNO (...)").
    sub(/ = -?[0-9].*$/, "", line)

    # Drop incomplete multi-line strace entries: lines that still contain
    # "<unfinished ...>" after return-value stripping, or resumed lines.
    if (line ~ /<unfinished/) next
    if (line ~ /^<\.\.\./)    next

    # -----------------------------------------------------------------------
    # Noise filters — drop entirely.
    # -----------------------------------------------------------------------
    if (line ~ /\/proc\/self\//)               next  # Go runtime reads
    if (line ~ /\/sys\/kernel\/mm\//)          next  # hugepage probe
    if (line ~ /\/sys\/fs\/cgroup/)             next  # cgroup reads
    if (line ~ /sun_path=""/)                   next  # unnamed/abstract sockets
    if (line ~ /^socket\(AF_NETLINK/)           next  # Go runtime netlink
    #if (line ~ /^socket\(AF_INET/)              next  # internal TCP (test harness)
    #if (line ~ /\/proc\/sys\/kernel\/random/)  next  # daemon startup, timing-dependent
    #if (line ~ /\.pebble\.state/)               next  # daemon state persistence, timing-dependent
    #if (line ~ /\/identity(\/|,|\))/)           next  # daemon identity dir, timing-dependent
    #if (line ~ /\/key\.pem/)                    next  # daemon identity key, timing-dependent
    if (line ~ /\/proc\/sys\/net\//)            next  # network kernel params, timing-dependent
    # Daemon reads of its own pebble dir are timing-dependent: the daemon is a
    # child of the strace wrapper so its syscalls are captured too.  Filter out
    # openat calls where the path is exactly a /tmp/... directory (no sub-path),
    # opened O_RDONLY. Use index/substr to avoid the unescapable slash issue.
    if ((index(line, "O_RDONLY)") || index(line, "O_RDONLY|")) && \
       match(line, /"(\/tmp\/[A-Za-z0-9._-]+)"/, _pa) && \
       split(_pa[1], _pc, "/") == 3) next  # /tmp/<name> only, no sub-path

    # -----------------------------------------------------------------------
    # openat / open / creat
    # -----------------------------------------------------------------------
    if (line ~ /^openat\(/ || line ~ /^open\(/ || line ~ /^creat\(/) {
        match(line, /^([a-z]+)\(/, arr)
        sc = arr[1]

        args = substr(line, length(sc) + 2)
        sub(/\)$/, "", args)

        # openat has a leading dirfd argument — skip it.
        if (sc == "openat") sub(/^[^,]+,[[:space:]]*/, "", args)

        # Extract quoted path.
        if (!match(args, /^"([^"]*)"/, parr)) next
        path  = norm_path(parr[1])

        # Extract flags (after path and comma).
        rest = substr(args, RSTART + RLENGTH)
        sub(/^,[[:space:]]*/, "", rest)
        # Drop trailing mode argument (octal literal) and anything after it.
        sub(/,[[:space:]]*0[0-9]+.*$/, "", rest)
        flags = strip_noise_flags(rest)

        if (flags == "") emit("openat(" path ")")
        else             emit("openat(" path ", " flags ")")
        next
    }

    # -----------------------------------------------------------------------
    # socket
    # -----------------------------------------------------------------------
    if (line ~ /^socket\(/) {
        args = substr(line, 8); sub(/\)$/, "", args)
        n = split(args, a, /,[[:space:]]*/); if (n < 2) next
        family    = a[1]
        sock_type = strip_noise_flags(a[2])
        emit("socket(" family ", " sock_type ")")
        next
    }

    # -----------------------------------------------------------------------
    # connect
    # -----------------------------------------------------------------------
    if (line ~ /^connect\(/) {
        if (!match(line, /\{([^}]*)\}/, sarr)) next
        sockaddr = sarr[1]
        if (!match(sockaddr, /sa_family=([A-Z_0-9]+)/, farr)) next
        family = farr[1]

        if (family == "AF_UNIX") {
            if (!match(sockaddr, /sun_path="([^"]*)"/, parr)) next
            emit("connect(" family ", " norm_path(parr[1]) ")")
        } else {
            emit("connect(" family ")")
        }
        next
    }

    # -----------------------------------------------------------------------
    # bind
    # -----------------------------------------------------------------------
    if (line ~ /^bind\(/) {
        if (!match(line, /\{([^}]*)\}/, sarr)) next
        sockaddr = sarr[1]
        if (!match(sockaddr, /sa_family=([A-Z_0-9]+)/, farr)) next
        family = farr[1]

        if (family == "AF_UNIX") {
            if (!match(sockaddr, /sun_path="([^"]*)"/, parr)) next
            emit("bind(" family ", " norm_path(parr[1]) ")")
        } else {
            emit("bind(" family ")")
        }
        next
    }

    # -----------------------------------------------------------------------
    # mkdir / mkdirat
    # -----------------------------------------------------------------------
    if (line ~ /^mkdir\(/ || line ~ /^mkdirat\(/) {
        match(line, /^([a-z]+)\(/, arr); sc = arr[1]
        args = substr(line, length(sc) + 2); sub(/\)$/, "", args)
        if (sc == "mkdirat") sub(/^[^,]+,[[:space:]]*/,"", args)
        if (!match(args, /^"([^"]*)"/, parr)) next
        path = parr[1]
        # Drop mkdir on /tmp itself (mktemp implementation detail).
        if (path == "/tmp") next
        # Bare names without a leading slash are relative paths:
        # single-component names that look like mktemp basenames go to $TMPDIR;
        # other bare names (e.g. "layers") are pebble-dir-relative.
        if (path !~ /^\//) {
            if (path ~ /^tmp\./) path = "/tmp/" path
            else path = "$PEBBLE_DIR/" path
        }
        emit("mkdir(" norm_path(path) ")")
        next
    }

    # -----------------------------------------------------------------------
    # unlink / unlinkat
    # -----------------------------------------------------------------------
    if (line ~ /^unlink\(/ || line ~ /^unlinkat\(/) {
        match(line, /^([a-z]+)\(/, arr); sc = arr[1]
        args = substr(line, length(sc) + 2); sub(/\)$/, "", args)
        if (sc == "unlinkat") sub(/^[^,]+,[[:space:]]*/, "", args)
        if (!match(args, /^"([^"]*)"/, parr)) next
        # Strip trailing flags argument (e.g. AT_REMOVEDIR).
        path = norm_path(parr[1])
        emit("unlink(" path ")")
        next
    }

    # -----------------------------------------------------------------------
    # rename / renameat
    # -----------------------------------------------------------------------
    if (line ~ /^rename\(/ || line ~ /^renameat\(/) {
        match(line, /^([a-z]+)\(/, arr); sc = arr[1]
        args = substr(line, length(sc) + 2); sub(/\)$/, "", args)

        if (sc == "renameat") sub(/^[^,]+,[[:space:]]*/, "", args)

        if (!match(args, /^"([^"]*)"/, parr)) next
        old_path = norm_path(parr[1])
        args = substr(args, RSTART + RLENGTH)
        sub(/^,[[:space:]]*/, "", args)
        if (sc == "renameat") sub(/^[^,]+,[[:space:]]*/, "", args)
        if (!match(args, /^"([^"]*)"/, parr)) next
        new_path = norm_path(parr[1])

        emit("rename(" old_path ", " new_path ")")
        next
    }
}

# ---------------------------------------------------------------------------
# Sort (insertion sort) and print with block markers.
# ---------------------------------------------------------------------------
END {
    for (i = 1; i < count; i++) {
        key = lines[i]; j = i - 1
        while (j >= 0 && lines[j] > key) { lines[j+1] = lines[j]; j-- }
        lines[j+1] = key
    }
    if (BLOCK != "") print "# begin " BLOCK
    for (i = 0; i < count; i++) print lines[i]
    if (BLOCK != "") print "# end " BLOCK
}
