# Pebble Integration Tests

This directory holds two suites of integration tests:

1. **Process-level tests** (`tests/*.go`) — run Pebble directly as a child
   process on the host.
2. **Container-level tests** (`tests/container/`) — build an OCI image with
   `podman` and run Pebble inside it, one command per image.

---

## Process-level tests

These tests use the standard Go test runner and are gated behind the
`integration` build tag.

### Run

```bash
go test -count=1 -tags=integration ./tests/
```

The above command will build Pebble first, then run tests with it.

To use an existing Pebble binary rather than building one, pass `-pebblebin`:

```bash
go test -v -count=1 -tags=integration ./tests/ -pebblebin=/home/ubuntu/pebble
```

---

## Container-level tests

These tests are gated behind the `container_integration` build tag and require
**[podman](https://podman.io/)** to be installed and functional.

### Layout

```
tests/container/
├── main.sh               # Runner: builds base + test images, runs containers
├── base/
│   ├── Containerfile     # FROM ubuntu:24.04; installs tools + pebble binary
│   ├── base.sh           # Shared harness: helpers, run_subtest, finish
│   ├── pebble-trace.sh   # strace wrapper used by run_subtest for audit
│   └── summarise-audit.awk  # Normalises raw strace output to golden format
└── version/
    ├── Containerfile     # FROM pebble-test-base; copies test.sh + audit.txt
    ├── test.sh           # Sources /base.sh; defines subtests; calls run_subtest
    └── audit.txt         # Golden syscall summary, one block per subtest
```

Each command under test gets its own sub-directory containing:

| File | Purpose |
|---|---|
| `Containerfile` | `FROM pebble-test-base`; copies `test.sh` and `audit.txt` |
| `test.sh` | `source /base.sh`; defines subtest functions; calls `run_subtest` for each |
| `audit.txt` | Golden file with one `# begin`/`# end` block per subtest |

`main.sh` builds the base image once, then builds and runs each test image in sequence.

### Requirements

- `podman` ≥ 4.x on the host
- The Pebble binary must be statically linked (`CGO_ENABLED=0`). The test
  framework builds one automatically if `-pebblebin` is not supplied.

### Run

```bash
cd tests/container
bash main.sh
```

To supply a pre-built binary:

```bash
CGO_ENABLED=0 go build -o /tmp/pebble ./cmd/pebble
bash tests/container/main.sh --pebblebin /tmp/pebble
```

### Syscall audit

Audit tracing is built into every normal test run — there is no separate audit
image or second pass. Each `run_subtest` call in `test.sh` automatically:
1. Points `$PEBBLE` at `pebble-trace` (the strace wrapper) for the duration
   of that subtest, so only the pebble binary is traced.
2. Summarises the captured syscalls with `summarise-audit.awk`.
3. Compares the summary against the matching `# begin`/`# end` block in
   `audit.txt` and fails the subtest if they differ.

The golden file has one block per subtest, sorted alphabetically:

```
# begin test_version_with_server
connect(AF_UNIX, $PEBBLE_DIR/.pebble.socket)
openat(/root/.config/pebble/cli.json, O_RDONLY)
socket(AF_UNIX, SOCK_STREAM)
# end test_version_with_server
```

To generate or regenerate golden files:

```bash
# Regenerate all golden files
bash tests/container/main.sh --update-audit

# Regenerate one test's golden file
bash tests/container/main.sh --update-audit version
```

The summariser (`base/summarise-audit.awk`) strips noise (Go runtime
`/proc/self` reads, daemon-internal state files, timing-dependent kernel
reads, etc.), normalises variable paths (`$PEBBLE_DIR`, `$TMPDIR`, `$HOME`),
deduplicates, and sorts so diffs are minimal and meaningful.

### Adding a new command test

1. Create `tests/container/<command>/Containerfile`:
   ```dockerfile
   FROM pebble-test-base
   COPY test.sh /test.sh
   RUN chmod +x /test.sh
   COPY audit.txt /audit.txt
   ENTRYPOINT ["/bin/bash", "/test.sh"]
   ```
2. Create `tests/container/<command>/test.sh` — copy the pattern from
   `version/test.sh`: `source /base.sh`, define subtests, call
   `run_subtest <fn>` for each, end with `finish`.
3. Create an empty `tests/container/<command>/audit.txt` placeholder.
4. Run `bash tests/container/main.sh --update-audit <command>` to populate
   the golden file, then commit `audit.txt` alongside the test.
5. `main.sh` will discover and run it automatically.

---

## Developing

### Visual Studio Code Settings

For VSCode Go and the gopls extension to work properly with files containing
build tags, add the following to `.vscode/settings.json`:

```json
{
    "gopls": {
        "build.buildFlags": [
            "-tags=integration"
        ]
    }
}
```
