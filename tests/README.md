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
├── main.sh               # Runner: builds images, runs containers, reports results
└── version/
    ├── Containerfile     # OCI image definition (FROM ubuntu:24.04)
    └── test.sh           # Shell script with subtests; prints PASS/FAIL lines
```

Each command under test gets its own sub-directory containing:

| File | Purpose |
|---|---|
| `Containerfile` | Inherits from `ubuntu:24.04` (or `scratch`), copies in the `pebble` binary and `test.sh` |
| `test.sh` | Exercises the command and prints `PASS: <name>` / `FAIL: <name>` lines |

`main.sh` discovers every sub-directory that contains a `Containerfile`,
builds the image, runs the container, and reports a summary.

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

### Adding a new command test

1. Create `tests/container/<command>/Containerfile` — use `FROM ubuntu:24.04`.
2. Create `tests/container/<command>/test.sh` — copy the pattern from
   `version/test.sh`: define subtests as shell functions, each calling
   `pass`/`fail`, then invoke them at the bottom.
3. `main.sh` will discover and run it automatically.

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
