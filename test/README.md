# Build and test instructions

The prebuilt, multi-platform test binaries are committed under `test/binaries/<OS>-<arch>`.
Additional fixtures are built alongside the debugger by default; see
[Building test binaries alongside the debugger](#building-test-binaries-alongside-the-debugger).

## Run unit tests

The standalone debugger build/test environment supports Python 3.10–3.14, matching
Binary Ninja's Python plugin support range. This is separate from the top-level
Binary Ninja build environment, which requires Python 3.12 or newer.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and make it
available on `PATH`. From the debugger repository root, run:

```sh
uv sync --locked
uv run --locked python test/debugger_test.py
```

The tests require a valid Binary Ninja license and its Python bindings to be
importable in the uv environment. Set `PYTHONPATH` to the installation's Python
bindings directory or install the corresponding `.pth` file into `.venv`.
Pass a keyword to run a subset, e.g.
`uv run --locked python test/debugger_test.py shared_library`.

uv selects a supported interpreter and installs the locked dependencies into
`.venv`. To select a particular supported interpreter, use
`--python` with both
`uv sync` and `uv run`, or set `UV_PYTHON`. uv rejects invalid or unsupported
requests before running the command.

Standalone CI uses `mise run build` with the debugger's pinned Python 3.12.13,
uv, CMake, and Ninja toolchain. It installs the same locked Python dependencies
into `.venv` and runs the existing build/test script; see
[Standalone CI builds](../build.md#standalone-ci-builds).

On Windows, `uv run --locked python` uses the project interpreter directly.
`uv run py -3` runs the external Windows Python launcher, whose explicit `-3`
selector [chooses a global interpreter](https://docs.python.org/3.12/using/windows.html#virtual-environments).

The attach test has a 60-second wall-clock deadline, including debugger initialization,
attach, register reads, quit, and worker shutdown. It runs in a supervised subprocess so a
blocked native call cannot hang the test runner. A timeout fails the test and kills/reaps
the test's target and worker. Worker output and exception tracebacks are preserved;
a timeout reports the worker and target PIDs.
Run `uv run --locked python -m unittest discover -s test -p attach_timeout_test.py -v` from the repository
root to test the watchdog without Binary Ninja. These watchdog checks also run in CI.

CI invokes pytest through the build script's Python interpreter and runs the full suite
even after individual test failures. An independent supervisor fails and terminates
pytest after a 15-minute total test deadline, including interpreter shutdown.

## Windows Remote integration tests

On a Windows x64 host with a licensed Binary Ninja Python environment and the built
debugger plugin loaded, run from the debugger repository root:

```powershell
$env:WINDOWS_REMOTE_SERVER_PATH = 'C:\path\to\build\out\plugins\windows-debug-server.exe'
uv run --locked python -m pytest -v --junitxml=test/results-windows-remote.xml test/x2winrpc_test.py
```

The suite starts its own local debug server on an ephemeral loopback port, connects
the real client, and exercises Windows debuggees. No second host, firewall rule,
or manually started server is needed. Missing server binaries or failed server
startup are errors on supported Windows hosts, not successful skips. Build the
`debugger_test_binaries` target too; missing shared-library fixtures fail the suite.

`scripts/build.py`, used by both Jenkins pipelines, includes this suite only on
Windows and sets `WINDOWS_REMOTE_SERVER_PATH` to the freshly built artifact. Results are included
in `test/results.xml`; pytest failures fail the build. The Windows test process tree
has a 15-minute outer timeout in addition to bounded debugger waits.

The UI label is **Windows Remote**, and the server executable is `windows-debug-server.exe`.
API identifiers (`X2WIN_RPC`), source names, and settings keys remain unchanged.
The test locator still accepts the legacy `X2WINSTUB_PATH` environment variable;
`WINDOWS_REMOTE_SERVER_PATH` takes precedence when both are set.

The RPC suite uses x64 targets; it does not cover the known x86/WOW64 StepReturn
unwind limitation. Conditional breakpoints are tested for get/set only, and the
restart test explicitly re-adds its breakpoint rather than testing automatic
carry-over. GUI-specific behavior is not covered.

## Building test binaries alongside the debugger

Some test binaries are built alongside the debugger, so that adding a new test does not require a
separate build. This is on by default (`BUILD_DEBUGGER_TEST_BINARIES`), so both local and CI debugger
builds produce them; pass `-DBUILD_DEBUGGER_TEST_BINARIES=OFF` to skip.

The build stages the binaries defined in `CMakeLists.txt` into `test/binaries/<OS>-<arch>`, alongside the
committed test binaries. On macOS the debugger build then ad-hoc codesigns that directory into
`test/binaries/<OS>-<arch>-signed`, which is where the tests load them from. On a universal macOS build the
binaries are still emitted thin, one per architecture. These staged binaries are not committed. Tests
whose binaries were not built are skipped. Binaries that require additional toolchains (e.g. the nasm
assembly samples) remain pre-built by the CI.
