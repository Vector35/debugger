# Build and test instructions

The full, multi-platform set of test binaries is built and signed by the
[debugger-test-binaries CI](https://github.com/Vector35/debugger/actions) and committed under
`binaries/<OS>-<arch>`. Running the unit tests does not require building any binaries.

## Run unit tests

Use Python 3.10–3.14 with the current Binary Ninja development builds; Python 3.9
is unsupported. CI dependencies and tests must use the same Poetry environment.
If an existing CI environment uses Python 3.9, install a supported interpreter and
select it with `poetry env use /path/to/python3.12`, then run `poetry install --sync --no-root`.
On Windows use `poetry run python`, not `poetry run py -3`: the Windows launcher can
select a different interpreter without the installed test dependencies.

The macOS launcher explicitly selects Python before `poetry install` and uses a
project-local `.venv`, matching Binary Ninja's CI environment layout. It probes
versioned executables on PATH and standard Homebrew/python.org installation paths.
Set `DEBUGGER_CI_PYTHON=/absolute/path/to/python3.12` to select a worker-specific
interpreter; an invalid or unsupported override fails before Poetry or the build runs.
Poetry itself is bootstrapped at a pinned version in `.ci-poetry` using that selected
Python. The worker's `virtualenv` creates this environment and seeds pip from its
own wheels, matching Binary Ninja CI and avoiding Homebrew `ensurepip` permissions.
This avoids the worker's global Poetry executable, which may still run under
Python 3.9 and reject the project before `poetry env use` can execute. The project
dependencies remain in `.venv`; neither environment changes the worker's global packages.

```zsh
cd test
python3 debugger_test.py
```
Pass a keyword to run a subset, e.g. `python3 debugger_test.py shared_library`.

The attach test has a 60-second wall-clock deadline, including debugger initialization,
attach, register reads, quit, and worker shutdown. It runs in a supervised subprocess so a
blocked native call cannot hang the test runner. A timeout fails the test and kills/reaps
the test's target and worker; failures include stage logs and a Python traceback. On macOS,
the supervisor also attempts a bounded native stack sample shortly before the deadline.
Run `python3 -m unittest discover -s test -p attach_timeout_test.py -v` from the repository
root to test the watchdog without Binary Ninja. These watchdog checks also run in CI.

CI invokes pytest through the build script's Python interpreter, with verbose test names
and stop-on-first-failure enabled. A Python stack dump is requested after 90 seconds in
one test. On macOS, an independent supervisor samples the pytest process if it is still
running after two minutes (diagnostic only). On all platforms it fails and terminates
pytest after a 15-minute total test deadline, including interpreter shutdown. Attach
workers also log explicit plugin-initialization stages and native debug messages.

## Windows Remote integration tests

On a Windows x64 host with a licensed Binary Ninja Python environment and the built
debugger plugin loaded:

```powershell
$env:WINDOWS_REMOTE_SERVER_PATH = 'C:\path\to\build\out\plugins\windows-debug-server.exe'
python -m pytest -v --junitxml=results-windows-remote.xml x2winrpc_test.py
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

The build stages the binaries defined in `CMakeLists.txt` into `binaries/<OS>-<arch>`, alongside the
committed test binaries. On macOS the debugger build then ad-hoc codesigns that directory into
`binaries/<OS>-<arch>-signed`, which is where the tests load them from. On a universal macOS build the
binaries are still emitted thin, one per architecture. These staged binaries are not committed. Tests
whose binaries were not built are skipped. Binaries that require additional toolchains (e.g. the nasm
assembly samples) remain pre-built by the CI.
