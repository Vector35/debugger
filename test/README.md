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

## Performance benchmark

`perf_benchmark.py` times debugger actions against a live target, N tries each, for any debug adapter. It
only uses the public `DebuggerController` Python API, so it needs no per-adapter code: the adapter is a name
string, and a newly registered adapter (see `--list-adapters`) works as soon as it is built in.

```zsh
cd test
python3 perf_benchmark.py -n 100                                  # 100 tries of every action, default adapter
python3 perf_benchmark.py -n 100 --adapter LLDB --adapter "GDB MI"  # compare adapters
python3 perf_benchmark.py -n 100 --out history.json --label "after register cache change"
python3 perf_benchmark.py -n 50 --actions step_into,reg_write --set lifecycle=10
python3 perf_benchmark.py --list-adapters
python3 perf_benchmark.py --list-actions
```

`-n` is the number of timed tries per action; each action also runs `--warmup` untimed tries first (default 3).
`--set GROUP=N` overrides the count for one action group, e.g. for `lifecycle` (a full launch and quit per try)
or `symbols_all`. Passing `--adapter` more than once runs each adapter in turn and prints a median comparison.
The report gives min, mean, median, p95, max and calls per second for each timing. At `-n 100` a full run takes
about two minutes on LLDB. `--csv` writes one row per timed call.

### Tracking performance over time (`--out`)

`--out PATH` adds the run to a JSON history file, creating it if needed, so one file accumulates a timeline:

```json
{"schema": 1, "runs": [
  {"timestamp": "...", "label": "...",
   "git": {"commit": "...", "branch": "...", "commit_date": "...", "subject": "...", "dirty": false},
   "binaryninja": "...", "host": {"hostname": "...", "platform": "...", "machine": "...", "cpus": 11, "python": "..."},
   "target": {"binary": "perf_target", "arch": "arm64"},
   "config": {"iterations": 100, "warmup": 3, "groups": [...], "group_iterations": {...}, ...},
   "complete": true,
   "adapters": [{"name": "LLDB", "results": [
     {"name": "step_into", "stats": {"n": 100, "min_ns": ..., "median_ns": ..., "p95_ns": ..., "mean_ns": ...},
      "failures": 0, "details": [], "skipped": null, "aborted": null}]}]}]}
```

* Each run records the debugger repository's commit and whether tracked files were modified (`dirty`), so a
  run can be placed on a timeline of commits. `--label` adds free text, e.g. what you changed.
* Result names are stable, and a result that is skipped or aborted appears with a reason rather than being
  left out, so a series always lines up. Only compare runs with the same `host`, `target` and `config`.
* Raw per-call timings are left out to keep the file small; `--samples` stores them too.
* An existing file that is not a schema 1 history file is never overwritten. The file is replaced
  atomically, so an interrupted run cannot corrupt the history so far.
* `--json` is accepted as an alias for `--out`.

The layout version is `HISTORY_SCHEMA` in `perf_benchmark.py`; it changes only if a field is renamed or
changes meaning, never when one is added.

### What is measured

`--list-actions` prints every group and the timings it produces. The groups cover:

* **Execution:** step into/over/return, stepping at LLIL/MLIL/HLIL, run to, breakpoint hit, pause, reverse
  execution.
* **State:** register read/write and reading all registers, instruction pointer, memory read/write (directly and
  through the BinaryView), address info, the controller's state properties, processes, threads, modules, memory
  map, stack frames, active-thread get/set and thread suspend/resume.
* **Breakpoints:** add/remove, enable/disable, conditions, module+offset breakpoints, listing, and hardware
  execute breakpoints and read/write/access watchpoints.
* **Other:** loading and removing backend symbols, remote base and rebasing, event callbacks, stdin, backend
  commands, adapter properties, and time-travel debugging (positions, bookmarks, memory/register history,
  events, calls, code coverage).
* **Session:** restart, attach/detach, and launch/quit. These end the session, so they run last.

How to read the numbers:

* Every number is the wall-clock time of one controller call, so it includes the controller's own work (state
  updates, cache invalidation, events) on top of the adapter's. Compare adapters or builds on the same machine
  and binary, not against numbers from elsewhere.
* The controller caches registers, memory, threads and modules. `reg_read`, `mem_read`, `regs_all`, `ip_read`
  and `data_read` invalidate the cache with an untimed write first (`_cold`), and `_warm` is a cache hit.
  `threads`, `modules`, `memory_map` and `frames` are the first read after a stop, with an untimed step before
  each try. `reg_write` includes the register refresh the controller does before a write when a previous write
  invalidated its cache.
* Each try is checked (a step must stop with `SingleStep`, a write must read back, a removed breakpoint must be
  gone, and so on). Failed tries are counted in `fail` and left out of the statistics, and the exit code is 1 if
  any try failed or a group aborted. An adapter that cannot do something makes the group `skipped` with a
  reason, not failed.
* Scratch registers, the instruction pointer and stack memory are restored before the target resumes.
  Breakpoint tests use `perf_unused`, code the target never runs, so a breakpoint an adapter fails to remove
  cannot change where later actions stop.

### Setup

The debuggee is `perf_target` (`src/perf_target.c`), an endless loop of small non-inlined functions, built with
the other test binaries. `--binary` accepts another test-binary name or a path; without the `perf_target`
symbols the `step_return`, `breakpoint_hit`, `run_to` and `reverse` actions are skipped and the rest run against
whatever function the target is stopped in.

Adapter setup that is not just a name goes through `--adapter-property KEY=VALUE` (e.g. `gdb.path=/usr/bin/gdb`),
`--executable-path`, and `--connect HOST:PORT` for adapters that attach to a debug server (this switches
`lifecycle` to timing connect and quit, and skips `attach_detach`). `--backend-command`, `--ttd-symbol` and
`--scratch-register` adjust individual actions.

To add an action, write a function in `perf_actions.py`, register it with `@action(group, [result names])`, and
give it a docstring; the first line is what `--list-actions` shows. Result names end up in the history file, so
keep them stable once they have been published.

Only LLDB on macOS arm64 has been run. The `reverse` and `ttd` groups need a time-travel adapter and have not
been run at all, and `--connect` and the GDB MI setup are untested.

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
