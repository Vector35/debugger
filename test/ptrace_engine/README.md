# Ptrace engine tests

The C++ drivers exercise the engine, architecture tables, ELF reader, modules,
frame walker and stepper without loading Binary Ninja. Pytest runs each named
scenario in its own process and reports individual failures, skips and timeouts.
The adapter and controller integration tests remain in `test/debugger_test.py`.
Production ptrace sources and headers live in `core/adapters/ptrace/`.

## Build and run on Linux

Only a C/C++ compiler, CMake, pthreads, binutils, Python and pytest are needed.
Initialize the `vendor/elfio` submodule with `git submodule update --init --recursive`.
The ELF reader uses its header-only C++ API; no system ELF library is required.
`BN_API_PATH` supplies Binary Ninja's API headers and bundled fmt sources; its
runtime and a license are not needed. Initialize the API's submodules as well.
From the debugger checkout:

```sh
cmake -S test/ptrace_engine -B build-ptrace -G Ninja -DBN_API_PATH=/path/to/binaryninja-api
cmake --build build-ptrace --target ptrace_tests
PTRACE_TEST_BUILD_DIR="$PWD/build-ptrace" python3 -m pytest -v test/ptrace_engine_test.py
```

To build alongside the debugger, configure with `-DBUILD_PTRACE_TESTS=ON`.
The drivers are then under `<build>/test/ptrace_engine`, which is the pytest
runner's default for a build directory named `build`. Standalone Linux CI enables
this option and includes the engine regression tests in its existing pytest/JUnit
run. A configured but missing build fails CI rather than silently skipping tests.

The drivers also accept `--list` or a single scenario name. Unknown names fail.
CMake supplies the fixture paths, so the checkout and build need no special mount
locations. `PTRACE_TEST_CORPUS_DIR` can override the default repository corpus at
`test/binaries/Linux-<host-arch>` used by the `conf_*` cases.

## Stress, sanitizers and investigations

- Set `PTRACE_TEST_REPEAT=30` to repeat each selected scenario. Use pytest's `-k`
  expression to select scenarios such as `stepover` or `attach`.
- Set `PTRACE_TEST_CPUS=0` or `PTRACE_TEST_CPUS=0,1` to constrain the native process
  and its inferiors. Choose CPU numbers allowed by the host's affinity mask;
  the runner checks them and invokes `taskset` without a shell.
- Set `PTRACE_TEST_TIMEOUT=180` to change the default 120-second per-scenario
  deadline. Each supervisor adopts, kills and reaps leftover descendants,
  including inferiors that create new sessions. Supervisor regression tests
  cover failure propagation and cleanup after both normal exit and timeout.
- Configure a separate build with `-DPTRACE_TEST_SANITIZER=address` for ASan/UBSan,
  or `-DPTRACE_TEST_SANITIZER=thread` for TSan. Use the same pytest command with
  that build's `PTRACE_TEST_BUILD_DIR`. Instrumentation covers the engine and
  drivers, while target fixtures keep their predictable instruction sequences.
  Sanitizer errors fail tests even when a runtime is configured to recover.
- The review regressions run in the default gate, including failed and partial
  memory writes, pause races, external stops, inherited signals and callback teardown.
- Use `PTRACE_TEST_EXTRAS=diagnostics` for the `repro_*` cases and the two event
  exception demonstrations, which currently expect SIGABRT. Use
  `PTRACE_TEST_EXTRAS=benchmark` for `perf` and `maps_cost`. Extras can be combined
  with commas. These investigations are not part of the default CI gate.

Hardware/kernel features that the drivers report as unavailable become pytest
skips. Failing cases remain failures even if they also print a skip message.
The `layout` and `hwabi` executables check x86 register layouts and ptracer ABI
offsets. The ELF comparison tests check names, addresses, sizes and symbol kinds
against `readelf` for the built fixtures. The fault drivers retain the link-time
`ptrace`, `pwrite`, `open` and `waitpid` wrappers.

## Optional Docker environment

Docker supplies Linux on other hosts; no shell runner is required. For example:

```sh
docker build -t ptrace-test test/ptrace_engine
docker run --rm --init -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD:/debugger:ro" -v /path/to/binaryninja-api:/bnapi:ro \
    -w /debugger ptrace-test bash
```

Inside the container, use the build/run commands above with `-B /tmp/ptrace-build`,
`-DBN_API_PATH=/bnapi` and `PTRACE_TEST_BUILD_DIR=/tmp/ptrace-build`.
The capabilities allow tracing and disabling ASLR. The fixtures themselves are
built in the output directory, leaving the source mount read-only.

Run x86 ptrace coverage on a native x86 Linux host: Docker Desktop's architecture
emulation cannot reliably provide ptrace. The arm64 harness retains its test-only
architecture table; passing there does not establish support for an arm64 adapter.
