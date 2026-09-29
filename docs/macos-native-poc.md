# Native macOS debugger PoC

The opt-in `MACOS_NATIVE` adapter implements local arm64 process debugging using
Mach task/thread APIs, Mach exceptions and BSD `ptrace`, without calling LLDB.
The existing LLDB adapter remains available and is still linked and packaged.
This demonstrates feasibility; replacing LLDB's full feature set remains a
substantial engineering project.

## Implementation

`core/adapters/macosnativeadapter.cpp` owns launch/attach/detach/termination,
the exception worker and reply rights, process I/O, module discovery, symbol
lookup, memory maps, memory access and breakpoint lifecycle. The worker orders
resume/stop events and delivers callbacks outside its state lock.
`macosnativearch_arm64.cpp` supplies registers, debug-register breakpoints,
instruction stepping and frame-pointer stack walking. The architecture boundary
is intended to accommodate a future x86_64 implementation.

Implemented operations include launch arguments/environment/cwd, stdin/stdout/
stderr, attach, pause, continue, restart, detach with trap restoration, exit codes,
software and hardware execute/write breakpoints, register/memory read/write,
threads and thread suspension, modules and mapped symbols, step into/over/return,
and frame-pointer stack traces. Software breakpoint continuation restores the
instruction, steps with peer threads suspended, then reinstalls the trap.

## Reproduce

Use an arm64 Mac, Xcode tools, a Binary Ninja development installation/API,
LLDB for the retained adapter, and framework Python with pytest. Initialize the
repository submodules. Configure paths for your installation:

```sh
cmake -S . -B build-native -DHEADLESS=ON -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DBN_API_PATH=/path/to/api \
  '-DBN_INSTALL_DIR=/path/to/Binary Ninja.app/Contents/MacOS' \
  -DLLDB_PATH=/path/to/llvm
cmake --build build-native --target debuggercore debugger_generator_copy -j 8
/opt/homebrew/bin/python3 scripts/test_macos_native.py \
  --bn-install '/path/to/Binary Ninja.app' \
  test/debugger_test.py::MacOSNativeArm64Test
```

The runner builds and ad-hoc signs a separate embedded Python executable with
the debugger entitlement, isolates plugin loading to this build, and uses an
existing Binary Ninja license. It does not re-sign the installed Python or Binary
Ninja application. Targets are signed with `get-task-allow` by the test build.
A copied Homebrew Python launcher is insufficient because it re-executes its
framework executable. Application signing and protected-target policy must be
addressed separately for shipping.

For broader regression coverage, replace the final test argument with
`test/debugger_test.py test/attach_timeout_test.py test/ci_launcher_test.py`.
Results are written to `build-native/macos-native-tests.log`.

## Validation and limits

Validation was performed on macOS 27.0 (26A428), Xcode 27.0 (27A266a),
Binary Ninja 5.4.10246-dev, framework Python 3.14.7 and pytest 9.1.1.
The native class inherits the existing debugger tests and adds deterministic
arm64 assembly call/return, hardware breakpoint continuation, detach restoration,
memory protections, thread control and launch/I/O tests. The inherited assembly
and divide-by-zero cases have no effective arm64 assertions; the new assembly
fixture provides real arm64 stepping coverage. The DbgEng-specific teardown case
is skipped. The final combined regression run completed with **71 passed,
100 skipped in 56.56 seconds**, including **25 native tests passed and one
DbgEng-specific skip**. Other skips cover base classes and unavailable platforms.
The Debug build and `git diff --check` also passed.

Remaining production work:

- Only thin arm64 Mach-O executable targets are accepted. Native x86_64,
  Rosetta and universal executable support are unimplemented; universal plugin
  builds currently omit this adapter.
- Stack walking uses frame pointers, not compact unwind or DWARF. Step over
  recognizes BL/BLR; authenticated calls and comprehensive optimized-code/PAC
  stepping need further work.
- Loader notifications, delayed breakpoints for future dlopen images, symbol
  edge cases and new-thread hardware-breakpoint inheritance need hardening.
- Signal/fault continuation policy is basic and lacks LLDB's configurable
  delivery behavior. Host protection against deny-attach targets, exception
  batching and adversarial lifecycle/concurrency require further validation.
- LLDB expressions/console, remote debugging, core files and other LLDB-only
  features are unsupported.
- The entitled test host validates eligible local fixtures. Shipping Binary
  Ninja entitlements, notarization and real target permission combinations were
  not validated.

For x86_64, add an architecture implementation for Mach register flavors,
INT3 instruction/PC adjustment, trap-flag stepping and DR0–DR7 breakpoints,
then generalize the fixed four-byte software trap representation and instruction
classification. Exercise both native slices and Rosetta explicitly before
enabling universal builds. Loader, unwinding and security-policy work will be
shared across architectures.

See [the initial feasibility assessment](macos-native-debugger-assessment.md)
for the API mapping and scope estimates.
