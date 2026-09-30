# Native macOS debugger PoC

The opt-in `macOS Native` adapter implements local arm64 process debugging using
Mach task/thread APIs, Mach exceptions and BSD `ptrace`. Local x86_64 apps on
Apple Silicon use Apple's `/usr/libexec/rosetta/debugserver` over RSP, without
calling the LLDB client API. **The Rosetta path is not a direct Mach-only
implementation.** Apple exposes translated ARM threads through Mach; its Rosetta
service supplies the x86 register, breakpoint and instruction-stepping view.
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

`macosrosettaadapter.cpp` starts and owns Apple's Rosetta service, communicates
through an inherited Unix socket pair (no TCP listener), and uses the existing
RSP transport. It adds Apple register/image discovery, asynchronous run control,
Mach-exception stop translation, breakpoint continuation, frame-pointer stepping,
and private stdin/stdout FIFOs. Native Mach inspection supplies memory maps and
mapped-image symbols. The factory selects the backend from the analyzed target
architecture; both appear as `macOS Native`.

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

Add `test/debugger_test.py::MacOSNativeRosettaTest` to exercise x86_64 apps on
the same Mac. The build creates and signs fixtures for both target architectures.

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
Both native test classes inherit the existing debugger tests and add deterministic
architecture-specific assembly call/return, hardware breakpoint continuation, detach restoration,
memory protections, thread control and launch/I/O tests. The inherited assembly
and divide-by-zero cases have no effective arm64 assertions; the new assembly
fixture provides real arm64 stepping coverage. The DbgEng-specific teardown case
is skipped. The original arm64-only regression run completed with **71 passed,
100 skipped in 56.56 seconds**. The expanded arm64/Rosetta run completed with
**50 passed and two DbgEng-specific skips in 83.79 seconds**: 25 applicable tests
passed for each target architecture. The final complete regression run completed
with **97 passed and 100 skipped in 127.63 seconds**, including the existing LLDB
tests. Other skips cover base classes and unavailable platforms. The Debug GUI/core
build and `git diff --check` also passed.

Remaining production work:

- Direct Mach debugging accepts thin arm64 executable targets. x86_64 debugging
  on this Mac depends on Apple's installed Rosetta service and its packet
  behavior. Native Intel-host support is unimplemented; universal plugin builds
  currently omit this adapter. Universal executable slice selection is untested.
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

For direct debugging on an Intel Mac, add an implementation for Mach register flavors,
INT3 instruction/PC adjustment, trap-flag stepping and DR0–DR7 breakpoints,
then generalize the fixed four-byte software trap representation and instruction
classification. Validate on Intel hardware before enabling universal plugin
builds. Loader, unwinding and security-policy work will be
shared across architectures.

The Rosetta distinction is also reflected in LLVM's
[initial Rosetta support](https://reviews.llvm.org/D82491), which selects a
separate system debugserver for translated processes. Apple's service is a
debugserver implementation; this PoC removes the LLDB client API from that
execution path, not all code historically associated with LLDB.

See [the initial feasibility assessment](macos-native-debugger-assessment.md)
for the API mapping and scope estimates.
