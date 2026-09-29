# macOS native debugger feasibility

An arm64 implementation now exists. See [the PoC and validation notes](macos-native-poc.md).
The assessment below records the initial source review before implementation.

Assessed 2026-09-29 at debugger commit `abd1369fe5c67dd7bc8cf198aa633c4b178b6603`.
This isolated worktree starts at the original checkout's committed HEAD. Its uncommitted
LLDB/controller/test changes were deliberately not copied. This is a source and SDK
assessment, not a working adapter or a runtime parity claim.

## Recommendation

A local macOS native adapter is feasible. Adding it beside LLDB is a medium-to-large
engineering project; replacing everything LLDB supplies is a much larger project.
There is no single macOS API equivalent to the LLDB SB API or Windows debug-event API.
We would own a Mach exception debugger, process lifecycle, architecture-specific register
and stepping logic, and parts of a loader/symbol/unwind engine.

Start with an opt-in `MacOS Native` adapter for native arm64 local user processes.
Keep LLDB for fallback, remote targets, core dumps, backend commands, and unsupported
architectures until their replacements are explicitly validated. Select a native backend
as default only after the same controller-level tests pass for both adapters.

Planning estimates for one engineer familiar with C++ and this debugger, not measured
delivery promises: 1–2 weeks for a permission/lifecycle spike; another 4–8 weeks for a
useful arm64 local adapter with basic breakpoints and modules; 3–6 months total for a
production-quality local backend with broad testing, x86_64, unwind and watchpoint work.
Rosetta and full symbol/unwind parity may exceed that range. The first spike should revise
these estimates before committing to replacement.

## Existing integration makes this possible

`core/debugadapter.h` already separates the controller from backend methods. The UI,
Python API, live memory view, breakpoint management, and Binary Ninja instruction analysis
can remain in place. Implement a new `DebugAdapter` and `DebugAdapterType`, register it in
`core/debugger.cpp`, and add Apple-only sources in `core/CMakeLists.txt`.

`core/debugadaptertype.cpp:GetBestAdapterForCurrentSystem` currently returns `LLDB` on
every non-Windows host. Adding an adapter does not change the default automatically;
default selection and saved adapter settings need a deliberate migration policy.

LLDB linkage and packaging are currently unconditional for macOS in `core/CMakeLists.txt`.
`LldbCoreDumpAdapter` also uses LLDB. A native local adapter therefore does not by itself
remove the bundled library, debugserver, or associated build dependencies. Removing those
requires separate build options and feature decisions for both LLDB-backed adapters.

## Feature mapping

| Existing behavior | Native building blocks | Effort / remaining responsibility |
| --- | --- | --- |
| Launch with arguments, environment, working directory, terminal | `posix_spawn`, `POSIX_SPAWN_START_SUSPENDED`, spawn file actions, pipes/PTY | Medium: stop before user code, rollback failed launches, preserve launch settings, reap children |
| Attach, detach, pause, resume, terminate | `task_for_pid`, `ptrace(PT_ATTACHEXC)`, Mach suspension and exception replies, signals, process exit monitoring | High: multiple independent stop mechanisms and ownership rules; task access alone is not debugger attachment |
| Read/write memory | `mach_vm_read_overwrite`, `mach_vm_write`, `mach_vm_protect` | Low for ordinary data; high for executable-page patching, protection restoration and cache coherency |
| Memory map | `mach_vm_region_recurse`, region information, optional libproc metadata | Low/medium: submaps, permissions, backing paths and partial failures |
| Process and thread lists | libproc, `task_threads`, `thread_info(THREAD_IDENTIFIER_INFO)` | Low/medium: stable identity and Mach right cleanup; native thread IDs are 64-bit while this adapter boundary uses 32-bit IDs |
| Registers | `thread_get_state`, `thread_set_state`; ARM/x86 general, SIMD and debug flavors | Medium per architecture: register aliases/widths, PC/SP, vector registers and arm64e state accessors |
| Stop reason / asynchronous events | exception ports, generated MIG `mach_exc` server, Mach messages, BSD signal exceptions | High: classify reasons, hold/reply exceptions correctly, forward unhandled faults, deduplicate exit/detach events |
| Software breakpoints | instruction patches plus Mach breakpoint exceptions and architecture-specific stepping | High: original bytes, trap PC normalization, reinsert after stepping, shared/thread races, executable-page restrictions |
| Single instruction step | architecture debug state and exception handling | Medium/high: step exactly one selected thread, restore debug state and balance suspension counts |
| Step over | existing controller instruction-analysis fallback | Medium: works through `SupportFeature(DebugAdapterSupportStepOver)`, still requires correct temporary-breakpoint/thread semantics |
| Step return | unwind return address / backend implementation or controller changes | High: existing controller always calls the adapter, despite having an unused emulation branch |
| Modules, ASLR offsets, pending breakpoints | `task_info(TASK_DYLD_INFO)`, remote `dyld_all_image_infos`, Mach-O parsing | Medium/high: remote pointers, loader changes, shared cache, slides, module sizes and unloads |
| Frames and symbols | own remote unwind and symbol engine; Binary Ninja information where available | High: compact unwind/DWARF, omitted frame pointers, shared-cache symbols, dSYM discovery, optimized and arm64e code |
| Hardware breakpoints/watchpoints | ARM/x86 debug register state | High: slot constraints, access/size alignment, per-thread state, new threads and resume after hits |
| Stdin/stdout/stderr | pipes/PTY plus an owned I/O worker | Medium: cancellation, terminal behavior and output ordering |
| LLDB console and startup commands | no direct equivalent | Product change: new native commands or explicitly unsupported LLDB-specific settings |
| Remote debugging / core dumps | separate protocol and file-format implementations | Outside the first local native adapter |

The SDK examined was the active Xcode macOS SDK on an arm64 host. It contains
`PT_ATTACHEXC`, `POSIX_SPAWN_START_SUSPENDED`, `TASK_DYLD_INFO`,
`THREAD_IDENTIFIER_INFO`, `ARM_DEBUG_STATE64`, and arm64 thread-state PC helpers.
Header presence is compile-time evidence, not proof of target access or successful debugging.

## The difficult parts

**Permissions and signing.** Apple documents `com.apple.security.cs.debugger` as allowing
task-port acquisition for unsigned apps and third-party apps with `get-task-allow` enabled.
Hardened/protected targets remain subject to OS policy. A native backend does not expand
debuggable targets automatically. Entitlements attach to the executable hosting the code,
so putting the backend in debuggercore does not independently grant Binary Ninja access.
An owned, signed helper is an alternative that isolates privileges and backend failure,
but adds IPC, packaging, lifetime, and signing work. Validate actual application packaging
early; a command-line development environment is insufficient evidence.

**Exception ownership and teardown.** Save previous exception handlers, distinguish handled
debugger traps from target faults, preserve forwarding semantics, and restore handlers on
detach and partial failure. An outstanding exception reply and a task/thread suspension
are different reasons a target cannot run. Track both explicitly. Own and join exception,
I/O and exit-monitor workers; keep callbacks alive until producers stop. Define what happens
to an attached process when Binary Ninja or a helper crashes. Do not assume switching
backends solves the controller/adapter lock ordering.

**Breakpoint continuation.** Receiving a trap is only the first part. Continuing past an
installed breakpoint requires original-instruction execution and reinstallation while
other threads cannot slip through. User breakpoints, temporary step breakpoints, watchpoints,
signals, and newly created threads can overlap. Restore bytes, page protections and debug
state on every cleanup path. Native executable-page writes need their own validation on
signed/JIT/translated targets; ordinary memory writes do not prove breakpoint support.

**Architecture and unwind parity.** Begin with native arm64 and treat native x86_64 and
Rosetta x86_64 as separate validation milestones. ARM register state is not a transparent
replacement for translated x86 register state. A frame-pointer walk can be useful but is
not equivalent to `LldbAdapter::GetFramesOfThread`, which obtains frames, symbols and
function names from LLDB. Calling local `backtrace()` or local libunwind does not unwind
another task. Binary Ninja's existing analysis can reduce symbol/step-over work, but does
not provide complete remote stack recovery by itself.

**Specific controller gap.** At this revision,
`DebuggerController::StepReturnAndWaitInternal` uses `if (true /* StepReturnAvailable() */)`.
Merely declining `DebugAdapterSupportStepReturn` will not enable the fallback. Also,
`EmulateStepReturnAndWait` runs to analyzed return/tailcall instruction addresses; that is
not automatically equivalent to stopping in the caller after the current frame returns.
Implement native step-out or carefully define and fix the fallback semantics.

## Smaller alternative: use debugserver without liblldb

If the immediate aim is reducing in-process LLDB complexity, an RSP adapter talking to
debugserver deserves an earlier spike. debugserver already performs native Mach debugging;
we would replace the LLDB client layer while retaining its native process-control helper.
This is not a direct native-API adapter, and helper distribution/signing still needs review.

The existing `GdbAdapter` and `RspConnector` offer a starting point, but compatibility is
unproven. `GdbAdapter::LoadRegisterInfo` requires XML `target.xml`, its connection advertises
`xmlRegisters=i386`, and local `Attach` is unsupported. Audit debugserver's register discovery,
launch/attach packets, thread IDs, stop packets, module metadata and stepping behavior before
calling it a drop-in solution. This path still lacks LLDB's higher-level symbol/unwind engine.

## Proposed bounded first milestone

1. Validate task access in the intended signed Binary Ninja executable or owned helper using
   a small, self-built, debuggable arm64 fixture. Check denied attach produces a useful error
   and leaves the target unchanged.
2. Exercise launch/attach, initial stop, memory/register read, one instruction step, resume,
   pause, detach and exit. Prove exception restoration, Mach-right ownership and worker cleanup.
3. Add one software breakpoint and correct continuation with two fixture threads; verify
   cleanup restores bytes/protections and detach leaves the fixture running normally.
4. Integrate through the real `DebuggerController`, then repeat launch/detach/relaunch and
   quit/read races with callback draining. A standalone helper success is not controller validation.
5. Add module-relative breakpoints and honest feature reporting; compare observable stop
   reasons, registers, ASLR addresses and output against LLDB on the same fixtures.

Production gates additionally include signals/crashes, attach denial, process exec, dynamic
module loads, thread creation/exits, concurrent traps, optimized unwind, hardware watchpoints,
terminal I/O, native x86_64, supported macOS versions, signed-app distribution and Rosetta
if claimed. This assessment did not run targets, change entitlements, or test those gates.

## Primary references

- [Apple debugging-tool entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [Apple XNU ptrace definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [Apple XNU task interfaces](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [LLVM debugserver native process control](https://github.com/llvm/llvm-project/blob/main/lldb/tools/debugserver/source/MacOSX/MachProcess.mm)
- [LLVM debugserver exception dispatch](https://github.com/llvm/llvm-project/blob/main/lldb/tools/debugserver/source/MacOSX/MachException.cpp)
- [LLVM debugserver arm64 stepping and register handling](https://github.com/llvm/llvm-project/blob/main/lldb/tools/debugserver/source/MacOSX/arm64/DNBArchImplARM64.cpp)

Upstream `main` links were consulted on the assessment date and may change. Repository
findings above refer to the pinned debugger commit, not to upstream LLDB behavior inferred
from a different release.
