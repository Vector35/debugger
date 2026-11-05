# Native Linux ptrace adapter

The PTRACE adapter launches and attaches to local Linux x86 and x86-64 processes.
Production code lives in `core/adapters/ptrace/`. The standalone engine tests also
have a test-only ARM64 architecture table; that does not enable a shipping ARM64 adapter.

## Implementation

| Source pair | Responsibility |
| --- | --- |
| `ptraceadapter` | Binary Ninja adapter interface, event translation, settings, module-relative breakpoints and symbols |
| `ptraceengine` | Tracer-thread ownership, process/thread lifecycle, signals, registers, memory, breakpoint installation and terminal I/O |
| `ptracearch` | x86/x86-64 register layouts and hardware breakpoint programming |
| `ptraceelf` | ELF headers, interpreter and symbols through pinned ELFIO |
| `ptracemodule` | Module instances from process maps, frame-pointer walking and process listing |
| `ptracestep` | Step-over and step-return operations using temporary breakpoints |
| `ptracesignal` | Mapping Linux signals to debugger stop reasons |
| `ptracesyscall` | Syscall names and presentation |

Every ptrace request and wait runs on the tracer thread. Public engine methods
marshal requests to that thread. A separate event thread invokes the adapter;
terminal output is collected by an I/O thread.

## Callback lifetime

Before replacing a session, the controller calls `StopEventDelivery` outside
`AdapterAccessMutex`. The engine stops admitting events/tasks and joins the active
callback while its tracer and the adapter's stepper are still alive. Controller
shutdown drains callbacks before stopping its dispatcher or deleting controller state.
Direct adapter users must also avoid holding locks needed by callbacks when
replacing a session. Joining delivery from its own callback is rejected.

PTRACE opts out of waiting for public event callbacks, including controller-generated
notifications such as TargetStopped. The controller still applies
its own state and stop-channel updates synchronously before queueing public events.
This allows a public callback to request an asynchronous restart without blocking
the engine's delivery of the stop/exit needed by that restart. Other adapters retain
their existing synchronous delivery policy. Synchronous controller operations from
public callbacks remain unsupported; use the asynchronous API there.

The bare engine retains separate self-destruction/blocked-handler behavior for
standalone clients. That behavior does not provide lifetime protection for objects
captured by a client callback; the adapter uses explicit callback quiescence.

## Breakpoint and memory guarantees

Software breakpoint reads expose saved original bytes. Writes preserve installed
trap instructions, and update saved originals only for the prefix successfully
written to the target. A failed write can have a successful prefix; metadata tracks
that prefix rather than assuming a boolean failure means nothing changed.

`SuspendBreakpoints` and `RestoreBreakpoints` temporarily lift breakpoints around
an instruction. Failed restoration is retained for retry and queues an error for
the next event. Successful restoration queues no diagnostic. Detach aborts if its
breakpoint cleanup cannot complete.

The stepper retains temporary breakpoints whose release fails. Cleanup failure
stops the operation and blocks a new resume until cleanup succeeds; an exec, exit
or completed detach discards step state already removed by the engine.
Automatic continuation after initial, loader and exec stops checks resume failure
and reports an error and a stopped event rather than leaving the controller waiting.

## Signals and process control

Debugger-owned stop requests carry a siginfo tag. Standard SIGSTOP requests can
coalesce, so the engine does not count them as separate acknowledgments. Pause
admission and publication of a stopped state share a lock to prevent late requests
from leaking into the next continuation.

An externally requested SIGSTOP is reported as a debugger stop. Continue consumes
that stop instead of reinjecting SIGSTOP and entering a job-control group stop.
This is an explicit debugger continuation policy, not a complete shell job-control implementation.
Launch resets signal dispositions and the mask before exec so ignored signals in
the Binary Ninja host do not leak into the inferior. Attach preserves target state.
SIGTRAP ownership distinguishes debugger breakpoints/steps from target-generated
traps; see `test/ptrace_engine/SIGTRAP_OWNERSHIP.md`.

## Modules, symbols and limitations

A new offset-zero ELF mapping starts a separate module instance, even when another
instance of the same path is nearby. File identity includes device and inode when
extending mapped segments. The adapter preserves unique short names for surviving
instances. A unique short name selects an instance; a shared full path chooses the
lowest-address instance. Stored breakpoint locations retain the selected short name.
When moving a breakpoint out of a still-live mapping, cleanup restores its bytes;
bookkeeping-only discard is reserved for removed/replaced mappings.

ELFIO is a pinned, header-only submodule at `vendor/elfio`, alongside the existing
FlatBuffers submodule. Initialize submodules recursively. Linux packages include
its MIT notice. No libelf runtime or development package is required.

The ELF reader supports little-endian ELF32/ELF64 metadata. Symbol lookup may use
an earlier zero-sized function as a fallback. Unwinding follows frame pointers;
optimized code without them needs a different unwinder. Automatic shared-library
breakpoint reconciliation currently uses the glibc `_dl_debug_state` rendezvous.
Module segment grouping still uses a bounded-gap heuristic after recognizing
instance headers; arbitrary loader layouts are not a complete ELF loader model.

## Validation

`test/ptrace_engine/CMakeLists.txt` builds C++ drivers and C fixtures; pytest runs
isolated scenarios from `test/ptrace_engine_test.py`. The default gate includes
review regressions, fault injection, malformed ELF comparisons, temporary breakpoint
cleanup and simultaneous loader instances. Diagnostics and benchmarks are opt-in.
See `test/ptrace_engine/README.md` for build, Docker, sanitizer and stress commands.

`test/debugger_test.py` contains the native x86/x86-64 adapter/controller tests.
Native x86-64 Linux runs must also exercise 32-bit inferiors and real Binary Ninja
integration. ARM64 Docker results establish engine behavior only; a successful
syntax check or macOS core build does not substitute for shipping-adapter runtime tests.
