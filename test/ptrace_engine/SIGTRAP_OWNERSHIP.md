# SIGTRAP ownership and signal-handler debugging

## Goal

The ptrace engine must distinguish traps created by the debugger from `SIGTRAP`s created by the target. A target may
use `raise(SIGTRAP)`, `kill`/`tgkill`, or an inline trap instruction as ordinary control flow, including moving useful
code into its `SIGTRAP` handler.

This distinction is independent of `common.debugSignalHandlers`:

- A debugger-owned trap is consumed by the debugger and is never delivered to the target.
- A target-owned trap is retained in `ThreadInfo::pendingSignal` and delivered on the next resume.
- With `common.debugSignalHandlers` disabled, delivery is normal: a caught signal runs its handler and an uncaught
  signal terminates the target.
- With `common.debugSignalHandlers` enabled, a caught signal is delivered with `PTRACE_SINGLESTEP`, allowing the
  debugger to report the beginning of the target's handler before continuing through it.

## Ownership rules

Classification must use both kernel metadata and debugger state. `SIGTRAP` or `siginfo_t::si_code` alone is not an
ownership indication.

The rules, in priority order, are:

1. A nonzero ptrace event in the wait status is a kernel/debugger event and is not signal-delivery.
2. `TRAP_TRACE` is debugger-owned only when the thread has an outstanding debugger step, including the step used to
   enter a signal handler.
3. A software-breakpoint trap is debugger-owned when its adjusted PC matches an active software-breakpoint record.
4. `TRAP_HWBKPT` is debugger-owned when the debugger has an active hardware breakpoint/watchpoint.
5. A trap from a breakpoint that was removed while another thread was running is an internal race and is resumed.
6. Every other SIGTRAP is target-owned and must be placed in `pendingSignal`.

User-generated `siginfo` codes such as `SI_USER`, `SI_TKILL`, and `SI_QUEUE` take the target-owned path, even if the
stopped PC happens to be adjacent to a debugger breakpoint. For `SI_USER`, a nonzero sender PID distinguishes an
actual sent signal from the code-zero, pid-zero trap that AArch64 can produce for a debugger-requested step around
kernel/vDSO code. CPU-generated breakpoint codes are matched against the debugger's breakpoint records and trap
instruction bytes.

Linux can preserve the original `si_code` when SIGTRAP itself is delivered with `PTRACE_SINGLESTEP`. For the specific
outstanding handler-entry operation, a changed PC is therefore also accepted as proof that the kernel entered the
handler. This state is recorded only after ptrace accepts the resume request and is cleared by the matching stop.

If `PTRACE_GETSIGINFO` fails, the engine must not silently turn the failure into an arbitrary classification. It may
use unambiguous outstanding debugger state, but an otherwise unknown trap must be reported conservatively rather than
silently consumed.

## Breakpoint precedence and unavoidable ambiguity

An active debugger software breakpoint takes precedence when a CPU breakpoint trap occurs at its patched address.
This includes code that calls `raise(SIGTRAP)` from an instruction on which the user has placed a debugger breakpoint:
the debugger breakpoint is handled first, and after it is stepped over the later raised signal is independently
classified and delivered.

Linux does not provide a provenance tag for the trap opcode itself. If the debugger patched an address and the target
then writes the identical trap opcode to that exact address, the resulting CPU trap is indistinguishable from the
debugger's patch. The deterministic policy is to treat it as debugger-owned while the debugger breakpoint record is
active. Targets that self-modify a breakpointed address should be analyzed with a hardware execute breakpoint instead.

## Adapter reporting

Trap ownership must survive into `PtraceEngine::Event`. The adapter must report target-owned SIGTRAP as a signal stop,
not as a generic breakpoint. Software and hardware breakpoints and debugger single-steps retain their existing stop
reasons.

## Attach behavior

While waiting for the attach-generated `SIGSTOP`, the attach bootstrap must not discard an unrelated SIGTRAP. Any
signal-delivery stop observed during this window must be reinjected or retained for normal classification.

## Regression coverage

The engine harness should cover:

- `raise(SIGTRAP)` with handler debugging disabled and enabled;
- an inline `int3`/`brk` with handler debugging disabled and enabled;
- an unhandled target SIGTRAP terminating the target;
- a debugger breakpoint in code that later raises SIGTRAP;
- a target SIGTRAP encountered while a debugger step is outstanding;
- a debugger breakpoint while the target has installed a SIGTRAP handler, proving the breakpoint is not reinjected;
- recently removed breakpoint races remaining internal;
- a SIGTRAP racing with attach.
