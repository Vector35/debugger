# Status

What this codebase currently supports, and the currently open issues in it. Each issue entry lists
where the problem lives, its symptom, and what's known about the root cause.

## Build status

Builds and runs against the remote Windows box this stub is developed/tested on. Whether it passes
this repo's Jenkins CI build is not yet confirmed.

## Current feature coverage

**Supported**, end to end (BN-core `X2WinRpcAdapter` <-> stub `WindowsDebugEngine`, over the FlatBuffers
RPC protocol):

- Connecting: Server mode two-phase (`ConnectToDebugServer` then `Launch`/`Attach`) and Target mode
  one-phase (`Connect` to a stub already running a target), matching `GdbAdapter`/`LldbAdapter`'s shapes.
- Launching a target exe on the remote Windows box (path/args/working directory), attaching to an
  existing pid, listing processes, detaching, quitting.
- Execution control: Go/continue, step into, step over, step return, break-into (interrupt).
- Breakpoints: software (set/remove) and hardware (set/remove). Stop reason reporting includes
  exception-driven stops (access violation, divide-by-zero, illegal instruction), not just
  breakpoints/steps.
- Memory: read, write, memory map query.
- Registers: read all, read one, write one.
- Threads: list, get/set active thread, suspend, resume.
- Modules: module list. Stack: frames-of-thread, stack pointer. Target architecture query.

**Not supported / not wired up:**

- Reverse step-over and Time Travel Debugging (TTD) -- `X2WinRpcAdapter::SupportFeature()`
  (`core/adapters/x2winrpcadapter.cpp`) reports both `false`; no stub-side support exists for either.
- `InvokeBackendCommand` -- always returns an empty string.
- `SupportFeature` is not exposed to the Python API.

## Known issues

### 1. Breakpoint on a running target: automated test fails, manual GUI use doesn't

**Where:** stub-side `ApplyBreakpoint()` (`debug/windows_debug_engine.cpp`).

**Symptom:** Run via the automated test (`test_breakpoint_set_on_running_target_triggers`), setting
a software breakpoint at an address inside the target's own running code is rejected every time:
`ReadProcessMemory()` fails with `ERROR_PARTIAL_COPY` (299) reading the original byte before writing
`INT3`. Reproduces regardless of address "hotness", delay before arming (0.1s-8s), launch vs.
attach, or target binary.

Manually reproducing the identical case through Binary Ninja's GUI (same adapter, same build, same
exact address, breakpoint set a few seconds after Continue) does not reproduce it -- the breakpoint
is accepted and triggers normally every time. Confirmed this isn't an address or code-path
difference: GUI's breakpoint toggle (`DebugControlsWidget::toggleBreakpoint()`, `ui/controlswidget.cpp`)
calls the exact same `AddBreakpoint(uint64_t)` path as the automated test when connected. Cause of
the discrepancy between the two is not known.

### 2. Cleanup after a rejected running-target breakpoint is slow

**Symptom:** Following issue #1, `Quit()`'s cleanup (pausing the still-running target) routinely
takes about a minute. Root cause not identified. A batch test runner that kills this on a tight
timeout can leave the next test in the batch spuriously stalling too (a leftover process not fully
torn down) -- give it a generous timeout, or run it last/in isolation.

### 3. Conditional breakpoints are slow to evaluate

**Where:** BN-core, `DebuggerController::ShouldSilentResumeAfterStop()` (generic, not X2Win-specific).

**Symptom:** Any breakpoint with a condition set takes 10+ seconds to resolve through
`go_and_wait()`, even when the condition is true on the very first hit. The RPC traffic itself
completes quickly; the delay is elsewhere in BN-core's result plumbing. Likely affects every
adapter, not just X2Win.

### 4. `StepReturn()` fails on the second call in a session

**Where:** stub-side `StepReturn()` (`debug/windows_debug_engine.cpp`), via `StackWalk64`.

**Symptom:** The first `step_return_and_wait()` in a session lands correctly; a second one (same
process, different return address) returns `InternalError`. Plausibly `StackWalk64` frame unwinding
depends on `.pdata`/`RUNTIME_FUNCTION` info that the current test binary (a hand-built
`asmtest.exe` with no real function prologues) doesn't have. Unconfirmed.

### 5. A breakpoint re-armed after `Restart()` can race the caller

**Where:** `X2WinRpcAdapter::AddBreakpoint(ModuleNameAndOffset&)`'s pending-breakpoint retry.

**Symptom:** A breakpoint added before `Restart()` gets automatically retried once the restarted
process's first stop event arrives, but that retry runs on a background thread -- a caller that
resumes immediately after `restart_and_wait()` returns can race past it before it's armed. Minor;
workaround is to re-add the breakpoint explicitly after restart instead of relying on the automatic
carry-over.

### 6. Resume after an exception can leave the GUI stuck, doesn't reproduce via script

**Where:** unknown.

**Symptom:** In Binary Ninja's GUI: open `asmtest.exe`, launch, let it stop at entry, click Resume
with no breakpoints set. The target runs (produces its output) and hits an access violation, but
Resume/Step buttons stop doing anything afterward -- Detach and Kill still work. Confirmed manually,
reproducibly, in the GUI.

Scripting the identical sequence (`launch_and_wait()`, then `go_and_wait()` with no breakpoints set)
does not reproduce it: the controller correctly reports `AccessViolation`, `dbg.running` correctly
flips back to `false`, and cleanup is instant. So the adapter/controller-level handling of this stop
is confirmed correct; whatever's wrong is specific to the interactive GUI path and not yet
identified.
