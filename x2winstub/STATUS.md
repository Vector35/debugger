# Windows Remote debugging status

What this codebase currently supports, and the currently open issues in it. Each issue entry lists
where the problem lives, its symptom, and what's known about the root cause.

## Build status

The Windows build runs the local client/server integration suite through `scripts/build.py`.
See `TEST_RESULTS.md` for validated results and the distinction between a local Windows run
and an actual Jenkins execution.

## Current feature coverage

**Supported**, end to end (BN-core `X2WinRpcAdapter` <-> stub `WindowsDebugEngine`, over the FlatBuffers
RPC protocol):

- Connecting: Server mode two-phase (`ConnectToDebugServer` then `Launch`/`Attach`) and Target mode
  one-phase (`Connect` to a stub already running a target), matching `GdbAdapter`/`LldbAdapter`'s shapes.
- Launching a target exe on the remote Windows box (path/args/working directory), attaching to an
  existing pid, listing processes, detaching, quitting.
- Execution control: Go/continue, step into, step over, step return, break-into (interrupt).
- Breakpoints: software (set/remove) and hardware (set/remove), including setting a breakpoint on a
  target that is already running. Stop reason reporting includes exception-driven stops (access
  violation, divide-by-zero, illegal instruction), not just breakpoints/steps.
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

### 1. Conditional breakpoints are slow to evaluate

**Where:** BN-core, `DebuggerController::ShouldSilentResumeAfterStop()` and the register-hint
computation it triggers (`DebuggerRegisters::GetAllRegisters()` / `DebuggerController::
GetAddressInformation()`, both in `core/debuggerstate.cpp` / `core/debuggercontroller.cpp`). Not
X2Win-specific -- affects every adapter.

**Symptom:** Any breakpoint stop, condition or not, takes 10+ seconds to resolve through
`go_and_wait()`, even when a condition is true on the very first hit. Root cause: on every stop,
`ShouldSilentResumeAfterStop()` populates register display hints via `GetAddressInformation()` for
every distinct register value -- each of which does live `ReadMemory()` calls plus analysis-database
lookups -- even though the only caller on this path (`AddRegisterValuesToExpressionParser()`) reads
just the raw register values and never uses the hint. This is core code shared by all adapters, not
part of x2winstub.

### 2. `StepReturn()` on a target with no real function prologues can pick an unrelated address

**Where:** stub-side `WindowsDebugEngine::StepReturn()` / `GetReturnAddress()`
(`debug/windows_debug_engine.cpp`).

**Symptom:** `StepReturn()` needs the address the current function will return to. When
`StackWalk64` can't unwind a second frame (no `.pdata`/unwind info -- e.g. hand-written test code
with no real prologue), it falls back to scanning the stack for a plausible return address (a value
that lands inside a known module and is immediately preceded by a `call` instruction). If the thread
is genuinely not inside any nested call at that moment (sitting at a call instruction that hasn't
executed yet, rather than inside a callee), there is no correct answer for "the current function's
return address" to find, and the scan can return an unrelated, older return address further up the
stack instead. Calling `StepReturn()` only while actually inside a called function's body gives the
correct result in the x64 integration case. Separate x86/WOW64 testing also
reproduced an incorrect return target while genuinely inside a callee: an
unreliable older frame from `StackWalk64` was accepted before consulting the
correct immediate return address. The same behavior was reproduced with the
native Windows adapter. Thus entering the callee fixes the test sequence, but
does not resolve all engine-side unwind failures.

### 3. A breakpoint re-armed after `Restart()` can race the caller

**Where:** `X2WinRpcAdapter::AddBreakpoint(ModuleNameAndOffset&)`'s pending-breakpoint retry.

**Symptom:** A breakpoint added before `Restart()` gets automatically retried once the restarted
process's first stop event arrives, but that retry runs on a background thread -- a caller that
resumes immediately after `restart_and_wait()` returns can race past it before it's armed. Minor;
workaround is to re-add the breakpoint explicitly after restart instead of relying on the automatic
carry-over.

### 4. Resume after an exception can leave the GUI stuck, doesn't reproduce via script

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

### 5. Intermittent Quit timeout during integration-test cleanup

One Windows-local run completed the x64 StepReturn assertions but remained
connected after `quit_and_wait(10000)` in cleanup. A focused rerun and the next
full run passed, but a subsequent full run hit the same cleanup timeout after
the attach test. Root cause is not established; the cleanup assertion remains
enabled so CI reports a recurrence. See `TEST_RESULTS.md` for validation scope.

The failing attach-run client log shows two `BreakIntoRequest`s without an
intervening stop notification. Only the cleanup fallback's direct server Quit
produces an exit event, after which the queued adapter Quit runs. This points
to pause/interrupt sequencing rather than establishing a StepReturn defect;
the exact race still needs isolation.
