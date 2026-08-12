# Status

What this codebase currently supports, and the known issues in it that aren't fixed yet. Each issue
entry lists where the problem lives, how to reproduce it, and its root cause.

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
- Breakpoints: software (set/remove) and hardware (set/remove).
- Memory: read, write, memory map query.
- Registers: read all, read one, write one.
- Threads: list, get/set active thread, suspend, resume.
- Modules: module list. Stack: frames-of-thread, stack pointer. Target architecture query.

**Not supported / not wired up:**

- Reverse step-over and Time Travel Debugging (TTD) -- `X2WinRpcAdapter::SupportFeature()`
  (`core/adapters/x2winrpcadapter.cpp`) reports both `false`; no stub-side support exists for either.
- Everything else in this file, until each entry's `Status` says otherwise.

## Known issues

### 1. Detach can terminate a multi-threaded target instead of leaving it running

**Where:** `debug/windows_debug_engine.cpp`, `WindowsDebugEngine::DebugLoop()`.

**Symptom:** If more than one thread of the debuggee is executing the same code path (e.g. several
threads sharing a loop body) and a software breakpoint is set on that shared path, detaching while
stopped there terminates the whole target process instead of detaching cleanly. Single-threaded
targets, and breakpoints not on a path executed by multiple threads concurrently, detach as expected.
Reproducible with `testBinaries/helloworld_thread.exe`.

**Root cause:** `DebugLoop()`'s `Detach()`-triggered cleanup only calls `ContinueDebugEvent()` for the
single debug event most recently retrieved via `WaitForDebugEvent()`, then calls
`DebugActiveProcessStop()`. If a second thread concurrently raised the same breakpoint exception, its
debug event is still queued in the kernel, never retrieved, and therefore never continued.
`DebugActiveProcessStop()` requires every outstanding debug event to be continued before it can detach
cleanly; the thread left with a pending event causes the detach to instead tear the process down.

The same code (including the pending-event gap) exists in `core/adapters/windowsnativeadapter.cpp`
(BinaryView-hosted native Windows adapter this engine was ported from), which this issue does not
cover.

**Status:** Fix identified (drain and continue any pending debug events before calling
`DebugActiveProcessStop()`), not yet implemented.

### 2. Breakpoints can carry over to an unrelated process after Detach + re-Attach

**Where:** `debug/windows_debug_engine.cpp`, `WindowsDebugEngine::Reset()` /
`ApplyPendingBreakpoints()`.

**Symptom:** Not yet observed in practice, but reachable once a stub session's TCP connection is
reused across multiple Attach/Launch cycles (server mode) instead of reconnecting each time: a
breakpoint set while debugging one process can get silently re-applied, by raw address, to a
different, unrelated process attached afterward on the same connection.

**Root cause:** `Reset()` (run at the start of every `Execute()`/`Attach()`) does not clear
`m_breakpoints`/`m_pendingBreakpoints` -- it only marks entries inactive, so a later
`ApplyPendingBreakpoints()` re-applies them by their stored absolute address. This is correct for
restarting the *same* binary (addresses stay meaningful), but unsafe once the same engine instance can
be reused for an unrelated target, since nothing here checks whether the new process has anything to
do with the old one.

**Status:** Fix identified (clear breakpoint state fully in `Reset()` rather than only marking it
inactive; the BN-core client already re-sends every breakpoint it cares about on every successful
connect, so nothing is lost), not yet implemented.

### 3. Binary Ninja's UI doesn't show the target as running while it's running freely

**Where:** `core/adapters/x2winrpcadapter.cpp`, `X2WinRpcAdapter::Go()` (BN-core side, not the stub).

**Symptom:** After clicking Go/Continue (or the target otherwise resumes and doesn't immediately hit
a breakpoint), the Binary Ninja UI keeps showing whatever it displayed while stopped -- status bar
doesn't say "Running", register/stack/disassembly views don't refresh or grey out -- with no visual
indication anything is happening on the remote target, until either a breakpoint is eventually hit
(the next `TargetStoppedEvent` arrives and everything jumps to the new state at once) or the target
exits. If the target runs for a long time without hitting a breakpoint, the UI looks identical to being
idle/stopped the entire time.

**Root cause:** `X2WinRpcAdapter::Go()` sends `GoRequest` and returns whether the stub *accepted* the
resume request, but never calls `PostDebuggerEvent()` with a `ResumeEventType` event on success.
`DebuggerController::ApplyOwnStateForEvent()` (`core/debuggercontroller.cpp`) is what flips
`m_state`'s execution status to `DebugAdapterRunningStatus` on `ResumeEventType` (also on
`StepIntoEventType`/`StepOverEventType`, which is why stepping doesn't have this problem), and both
`DebuggerStatusBarWidget::updateStatusText()` (`ui/statusbar.cpp`, sets "Running") and
`DebuggerWidget`'s `ResumeEventType` handler (`ui/ui.cpp`, `refreshCurrentViewContents()`) key off the
same event. With no event posted, none of that fires until the next event this adapter *does* post
(`TargetStoppedEvent`/`TargetExitedEventType`), so the whole "running" interval is invisible to the UI.
`GdbAdapter::Go()` (`core/adapters/gdbadapter.cpp`) posts `ResumeEventType` as the very first thing it
does, before it actually resumes the target -- `X2WinRpcAdapter::Go()` is missing the equivalent call.
Note `X2WinRpcAdapter::BreakInto()` already posts `ResumeEventType` on success (existing code, unrelated
to this fix), which is a separate, already-correct case.

**Status:** Fix identified (post a `ResumeEventType` `DebuggerEvent` at the start of
`X2WinRpcAdapter::Go()`, mirroring `GdbAdapter::Go()`), not yet implemented.
