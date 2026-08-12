# Known Issues

Issues identified in this codebase but not yet fixed. Each entry lists where the problem lives, how
to reproduce it, and its root cause.

## 1. Detach can terminate a multi-threaded target instead of leaving it running

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

## 2. Breakpoints can carry over to an unrelated process after Detach + re-Attach

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

## 3. `--ip` / `--port` command-line flags are broken

**Where:** `main.cpp`, `ParseArgs()`.

**Symptom:** `--ip <value>` parses `<value>` as a port number and assigns it to the listen port,
never touching the listen address; `--port` is not recognized as a flag at all and causes the program
to exit with "unrecognized argument". In practice only the compiled-in defaults
(`0.0.0.0:31338`) are usable.

**Root cause:** The `--ip` branch in `ParseArgs()` operates on `options.listenPort` instead of
`options.listenIp`, and there is no corresponding `--port` branch.

**Status:** Not fixed. Low priority -- does not affect normal testing against the default
address/port.
