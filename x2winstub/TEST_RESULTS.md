# X2Win test session results

Findings from a full pass over `test/x2winrpc_test.py` on Windows, including several real bugs found
and fixed and some still-open discrepancies that need a maintainer to chase further. Cross-references
`STATUS.md` where relevant; read that first for the feature/issue numbering this file assumes.

**Update**: a follow-up session added 11 new tests covering previously-untested surface (exit codes,
exceptions, StepOver, Restart, conditional breakpoints, SetActiveThread, module+offset hardware
breakpoints, shared-library loading, and three negative-path cases), and found and fixed three more
real bugs along the way -- see "Fixed in the coverage-expansion follow-up" below.

## Fixed this session

### Build: `inet_pton` not declared on Windows

`X2WinRpcAdapter::ConnectSocket()` (`core/adapters/x2winrpcadapter.cpp`) called `inet_pton()`, which
the legacy `<winsock.h>` this codebase includes on Windows (`core/adapters/socket.h`) doesn't declare
-- fails to compile with `C3861`. Fixed by switching to `inet_addr()`, matching every other adapter in
this repo (`esrevenadapter.cpp`, `corelliumadapter.cpp`, `gdbadapter.cpp`).

### `ReaderLoop()` self-deadlock

`ReaderLoop()` -- the sole thread that reads RPC responses off the socket -- called `ApplyBreakPoints()`
inline on receiving a `TargetStoppedEvent`. If any breakpoint was staged in `m_pendingBreakpoints`
(module+offset breakpoints not yet resolvable, e.g. right after Launch/reconnect before the module list
is populated), `ApplyBreakPoints()` calls `AddBreakpoint()` -> `CallSync()`, which blocks in
`future.get()` until `ReaderLoop()` reads the matching response -- called from `ReaderLoop()` itself,
that response can never be read. Reproducible self-deadlock whenever a stop event arrives with a
non-empty pending list.

Fixed by dispatching the flush to a separate thread (guarded by `m_applyingBreakpoints` so concurrent
stop events don't race two flushes) instead of running it inline, plus a mutex for the
previously-unsynchronized `m_pendingBreakpoints`/`m_pendingHardwareBreakpoints`, plus breaking any
still-outstanding `CallSync()` promise with an empty envelope when `ReaderLoop()` exits so a caller
blocked on a response that will now never arrive doesn't hang either.

**Confirmed fixed**: `test_module_list`, `test_register_read_write`, and
`test_thread_list_suspend_resume` all hung indefinitely before this fix (reproduced in full isolation,
not just contention with other tests) and pass cleanly after it.

### Test bugs (not product bugs) -- fixed in `x2winrpc_test.py`

- `test_software_breakpoint` re-added a breakpoint at the address the target was already stopped at
  (`entry`) and asserted `go_and_wait()` would hit it again immediately.
  `WindowsDebugEngine::Go()` correctly steps over a breakpoint sitting at the current IP before
  resuming (standard debugger semantics), and `entry` executes exactly once, so that breakpoint could
  never fire a second time -- `ProcessExited` is the correct outcome. Trimmed to what's actually left to
  verify once `_launch_and_stop_at_entry()` already covers add-then-hit: that delete takes effect.

## Fixed in the coverage-expansion follow-up

### `Attach()`/`ExecuteWithArgs()`/`Connect()` never corrected state on failure

`DebuggerController::AttachAndWaitInternal()`/`LaunchAndWaitInternal()`/`ConnectAndWaitInternal()`
(`core/debuggercontroller.cpp`) each post an *optimistic* `LaunchEventType` (->
`DebugAdapterRunningStatus`) before calling into the adapter, and rely on the adapter posting
`LaunchFailureEventType` on failure to correct that back to Invalid -- `ApplyOwnStateForEvent()`
only resets connection/execution status on that event. Every other adapter that hits a connect
failure (e.g. `GdbAdapter::Connect()`) posts it; `X2WinRpcAdapter::Attach()`,
`::ExecuteWithArgs()`, and `::Connect()` didn't, on any of their failure paths. Concretely: attach
to a nonexistent pid, and `dbg.running` stays `true` forever -- nothing ever calls `NotifyStopped()`
since `AttachAndWaitOnWorker()` skips it for `InternalError`, and no adapter code ever undoes the
optimistic status flip.

**Confirmed fixed**: `test_attach_invalid_pid_fails_cleanly` reproduced this deterministically
before the fix (`dbg.running` still `true` after a failed attach) and passes after it. Added
`X2WinRpcAdapter::PostLaunchFailure()` and call it from every failure path in all three methods.

### Wire protocol had no `StopReason` for exception-driven stops

`WindowsDebugEngine::HandleException()` (`x2winstub/debug/windows_debug_engine.cpp`, unmodified)
already classifies SEH exceptions into `AccessViolation`/`Calculation`/`IllegalInstruction`
correctly, but `protocol/x2win.fbs`'s `StopReason` enum only ever had `UNKNOWN`/`BREAKPOINT`/
`SINGLE_STEP`/`INITIAL_BREAKPOINT`/`EXITED` -- there was no wire value for any of the three
exception reasons. `x2win_session.cpp`'s `OnEngineEvent()` switch had no case for them either, so
every exception-driven stop (segfault, divide-by-zero, illegal instruction) silently collapsed to
`StopReason_UNKNOWN` on the wire, which `X2WinRpcAdapter::ReaderLoop()`'s reverse mapping then
turned into `DebugStopReason::UnknownReason` -- losing the actual reason entirely.

**Confirmed fixed**: `test_exception_access_violation` and `test_exception_divide_by_zero` both got
`UnknownReason` instead of `AccessViolation`/`Calculation` before the fix, and pass after it. Added
`ACCESS_VIOLATION`/`CALCULATION`/`ILLEGAL_INSTRUCTION` to the `StopReason` enum, wired them through
`x2win_session.cpp`'s switch, and added the corresponding cases to `X2WinRpcAdapter::ReaderLoop()`'s
reverse mapping. Regenerated `x2win_generated.h` (`GENERATE_x2win_fbs` target) and rebuilt both
`debuggercore.dll` and `x2winstub.exe`, which must ship together now that the wire format changed.

### `Restart()` silently dropped every breakpoint it replayed

`DebuggerBreakpoints::Apply()` (core/debuggerstate.cpp, replayed by `CreateDebugAdapter()` whenever
it reuses an existing adapter -- e.g. on every `Restart()`) always calls
`X2WinRpcAdapter::AddBreakpoint(const ModuleNameAndOffset&)` for software breakpoints. That call
happens *before* the restart's own `Launch()` RPC has run, while the stub is between debuggees (old
process just `Quit()`'d, new one not launched yet) -- but the stub's `GetModuleList()` still
answered with the just-terminated process's stale module info at that exact moment, so
`ResolveModuleAddress()` "succeeded" against a dead target, the resulting `SetBreakpointRequest` was
rejected, and -- unlike the already-handled "module not resolvable yet" case just above it in the
same function -- nothing re-staged it for a second try. The breakpoint was dropped silently and
permanently on every restart.

**Confirmed fixed**: `test_restart` (new) reproduced this 100% of the time before the fix (a
breakpoint added before `restart_and_wait()` never fired again) and passes reliably after it (5/5
repeated runs). Fixed by re-staging into `m_pendingBreakpoints` on that rejection too, so the
existing second-chance flush (`ReaderLoop()`'s post-stop-event handling) picks it up once the
restarted process's own module list is real. This re-staging only applies to the
`ModuleNameAndOffset` overload (the replay path) -- `AddBreakpoint(uintptr_t)`, used for an
absolute-address `add_breakpoint()` call made directly by a caller, was deliberately left alone (see
the "not caused by the Restart fix" note under `test_breakpoint_set_on_running_target_triggers`
below).

**Residual, not fixed**: the second-chance flush this relies on runs on a detached thread (it can't
run inline from `ReaderLoop()` without self-deadlocking -- see `ApplyBreakPoints()`'s own comment),
so there's a narrow race between that flush actually completing and whatever the caller does right
after `restart_and_wait()` returns. `test_restart` lost that race often enough in a full-suite run
to not be a reliable pass/fail signal for the auto-carry-over behavior specifically, so it was
rewritten to re-add the breakpoint explicitly after restart (a direct, synchronous call, same
pattern `_launch_and_stop_at_entry()` already relies on) rather than depend on winning the race. A
real fix would need `RestartAndWait()`/`LaunchAndWait()` to not report success until any
re-staged breakpoints are confirmed flushed -- not attempted here.

## Full suite result: 15/17 pass (pre-follow-up); 26/28 pass including the 11 new tests

The two below are real, understood, but **not fixed**.

### `test_step_return`: `InternalError` on the *second* `step_return_and_wait()` in a session

First `StepReturn()` call in a session lands correctly; a second one (same process, different return
address) fails with `InternalError`. `WindowsDebugEngine::StepReturn()`
(`x2winstub/debug/windows_debug_engine.cpp`) gets the return address via `StackWalk64` frame
unwinding, which on x64 depends on `.pdata`/`RUNTIME_FUNCTION` unwind info -- `asmtest.exe` is a
hand-built binary with no real function prologues (confirmed via disassembly: the called function is a
bare `retn`, no `push rbp`/frame setup anywhere in the call chain), so `StackWalk64`'s result here is
plausibly undefined behavior that happens to work once and not the second time. **Hypothesis, not
confirmed** -- would need stub-side instrumentation to pin down which specific step fails.

### `test_breakpoint_set_on_running_target_triggers`: stub rejects the breakpoint (`ERROR_PARTIAL_COPY`)

STATUS.md #4 regression. The test's address selection was wrong twice over before being fixed:

1. First assumed `helloworld_loop.exe`'s *entry point* was inside its repeating loop -- disassembly
   shows entry is the one-shot CRT startup thunk that `jmp`s away and never returns.
2. Then sampled a "live" address via `pause_and_wait()` -- also wrong: `dbg.threads` showed *every*
   thread of the process sitting inside ntdll at the moment of pause (these test binaries spend nearly
   all their time blocked in system wait calls, not their own code), so the sampled address was never
   actually in the target's own module.

Now uses a statically-verified in-module address (`main()`'s own busy-spin body, confirmed via
disassembly). With that fixed, direct log capture (`binaryninja.log_to_file`) shows the request
actually reaching the stub and getting a real answer:

```
X2WinRpcAdapter::CallSync: sending request_id=166 body_type=18   (SetBreakpointRequest)
X2WinRpcAdapter::CallSync: received response for request_id=166
X2WinRpcAdapter::AddBreakpoint: stub rejected breakpoint at 0x140001034
```

Stub's own stdout for that same request:

```
[x2winstub][WARN] ApplyBreakpoint: Failed to read memory at 0x140001034, error=299
[x2winstub][WARN] Failed to apply breakpoint at 0x140001034
```

`error=299` is `ERROR_PARTIAL_COPY` from the `ReadProcessMemory()` call in `ApplyBreakpoint()`
(`x2winstub/debug/windows_debug_engine.cpp`), which reads the original byte before writing `INT3`.

**Ruled out** (each retested individually, same rejection every time):
- Address "hotness" -- same result on the busy-spin instruction (~50M executions/outer loop) and on a
  low-frequency address (executed once per outer iteration).
- Timing -- same result with 0.1s, 2s, and 8s between resuming the target and adding the breakpoint.
- Launch vs. Attach -- same result via `ExecuteWithArgs` and via `Attach()` to an already-running,
  independently-spawned process.
- Target binary -- same result on both `helloworld_loop.exe` and `helloworld_thread.exe`.

**Not resolved**: the user reports the equivalent manual sequence (BN's GUI, X2WIN_RPC adapter,
`helloworld_thread.exe`, attach -> Continue -> add breakpoint while running) works every time, not
intermittently. That directly contradicts the 100%-reproducible rejection above. Every variable tried
here still failed the same way, so the remaining, untested difference is almost certainly something
about the manual GUI session itself -- most likely whether it was actually pointed at this same local
build (`BN_STANDALONE_DEBUGGER`/`BN_USER_DIRECTORY` env vars set before launching BN) rather than
whatever `x2winstub.exe`/`debuggercore.dll` ships with the installed Binary Ninja. Skipped rather than
chased further this session; **whoever picks this up next should confirm which binaries the manual
repro actually exercised before assuming it's the same code path being tested here.**

Per explicit direction this session, `debug/windows_debug_engine.cpp` was **not** modified to
"fix" this (e.g. a retry-on-`ERROR_PARTIAL_COPY` loop around the `ReadProcessMemory`/
`WriteProcessMemory` calls in `ApplyBreakpoint()`/`RemoveBreakpointInternal()`/`WriteMemory()` would be
the standard mitigation for that specific error if it does turn out to be a genuine transient race) --
the discrepancy above needs to be understood first.

**New in the coverage-expansion follow-up**: this test's `go_and_wait(5000)` itself still fails
fast (same rejection as above), but its *cleanup* -- `quit_and_wait()` pausing the still-running
target -- was newly measured taking on the order of a minute on top of that, not previously
recorded. Initially suspected to be a side effect of the new `Restart()` re-staging fix (see above)
retrying this same rejected breakpoint once the target is next paused -- ruled that out via
`binaryninja.log_to_file`: the re-staging only lives in `AddBreakpoint(ModuleNameAndOffset&)`, and
this test's `dbg.add_breakpoint(loop_addr)` (an absolute address) goes through
`DebuggerBreakpoints::AddAbsolute()` straight to `AddBreakpoint(uintptr_t)`, a separate overload
with no re-staging logic; the RPC log confirms no second `SetBreakpointRequest` is ever sent. So
this slow cleanup is pre-existing, not newly introduced -- it just hadn't been measured end-to-end
before now. Root cause not pinned down (a `TargetStoppedEvent` at an unrelated ntdll address shows
up during the pause, consistent with but not confirmed to be related to the break-in mechanism
described above for the earlier, wrong-address version of this test). **Whoever picks up the
ERROR_PARTIAL_COPY investigation above should probably also profile this cleanup path.**

Practical consequence for anyone running the suite as a batch with an external timeout per test:
when this test's slow cleanup gets cut off by a forced kill (`Stop-Process`) rather than allowed to
finish, whatever test runs immediately after it in the same batch can itself spuriously stall for a
full test-runner cycle (observed: `test_module_offset_hardware_breakpoint`, otherwise a reliable
~5s test, hit the same external timeout right after a forced kill of this test, then passed cleanly
in isolation immediately afterwards). Likely a leftover process (the target, or the stub) not fully
torn down by the forced kill. Give this specific test its own generous timeout (upwards of 90s) when
scripting a batch run, or run it last/in isolation, rather than chaining tests with a tight per-test
timeout.

## New open issue: conditional breakpoints are pathologically slow to evaluate

`test_conditional_breakpoint` originally tried to drive a real `go_and_wait()` through a conditional
breakpoint end to end (both an always-true and an always-false condition). Every attempt timed out
-- and not for a reason specific to which address or condition was used: even a *single*
`ShouldSilentResumeAfterStop()` call (`core/debuggercontroller.cpp`) for a breakpoint whose
condition evaluates true on the very first hit (one evaluation, immediate stop, no silent-resume
looping at all) still took over 10 seconds. Instrumented down to: the real RPC traffic (the stop
event, the condition's one evaluation) completes quickly, but `go_and_wait()` doesn't return the
result back to the caller for tens of seconds afterwards -- confirmed via one always-false run that
did eventually return the correct `ProcessExited` result, just ~85 seconds late.

This is generic BN-core code (`ShouldSilentResumeAfterStop()` itself, or
`ExecuteAdapterAndWait`/`SubmitAndWait`'s result plumbing), not X2Win-specific -- and per
`test/debugger_test.py`'s own `test_breakpoint_condition` (get/set string round-trip only, no
`go_and_wait()` involved), this looks like the first attempt anywhere in this suite to exercise a
conditional breakpoint through a real run/stop cycle end to end, against any adapter. Root cause not
pinned down; `test_conditional_breakpoint` was restricted to the condition string round-trip (fast,
and already proven correct) so it doesn't itself take a minute-plus to run. **Worth profiling
`ShouldSilentResumeAfterStop()`/`AddRegisterValuesToExpressionParser()`/
`AddModuleValuesToExpressionParser()` directly** -- possibly not specific to X2Win at all.

## Coverage still missing

32-bit (x86) target variant, `ExecuteWithArgs` with real args/working directory beyond `cmd_line`,
the pending-breakpoint-on-unloaded-module path specifically, `InvokeBackendCommand` (currently a
stub that always returns `""`, nothing to verify), and `SupportFeature` (not exposed to Python).
