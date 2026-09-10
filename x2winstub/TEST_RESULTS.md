# X2Win test session results

Findings from a full pass over `test/x2winrpc_test.py` on Windows, including two real bugs found
and fixed and one still-open discrepancy that needs a maintainer to chase further. Cross-references
`STATUS.md` where relevant; read that first for the feature/issue numbering this file assumes.

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

## Full suite result: 15/17 pass

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

## Coverage still missing (not attempted this session)

Exception handling (segfault/illegal instruction/divide-by-zero), process exit code capture, shared
library load updating the module list, `restart`, conditional breakpoints, `StepOver` specifically, a
32-bit (x86) target variant, `ExecuteWithArgs` with real args/working directory, module+offset hardware
breakpoints and the pending-breakpoint-on-unloaded-module path, `InvokeBackendCommand`,
`SupportFeature`, `SetActiveThread(Id)`, and negative-path testing (connect failure, duplicate connect,
invalid pid attach).
