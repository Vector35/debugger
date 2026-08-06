# x2winstub is now built on WindowsDebugEngine (ported from WindowsNativeAdapter), not a hand-rolled debug loop

## What changed

`debug/debug_loop.cpp`/`.h` (the hand-rolled `x2win::RunDebugLoop`/`AddBreakpoint`/`ReadTargetMemory`/...
free-function API + global state) has been replaced wholesale:

- `debug/debug_types.h` -- plain structs/enums (DebugModule, DebugBreakpoint, DebugRegister, etc.)
  copied from `core/debugadapter.h`/`core/debuggercommon.h` in the BN-core repo, with no Binary
  Ninja dependency.
- `debug/windows_debug_engine.h`/`.cpp` -- `WindowsDebugEngine`, a straight port of
  `core/adapters/windowsnativeadapter.cpp` (`BinaryNinjaDebugger::WindowsNativeAdapter`) with the
  BN-only seams removed (no `BinaryView`, no `Settings`, no BN logging, no `DebugAdapter` base
  class -- see the file's header comment for the full list of what changed and why). This gives
  x2winstub the *complete* Windows native debug engine for free: software + hardware breakpoints,
  step into/over/return, register read/write, memory map, WOW64 handling, thread suspend/resume,
  stack unwinding -- none of which the old `debug_loop.cpp` had.
- `x2win_session.h`/`.cpp` -- `X2WinStubSession`, the new class that owns one `WindowsDebugEngine`
  and does the `x2win::Envelope` proto parsing/dispatch (`HandleRequest`), replacing the inline
  `switch` that used to live in `main.cpp::HandleClient`. It also translates the engine's stop
  events into `TargetStoppedEvent` envelopes written back over the connection.
- `main.cpp` -- rewritten to construct an `X2WinStubSession` per connection (or, in target mode,
  before the connection even exists) and delegate to it, instead of calling the old free functions.
  The launch-then-wait-for-initial-stop-then-accept-connection ordering in target mode is preserved
  exactly (see `X2WinStubSession::WaitForFirstStop()`).
- `CMakeLists.txt` -- updated sources (`debug/windows_debug_engine.cpp`, `x2win_session.cpp`,
  dropped `debug/debug_loop.cpp`) and added `dbghelp` to `target_link_libraries` (needed for
  `GetFramesOfThread`'s `StackWalk64`, which the old debug_loop never used).

The old `debug_loop.cpp`/`.h` were renamed to `*.superseded` on this box (not deleted) in case
anything here needs cross-checking against the old behavior.

## Why

Instead of hand-adding each new RPC to a from-scratch WinAPI debug loop (the pattern this repo's
`read_memory_task.md` etc. followed), directly reuse the already-complete, already-tested Windows
debug engine BN's own `WindowsNativeAdapter` class provides. Confirmed with the mentor that this
should be a genuinely standalone port (no Binary Ninja core/license dependency on this box), not a
thin wrapper that links `binaryninjaapi`/`binaryninjacore` -- see the earlier rejected proposal to
do that (would have required a licensed BN headless core just to construct a `BinaryView`, mostly
unused since `WindowsNativeAdapter`'s own logic barely touches BinaryView-derived data).

## What you need to do

1. Rebuild `x2winstub` with the updated `CMakeLists.txt` (new sources + `dbghelp` link).
2. Run the verification checklist below.
3. If something doesn't compile (MSVC-specific issue I couldn't catch from a Mac with no Windows
   headers available), the fix is almost certainly narrowly scoped to `windows_debug_engine.cpp`/
   `.h` or `x2win_session.cpp`/`.h` -- those are the newly-ported files. `net/*` and the CMake
   scaffolding are unchanged apart from the sources list.

## Verification checklist

1. **Target mode**, launching a test exe (e.g. `helloworld.exe`):
   - `x2winstub.exe target <path>` should print "launching ... waiting for initial breakpoint...",
     then "target stopped at initial breakpoint, waiting for adapter..." once the OS loader
     breakpoint is hit -- *before* any client has connected (same as before the port).
   - Connect a test client; it should immediately receive a `TargetStoppedEvent{reason:
     STOP_REASON_INITIAL_BREAKPOINT}`.
   - `GetTargetArchRequest` -> `"x86_64"` (or `"x86"` for a 32-bit/WOW64 target).
   - `SetBreakpointRequest{address}` -> `success=true`, non-zero `breakpoint_id`.
   - `GoRequest` -> `success=true`; the breakpoint should be hit and reported as a
     `TargetStoppedEvent{reason: STOP_REASON_BREAKPOINT, address}` matching the address you set.
   - `ReadMemoryRequest` at the breakpoint address -- confirm the returned byte is the *original*
     instruction byte, not `0xCC` (the breakpoint-hiding logic ported from `ReadMemory`'s shadow
     copy in `WindowsNativeAdapter`).
   - `ReadMemoryRequest` at an unmapped address (e.g. `0x1`) -> `success=false`, empty `data`.
   - `GetModuleListRequest` -> at least the main module, with a sane base address.
   - `DetachRequest` then `QuitRequest` -- both should return `success=true` without hanging.
2. **Server mode**: `ConnectServerRequest` -> `success=true`; `GetTargetArchRequest` still works
   with no target attached (defaults to `"x86_64"`).
3. Disconnect the client mid-session with a target still running -- confirm the debuggee gets
   terminated (`RunRequestLoop`'s disconnect cleanup in `main.cpp`), not left orphaned.
4. Compare a full session's log output side by side with a pre-port run if you still have one, to
   catch any behavioral drift beyond what's called out in the file header comments.
