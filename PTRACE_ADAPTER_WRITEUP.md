# PTRACE adapter: what is done, what is wrong, and what is left

This document is the honest state of the Linux `ptrace()` debug adapter after Phases 0 to 5. It lists every problem,
drawback and open question that I know of, and ends with a checklist of what has to happen before the adapter can be
called finished.

How to read the labels:

- **Confirmed** means I reproduced it with a test that ran against a real process.
- **Suspected** means I found it by reading the code or reasoning, and did **not** reproduce it.
- **Cleared** means I suspected it and checked, and it was fine.
- Severity: **Blocker** (do not ship without fixing or deciding), **High**, **Medium**, **Low**.

---

## 1. Where things stand

Branch `claude/ptrace-adapter-integration-de3ad7`, 16 commits on top of `dev` (`61c7638`). None of them has a co-author
or attribution trailer.

| Commit | What |
| --- | --- |
| `d7005f8` | Your scaffold |
| `3541b8a` | Launch, run control, event thread (Phases 0 and 1) |
| `c7c8128` | Registers and memory (Phase 2) |
| `7bf8d4b` | Software and hardware breakpoints (Phase 3) |
| `ad42176` | Modules, symbols, frames, process list, dynamic loader breakpoint (Phase 4) |
| `cfad919` | Step over and step return (Phase 5) |
| `96efddf` | Fork and `vfork` children no longer inherit breakpoints (fixes C1) |
| `f605a6c` | Carry on through `exec`, with the `common.stopOnExec` setting (fixes C2) |
| `f439b34` | Fix overlapping interrupts (a bug found by stress testing, see S3) |
| `00351ac` | The `common.debugSignalHandlers` setting: stop at the handlers of signals |
| `69ce650` | Trust the analysis only inside the analyzed module; messages after an exec |
| `9c598b5` | The `common.resolveBreakpointsByNameOnExec` setting: find breakpoints by function name after an exec |
| `06535ef` | Check the symbols in the view again after an exec; the `common.loadSymbolsAfterExec` setting |
| `ace74b2` | Use the stop reasons of Linux for signals (found by reading the repo's tests) |
| `3784118` | Attach to a running process |
| `cf74e31` | The `launch.redirectFileDescriptors` setting: redirect any file descriptor of the target |

- **Pushed:** up to `ad42176`, to `origin/claude/ptrace-adapter-integration-de3ad7`. The eleven commits after it
  (`cfad919` to `cf74e31`, the last eleven in the table) are **not pushed**.
- **`native-linux-adapter`:** local copy is at `3541b8a`, `origin` still has `d7005f8`. Neither has Phases 2 to 5.
- **Not committed:** this file, and `test/ptrace_engine/` (the test harness, copied out of a temp directory so it is not
  lost).
- **Size:** 12 source files in `core/adapters/`, about 4,200 lines, plus `CMakeLists.txt` and `debugger.cpp`. The scaffold
  was 2 files.

What exists, by file:

| File | Job |
| --- | --- |
| `ptraceadapter.cpp/.h` | The `DebugAdapter` itself. Translates between Binary Ninja and the engine. Needs Binary Ninja. |
| `ptraceengine.cpp/.h` | One tracer thread that owns every `ptrace` and `waitpid` call, plus an event thread and a pty reader. No Binary Ninja. |
| `ptracearch.cpp/.h` | Per-architecture tables: registers, breakpoint instruction, debug registers. Only x86 and x86_64. |
| `ptraceelf.cpp/.h` | Reads ELF headers and symbol tables. |
| `ptracemodule.cpp/.h` | Groups `/proc/<pid>/maps` into modules, walks frame pointers, lists processes. |
| `ptracestep.cpp/.h` | The step-over and step-return state machine. |

**The short version.** The engine and helpers work and are well tested, but only on arm64 Linux in a container. The
adapter that plugs them into Binary Ninja has been compiled and reviewed, and never run. Nothing has ever run on x86.

---

## 2. The things most likely to hurt

Read these first.

1. **The adapter has never run inside Binary Ninja.** I could not build or run Binary Ninja on Linux here. Everything in
   `ptraceadapter.cpp` (settings, controller events, stop reasons, the entry-point breakpoint, the loader breakpoint
   handling, the `StepOver`/`StepReturn` entry points, `GetFramesOfThread`, module and symbol conversion) has only been
   compiled, never executed. *Blocker.*
2. **Nothing has been traced on x86 or x86_64.** The machine is arm64 and emulated x86 cannot ptrace. So the `0xCC`
   breakpoint, the PC rewind by one byte, the debug-register code, the x86 register sets, and the x86 single-step quirks
   are all unrun. Their *layouts* were checked against the real headers, which proves the offsets, not the behavior.
   *Blocker.*
3. **Fork and exec were blockers, and are now fixed** (C1 and C2, `96efddf` and `f605a6c`). They are covered by tests
   on arm64. The adapter half of the exec fix has never run in Binary Ninja, and the fixes were never run on x86, like
   everything else.
4. **Breakpoints in a library are lost if the library is unloaded and loaded again.** Suspected. See S1. *High.*
5. **Stack traces are frame-pointer only.** Frames stop early in code compiled without frame pointers, and the caller of
   a function is missed at its first instructions. See Appendix A. *High* for usability.

---

## 3. How it was tested

What was actually run, and how much it proves.

| What | How | Result | What it does **not** prove |
| --- | --- | --- | --- |
| Engine, arch, ELF, modules, stepper | 55 functional tests against real processes, on arm64 Linux (Ubuntu 24.04, Docker Desktop, kernel `7.0.12-linuxkit`) | All pass | Anything on x86, other kernels, other libcs |
| Races | Stress loops: 20 to 30 rounds of the breakpoint, stepping and thread tests, plus rounds pinned to 1 CPU and 2 CPUs | 0 failures. The 1-CPU run found one real hang early on (fixed) | Real-world workloads |
| Memory safety | AddressSanitizer + UBSan over the whole suite | 0 errors, 0 leaks. One use-after-free was found, and it was in the **test harness** (fixed) | The adapter, which is not in the harness |
| Data races | ThreadSanitizer over 24 of the tests | 0 warnings | The adapter, and the tests I did not include |
| Compile | g++ 13 and clang++ 18, `-std=c++20 -Wall -Wextra`, against the real Binary Ninja API headers | 0 warnings, 0 errors, all 6 `.cpp` files | A real CMake build and link. **Never linked.** |
| ELF reader | Compared with `readelf` on arm64, x86_64 and i386 files, including libc and libstdc++ | Identical on name, address and kind. The only difference is deliberate: I keep one entry per name and address where `readelf` lists versioned aliases with different sizes | Big-endian ELF (unsupported), unusual section layouts |
| x86 register tables | Every offset compared with `offsetof` on the real `user_regs_struct` and `user_fpregs_struct`, 64-bit and 32-bit; debug-register offsets 848 and 252 compared with `struct user` | All match | That the registers behave correctly on a live x86 process |
| macOS build | A full CMake configure and build of `debuggercore` on this Mac (Release, your dev Binary Ninja API, LLDB 22.1.8), from a copy of the worktree with the pinned flatbuffers added | Built, 0 warnings, 0 errors. The Linux-only ptrace files were correctly left out | The Linux build, the UI library, running it |
| Formatting | `clang-format` with the repo's `.clang-format` | Applied to the ptrace files. The existing adapters are much further from the config than mine | |

Not done at all:

- No test in the repo. The harness is in `test/ptrace_engine/` and is not part of any commit. See section 12.
- No `PtraceLinuxTest` in `test/debugger_test.py`, which is where `GdbMiLinuxTest` lives.
- No CI job.
- No manual run of the UI.

The tests use a **test-only aarch64 architecture table**, defined in the harness, because the machine is arm64. That is
also a strength: the engine has no x86 in it, and it works unchanged on a second architecture. But it means the shipping
x86 tables were never exercised at runtime.

---

## 4. Confirmed problems

Each of these has a test that reproduces it (`test/ptrace_engine`, the `repro_*` tests). C1 and C2 are fixed and their
tests are now ordinary tests.

### C1. A forked child inherits the breakpoints and dies. *Fixed in `96efddf`*

- **What it was:** a target forked, and the child called a function that had a breakpoint. The child was killed by
  `SIGTRAP` and the parent exited with `100 + 5 = 105`. `fork` copies the process memory, including the inserted `int3`
  bytes, and the child was not traced.
- **The fix:** the engine now sets `PTRACE_O_TRACEFORK`, `TRACEVFORK` and `TRACEVFORKDONE`. On a fork it waits for the
  child's first stop, writes the original bytes back over every inserted breakpoint in the child's memory, detaches
  the child, and lets the parent carry on. A `vfork` (and so `posix_spawn`) child shares the memory of its parent, so
  the breakpoints are taken out of the target until the parent gets the `VFORK_DONE` event, and then put back, after
  re-reading what is there. A breakpoint added during that window is kept aside until the same moment.
- **Tests:** the child that used to die now exits with 0 for `fork`, `vfork` and `posix_spawn` (which execs another
  program), and a multithreaded parent that forks 60 times reports exactly 60 hits of its own and no dead child. The
  parent's own breakpoint is checked to be back in place after each. Also clean under AddressSanitizer, UBSan and
  ThreadSanitizer, and pinned to one CPU.
- **What is still true:**
  - The child is **let go, not followed.** There is no follow-fork mode, and no setting for one.
  - During a `vfork`, the **other threads of the parent run with no breakpoints** until the child is done. GDB
    behaves the same way.
  - The engine assumes that a forked child does not inherit hardware debug registers. That is the documented Linux
    behavior, and it was only observed on arm64.
  - A `clone` that makes a new process without being a fork or a vfork (S5) is still not handled.
  - Not run on x86.

### C2. `execve` in the target breaks the session. *Fixed in `f605a6c`*

- **What it was:** after the target exec'd, the stop was reported as a plain `SIGTRAP`, memory at the PC could not be read
  (the `/proc/<pid>/mem` handle belonged to the old address space), and the breakpoint table listed breakpoints that
  no longer existed.
- **The engine now:** sets `PTRACE_O_TRACEEXEC`. On the exec event it drops every thread but the leader (the exec'ing
  thread becomes the leader, whichever thread it was), reopens the memory handle, throws away the breakpoint table, the
  hardware slots and any step in progress, detects the architecture again, and reports the stop with an `exec` flag.
- **The adapter now:** treats that stop like the first stop. It cancels any step, throws away its caches, puts the
  user's breakpoints back from a list it keeps by module and offset (so they resolve against the new program), sets up
  the loader breakpoint again, and posts the message `PTRACE: the process started <path>`. Then it **carries on**,
  unless the new setting **`common.stopOnExec`** is on. A **step that the exec cut short always stops**, so the user
  is not left waiting.
- **Tests (engine only):** memory readable after the exec; no stale breakpoint in the new image and none reported; a
  breakpoint added afterwards hits five times in the new program; exec from a **non-main thread** leaves one thread; the
  process can still be interrupted, single-stepped and killed afterwards. Clean under all three sanitizers and on one
  CPU.
- **What is still true:**
  - The **adapter half was never run in Binary Ninja** (the message, the setting, the re-applied breakpoints).
  - Only breakpoints that sit **in a module** are restored. A breakpoint by raw address in memory that is not in any
    module, or a hardware breakpoint like that, is lost at an exec.
  - The new program is **not the program that Binary Ninja analyzed**, so the view and the debugged process disagree
    afterwards. Part of that is now handled inside the adapter (see "The view mismatch after an exec" below), and the rest
    needs the controller. This needs to be in the docs.
  - The entry-point breakpoint (`stopAtEntryPoint`) is **not** set again for the new program, on purpose.
  - A change of architecture across an exec (32-bit to 64-bit, say) is re-detected, but never tried.
  - Not run on x86.

### C3. A detached target becomes a zombie. *Low to Medium* — **fixed**

- **Evidence:** after `Detach`, when the target exits by itself its state is `Z (zombie)`.
- **Why:** the target is still a child of the debugger process, and nothing calls `waitpid` on it after detaching.
- **Impact:** a zombie process stays until Binary Ninja exits, once per detach.
- **Fix (done):** after a detach, a small thread waits for the target and reaps it. Its status is kept, and
  `PtraceEngine::WaitForDetachedExit` gives it, which is how the detach tests see that a breakpoint did not stay behind. A
  double fork was not an option: `PTRACE_TRACEME` makes the parent the tracer. Attached targets are not our children, so
  they need nothing. Test: `detach_reaped`.

### C4. The pty has no window size, and it echoes input. *Medium* — **window size fixed, echo kept**

- **Evidence:** a target reads its terminal size and gets `rows=0 cols=0`. Writing `ping\n` to stdin comes back as
  `ping\r\ngot: ping\r\n`, so the typed line shows up twice, with `\r\n` line endings.
- **Impact:** programs that format output by terminal width misbehave. The console in the UI would show the echo unless
  it filters it.
- **Fix (done for the size):** the terminal is 24 rows by 80 columns (`LaunchOptions::rows` and `columns`; no setting yet).
  Test: `winsize`.
- **Echo, decided to keep:** the target's terminal echoes as any terminal does, which is also what LLDB does, because it
  passes the input to the terminal of the target as it is (`PutSTDIN`). Note that the Binary Ninja console shows the line
  that the user types by itself (`TargetScriptingInstance` only forwards it), so the typed line probably shows up twice.
  Whether the console adds the newline to what it sends is **not known**, since it was never run. Check in the UI, and if
  the echo is unwanted, turn it off with `termios` on the terminal, which changes what programs that ask for a password see.

### C5. Two arm64-only facts that matter if ARM is ever enabled. *Only relevant for ARM*

- **Evidence:** on arm64 the walked frame `sp` is not exact, and `StepReturn` needs its stack threshold raised by one
  or a deeper recursive call is taken for the current frame (the recursion test failed until I did this).
- **Why:** on x86 the caller's `sp` after a return is `fp + 16` and a deeper `ret` has a strictly lower `sp`. On arm64
  the frame size varies, and a deeper `ret` has an *equal* `sp` after its epilogue.
- **Status:** the adapter always passes the x86 rule, because ARM is not enabled. See section 11.

---

## 5. Suspected problems (not reproduced)

### S1. Breakpoints in a library are lost after unload and reload. *High*

A breakpoint set by module and offset is applied once and then removed from the pending list
(`ptraceadapter.cpp:1168`). If the library is closed (`dlclose`) and opened again, or another library is mapped at the same
address, the engine's breakpoint table still holds the old address with its old saved bytes. The new mapping has no
`int3`, so the breakpoint never hits, and `ReadMemory` would show the old bytes over the new contents.
**Fix:** notice unloads (the loader breakpoint already fires for them), drop the breakpoints of the unloaded module, and
put them back on the pending list.

### S2. Writing the instruction pointer while stopped in a restarted system call. *Medium*

If the target is interrupted inside a blocking system call, the registers hold "restart this syscall" state. Changing
`rip` afterwards (the "set IP" feature) can make the kernel back the PC up by two bytes on resume. GDB avoids this by
also setting `orig_rax` to `-1`. `WriteRegister` does not.

### S3. Overlapping interrupts. *Fixed in `f439b34`, and worse than I first thought*

I listed this as a low-severity "spurious pause". The stress tests then showed the real effect. Roughly **1 run in 150**
of the interrupt-while-hitting-breakpoints test failed, because two overlapping `Interrupt()` calls each sent a
`SIGSTOP`, and only the first was recognized as ours. The second came back as an ordinary stop by `SIGSTOP` of the
target, and the engine then **passed that `SIGSTOP` on to the target when it was resumed, which stopped the target
for good.**

- **The fix:** the signals on their way are counted, and only one is sent at a time. A `SIGSTOP` that arrives after the
  pause has already been given (by a breakpoint, say) is dropped quietly. Any reported stop answers a pending request.
- **The proof:** a new test (`interrupt_burst`) fires 100 interrupts from 4 threads per round and checks for exactly
  one pause and nothing left over. It fails 5 times out of 5 against the old logic and passes against the new. The
  original test then ran clean for 300 runs.
- **This is the kind of bug that only shows up under load.** It was there from the start, and the earlier stress
  rounds did not catch it. There may be others like it, which is the main argument for keeping the stress rounds in CI.

### S4. A failed resume can leave a thread marked as running. *Low*

`ResumeThread` clears `stopped` before it calls `ptrace` (`ptraceengine.cpp:854`), and only treats `ESRCH` as harmless.
Any other error leaves a stopped thread that the engine believes is running, which would later make a stop-all wait
forever.

### S5. A `clone` that is not a thread. *Medium to Low*

A `clone` without `CLONE_THREAD` (and that is not a fork or a vfork) creates a new *process*, but the engine adds it
to the thread map. Stop-all would then `tgkill` a thread of another process, which fails, and wait forever for a stop
that never comes. This is rare. (An `execve` from a non-main thread used to be listed here, and is now handled.)

### S6. A huge read request crashes Binary Ninja. *Medium*

`ReadMemory` allocates a buffer of the requested size (`ptraceadapter.cpp:736`). A bogus size throws `std::bad_alloc`.
The LLDB adapter has the same pattern, but it is still a crash. **Fix:** cap the size, or read in chunks.

### S7. The target never sees its own `SIGTRAP`. *Low, by design*

`SIGTRAP` is never passed on to the target, because the engine cannot tell its own breakpoint traps from the target's.
A program that installs a `SIGTRAP` handler (some anti-debug code) will not see its handler run.

### S8. Signal dispositions and the environment leak into the target. *Medium to Low*

The child resets the signal *mask* but not signal *dispositions*. Anything Binary Ninja (or an embedded Python) set to
`SIG_IGN`, such as `SIGPIPE`, is inherited by the target across `exec`. The environment is also inherited as is, which
includes anything Binary Ninja put into `LD_LIBRARY_PATH` or similar. LLDB inherits the environment too, but not
necessarily the ignored signals. Open file descriptors without `CLOEXEC` also leak in.

### S9. Job-control signals are unverified. *Low to Medium*

`SIGTSTP`, `SIGTTIN` and `SIGTTOU` cause group stops. The engine uses `PTRACE_TRACEME` and not `PTRACE_SEIZE`, so
group-stops are not reported cleanly, and I did not test what happens.

### S10. Nothing has a timeout. *Medium*

Adapter calls block until the tracer thread answers (`RunOnTracer`). If the tracer thread is stuck in a `waitpid` on a
thread that never stops (a process in uninterruptible sleep, for example), every call that reaches the engine hangs,
including `Quit`. The same goes for `DoKill`.

### S11. An exception on the tracer thread ends the process. *Low*

The tracer, event and pty threads have no exception guard. An allocation failure or a `std::system_error` from
thread creation calls `std::terminate`, which takes Binary Ninja with it.

### S12. Output can grow without limit. *Low*

Output from the target goes into an unbounded queue. A target that prints a lot while the event thread is blocked in the
UI callback grows memory.

### S13. The main executable's full symbol table is read on the event thread at the first stop. *Low*

`SetUpLoaderBreakpoint` calls `GetElf(exe)` (`ptraceadapter.cpp:808`) only to read the interpreter path, but that reads
every symbol. For a very large binary this delays the first stop. **Fix:** read only the headers.

### S14. The adapter's own step logic depends on Binary Ninja analysis. *Medium*

- `StepOver` decodes the instruction through Binary Ninja (`LLIL_CALL` as the first low-level instruction, the same test
  the controller uses). Calls that are not lifted as `LLIL_CALL` are stepped into.
- `StepReturn` takes the return instructions from the low-level IL of the function that the analysis knows. If the
  analysis has no function there (libc, for example), it falls back to frame pointers, with the problems in Appendix A. If the
  analysis is out of date or incomplete, a return site can be missed, and the step then runs until something else stops
  the target.
- A tail call ends the step at the tail-call jump, inside the callee, not in the caller.
- `StepOver` accepts a return when `sp >= sp_at_call - word size`. That rule was derived and tested on arm64 only.
  On x86 it is unverified.
- The work runs on the event thread so Binary Ninja analysis is never called under the controller's adapter lock. I
  believe that avoids the lock-order deadlock that the controller's comments warn about, but it was never run in Binary
  Ninja.

### S15. Hardware breakpoints have several limits. *Medium*

- They can only be added or removed while the target is **stopped** (the call fails while it runs).
- x86 has 4 slots, and sizes must be 1, 2, 4 or 8 with matching alignment.
- x86 has no read-only watchpoint, so *read* is turned into *access*.
- A hit does not say **which** breakpoint or watchpoint fired. All are reported as a generic breakpoint stop.
- The x86 implementation writes DR0 to DR7 through `PTRACE_POKEUSER`. Some virtual machines do not provide debug
  registers, and then this fails. It was never run.
- On x86 a data watchpoint traps after the access, on arm64 before it. The `DataTrapsBeforeAccess` flag handles that,
  and the arm64 side was tested with a test table only.

### S16. Resuming from a breakpoint address skips that breakpoint. *Low, matches GDB*

If a stop happens exactly on an address that has a breakpoint (a step landed on it, or an interrupt hit just before
it ran), the next resume steps over it rather than hitting it. GDB behaves the same way.

### S17. A 32-bit target on a 64-bit host is untested. *Medium*

The arch detection reads the ELF class, and the 32-bit tables were checked against `<sys/user.h>` from an `-m32` build. A
32-bit process traced from a 64-bit debugger goes through the kernel's compat register sets, which I never ran.

### S18. `SetActiveThreadId` posts no event. *Unknown*

It only changes the stored thread id. I did not check whether the controller refreshes registers and frames itself when
the user selects another thread.

---

## 6. Suspected and cleared

- **`SIGCHLD` ignored in the debugger process.** I worried that with `SIG_IGN` on `SIGCHLD` the kernel would reap the
  target and `waitpid` would fail with `ECHILD`, which the engine treats as "process gone, exit code 0". Test: with
  `SIGCHLD` ignored, the exit of a target that exits with 3 was reported as code 3. Not a problem. (The `ECHILD` path
  itself still exists at `ptraceengine.cpp:688`, so an unrelated cause of `ECHILD` would still be reported as an exit
  with code 0.)
- **Races in the engine and stepper.** ThreadSanitizer: 0 warnings across 24 tests.
- **Memory errors in the engine and stepper.** AddressSanitizer and UBSan: nothing.
- **Compiler warnings.** None with g++ 13 or clang++ 18 at `-Wall -Wextra`.
- **A relaunch leaks threads or file descriptors.** A 20-relaunch loop passes, and the destructor kills the target.

---

## 7. What is missing compared with the other adapters

| Feature | State |
| --- | --- |
| **Attach** to a running process | **Implemented** (`3784118`), see the notes below the table. Tested at engine level only. |
| Connect to a remote or debug server | Not supported by design. `CanConnect` is false. |
| Suspend or resume a single thread | Returns false. The engine is all-stop. |
| Debugging signal handlers | **Available, off by default:** the `common.debugSignalHandlers` setting. See the notes below the table. |
| Console commands (`InvokeBackendCommand`) | Returns an empty string. |
| Adapter properties (`GetProperty`, `SetProperty`) | Stubs. |
| Reverse execution, TTD | Not applicable. |
| Launch settings that LLDB has | Missing: terminal emulator, environment variables, follow-fork mode, initial commands. Redirection exists, and it is more general: `launch.redirectFileDescriptors` sets any descriptor, not only 0, 1 and 2. |
| Follow fork, catch fork/exec/clone/syscalls | None. A forked child is let go (C1). An exec is reported as a message, and `common.stopOnExec` stops on it (C2). |
| Signal handling policy | A fixed list of signals is passed on silently (`SIGCHLD`, `SIGALRM`, `SIGURG`, `SIGVTALRM`, `SIGPROF`, `SIGWINCH`, `SIGIO`). Everything else stops the target, and is delivered on resume. No settings. |
| Registers | General registers, x87 control and status words, `st0` to `st7`, `xmm0` to `xmm15`, `mxcsr`. **Missing:** `ymm`/`zmm`/mask registers, the x87 tag word, debug registers as registers, sub-registers such as `eax`, `ax`, `al`. I did not check whether the UI or the expression parser needs sub-registers. |
| Symbols | ELF `.symtab` and `.dynsym` only. **Missing:** DWARF, `.gnu_debugdata`, separate debug files, PLT stub symbols, TLS symbols. C++ names are **not demangled** (Binary Ninja's demangle call is deprecated, so I did not use it). |
| Unwinding | Frame pointers only. No `.eh_frame` (CFI). No signal frames. |
| Modules | ELF objects only. `[vdso]` is not a module, so frames inside it have no module or name. |
| Writing registers of a thread other than the active one | Not supported. |
| Architectures | x86 and x86_64 only, by design. |
| Platforms | Linux only. The CMake entry is Linux-only, and macOS and Windows builds are unaffected. |

---

### Notes on stopping at signal handlers

The setting is `common.debugSignalHandlers` (default **off**). "Interrupt" here means a **signal** and its handler (what a
program registers with `signal` or `sigaction`). Hardware interrupts are not visible to a debugger that runs in user space.

- **How it works.** When the setting is on and the target is resumed with a signal to deliver, the engine checks whether
  the target has a handler for it (the signal is listed as caught in `/proc/<pid>/status`). If so, it resumes that
  thread with a **single step and the signal**, which makes the kernel deliver the signal and stop the thread at the first
  instruction of the handler. The stop is reported with the signal as its reason, and a message says which signal and
  where. Signals that have no handler (default action or ignored) go by as before.
- **Two stops, or one.** A signal that already stops the target (such as `SIGUSR1`) still stops it where it is
  delivered, and the *next* resume then stops it at the handler. A signal that normally does not stop the target
  (`SIGCHLD`, `SIGALRM`, `SIGWINCH` and the other silent ones) stops only at the handler.
- **Tests (engine only):** the stop is exactly at the handler's first instruction with the signal number as its
  argument, for a `sigaction` handler with `SA_SIGINFO` and for a plain `signal()` handler; a silent signal stops only at
  its handler; a signal with no handler does not stop; a handler that runs in another thread; turning the setting off in
  the middle of a session; and a breakpoint in a handler still works with the setting off.
- **Limits and things to know:**
  - **Not run on x86.** On x86 the kernel reports this step with a different `si_code` than on arm64, and the engine goes
    around that by remembering that it asked for the step, but it was never run.
  - **Not run in Binary Ninja.** That includes how the UI shows the stop reason and the message.
  - **It can be noisy.** With the setting on, every `SIGCHLD` (each child that exits), `SIGALRM` timer tick or
    `SIGWINCH` that has a handler stops the target.
  - **Stepping is unchanged.** A single step already goes into a handler when a signal is delivered.
  - **What it tells you about the interrupted code is limited.** At the first instruction of a handler the frame walker
    (frame pointers only, Appendix A) cannot see the interrupted function or the signal trampoline, so the stack
    trace starts at the handler and skips them. Registers and memory are fine.
  - **A corner case can skip the stop.** If something else stops that same thread while it is on its way into the
    handler (an interrupt request, say), the handler stop is dropped and the handler runs on.
  - **The "has a handler" test is made when the thread is resumed.** If the handler is changed in between, the stop
    could be at the wrong place. This is rare.
  - **`sigaltstack` and `SA_ONSTACK` handlers** were not tried.
  - **The setting is read before every resume,** so a change applies at the next resume.

## The view mismatch after an exec

**What was observed** (a hand-run test, LLDB adapter, on this Mac, with two small programs where the first execs the second):

- The **memory map** changes after the exec. The controller refreshes it at every stop.
- The **module list** changes after the exec, for the same reason.
- A **breakpoint** set on the first program's `main` does **not** stop in the second program.

**What that means.** My first diagnosis said the module list would go stale, and that was wrong. What is left is that a breakpoint is a
module and an offset, which mean nothing in another program, and that the *view* stays bound to the first program (the controller
finds the analyzed module once per launch). LLDB and GDB do this differently: they look a breakpoint up again by its name.

**Scope decision: no changes to the controller, the Python API or the UI.** So this is only what an adapter can do:

| Problem | Adapter-only fix | State |
| --- | --- | --- |
| Step-out of a function used the analysis of the old program | The analysis is only trusted inside the analyzed module, and frame pointers are used elsewhere | Done (`69ce650`), never run in Binary Ninja |
| Nothing says that the view no longer applies | A message after the exec says so | Done (`69ce650`), never run in Binary Ninja |
| Nothing says which breakpoints are dead | A message lists the inactive ones | Done (`69ce650`), never run in Binary Ninja |
| A breakpoint does not apply to the new program | Optionally look up the ones at the start of a function by name in the new main executable (`common.resolveBreakpointsByNameOnExec`, off by default) | Done (`9c598b5`). The lookup and the flow through the engine are tested; the adapter glue was never run in Binary Ninja |
| The view is not rebased or re-bound to a new base | Needs the controller | **Not done, by decision** |
| Backend symbols loaded for the old modules stay in the view | After an exec, the symbols of modules that are gone are removed and the others are loaded again, through the controller's existing public methods (no change to it). The `common.loadSymbolsAfterExec` setting also loads the new program's symbols | Done, never run in Binary Ninja (see the notes below) |
| The breakpoint list in the UI still shows the dead breakpoints as active | Needs the controller and the UI | **Not done, by decision** |
| A banner in the UI | Needs the UI | **Not done, by decision**; the console message is the substitute |

Notes on checking the symbols again:

- **It uses what the controller already offers** (list the modules that have symbols loaded, remove a module's symbols, load a module's
  symbols) and does not change the controller. It hands the controller modules that are built from what the adapter sees, because the
  controller only brings its own list of modules up to date at the **next stop**, which an exec that carries on does not reach.
- **Only what the user loaded is touched.** Nothing is loaded that was not loaded before, unless `common.loadSymbolsAfterExec` is on
  (off by default), which loads the symbols of the new main program.
- **It runs on the event thread while the target is stopped**, with none of the adapter's own locks held, since it reaches into Binary
  Ninja. I reasoned through the lock order against the controller's comments and found no cycle, but it was **never run**, and it is the
  part of the change I would watch most closely.
- **Loading is slow for large modules** and delays the resume while it runs.
- The controller's own module list, and so its idea of the base, is still stale until the next stop.

Notes on the by-name lookup:

- Only breakpoints at the **very start of a function** are looked up. An offset inside a function means nothing in a different program.
- Only a name that is **exactly one function** in the new **main executable** is used. Libraries are not searched.
- It is off by default because it can put a stop in a program that is not the one the user meant. When it is off, the message after an exec
  says if it would have found some of the inactive breakpoints.
- It needs the symbol table of the new program. A stripped program has none.
- This is the same idea that GDB has. The LLDB and GDB MI adapters in this repo do nothing of the kind, so the same problem exists there, and was
  seen there. Fixing those adapters is not part of this work.

## Gaps found by reading the tests and docs of the repository

The LLDB and GDB MI adapters are held to `test/debugger_test.py`. I went through every test in it, and through the documented features, and
compared them with this adapter. To check what could be checked, I ran the **same scenarios at engine level on the repository's own Linux
test binaries** (dynamic PIE programs, arm64), which is how the conformance tests in the harness (`conf_*`) came about.

**Found by this, and fixed:** on Linux, `test_exception_segfault` and `test_exception_divzero` expect the stop reasons `SignalSegv` and
`SignalFpe`. This adapter used the shared signal table, which uses the numbers and names of macOS and gives `AccessViolation` and
`Calculation`, so both tests would have failed. Fixed in `ace74b2`, with a mapping by the `SIG*` constants (the LLDB adapter's own Linux
table uses BSD numbers, so it is right for these two signals only by luck).

**The tests, one by one** (`E` = the scenario passes at engine level on the repo's test binaries; the adapter itself was not run):

| Test | State |
| --- | --- |
| `test_repeated_use`, `test_step_into` | E: entry breakpoint by module and offset on a PIE program, three steps, run to the end, ten times |
| `test_breakpoint` | E for the entry breakpoint and `ip == entry`. Adding a breakpoint at address 0 fails as it should |
| `test_return_code` | E: exit codes 245, 255, 253, 0, 3, 7, 123 |
| `test_exception_segfault` | E, after the fix above |
| `test_exception_divzero` | Only runs on x86. Mapping is now right. **Not run** |
| `test_memory_read_write` | E: read, write at address 0 fails, overwrite, restore |
| `test_register_read_write` | E on arm64 with the test table. The x86 register names were checked, **never run** |
| `test_thread` | E: more than one thread after each pause |
| `test_restart` | E for kill and relaunch while running. The adapter's reuse of itself for a relaunch was not run |
| `test_load_module_symbols` | E: modules other than the main one have symbols. The load and remove logic is the controller's and was not run |
| `test_breakpoint_condition`, `test_breakpoints_list_and_repr` | Controller only, use `$rax`, `$rbx`. Not run |
| `test_go_and_wait_timeout` | Controller only. Killing a running target was tested at engine level |
| `test_debug_shared_library` | The pieces are tested. The flow (analyze a library, run another program, stop at the system entry point) was **not run** |
| `test_assembly_code` (x86_64) | **Not run.** Needs x86, and a static program that starts at its entry point |
| `test_hardware_breakpoint` | **Skipped on Linux upstream** ("not yet supported on Linux"), so nothing tests the x86 debug-register code |
| `test_attach` | **Skipped on Linux upstream.** Attach is implemented here, and tested at engine level |
| `test_remove_breakpoint_after_exit` | DbgEng only |
| `GdbMiLinuxTest.test_local_launch_stops_at_stripped_pie_entry_point` | The entry point comes from the file header, so it should work on a stripped program. **No equivalent test for this adapter** |

**No test class runs this adapter.** `debugger_test.py` has classes for LLDB, GDB MI, DbgEng and Windows Native, and none for PTRACE. It needs a
`PtraceLinuxTest` beside `GdbMiLinuxTest`, with `adapter_type = 'PTRACE'`, for x86_64 and 32-bit x86. This is the biggest gap, because it is the
only thing that would run the adapter through the controller.

**Features of the documentation that this adapter does not have:**

| Feature | State |
| --- | --- |
| Debugging **without opening a file** (a mapped view) | **Not offered.** `CanExecute` only accepts an ELF view, so a mapped or raw view cannot use this adapter. (GDB MI has the same limit, LLDB does not) |
| **Attach to a process** (the button) | Implemented. The pid comes from the controller, so the adapter has no `attach.pid` setting |
| **Backend commands** (the console, `execute_backend_command`) | Returns nothing. So no `image list`, `breakpoint list`, `process save-core` (dump files) and so on |
| **Terminal emulator** (`request_terminal_emulator`) | Not supported. The target always runs on a pty whose output goes to the console |
| **stdin, stdout and stderr redirection** (`launch.redirect*`) | Implemented as `launch.redirectFileDescriptors`, which takes any descriptor |
| **Environment variables** (`launch.environmentVariables`) | Not supported |
| **Fork handling** (`common.followForkMode`, parent or child) | The child is let go. There is no setting, and no way to follow it |
| **Initial commands** (`common.initialLLDBCommand`) | Not supported |
| Suspending and resuming one thread from the UI | Returns false |
| Remote and server targets, time travel, core dumps, kernel and Wine targets | Other adapters. Not applicable |

### Attach and redirection: what they do, and where they stop

**Attach** (`PtraceEngine::Attach`, `PtraceAdapter::Attach`):

- Every thread in `/proc/<pid>/task` gets `PTRACE_ATTACH`. The list is read again until no thread is new, because a thread
  can be created while the others are being stopped. A thread that exits meanwhile is skipped. The leader exiting is an
  error.
- A signal that reaches a thread before the `SIGSTOP` of the attach is passed on with `PTRACE_CONT`, and the thread is
  waited for again (up to 16 times). `SIGTRAP` is not passed on, because that would kill the target.
- The first stop is reported as the initial breakpoint. The entry-point breakpoint and "stop at the system entry point" do
  not apply, and the target is not resumed by itself. The loader breakpoint is set, so libraries loaded later are found.
- The thread that is reported steps over a breakpoint at its own PC when it is resumed, so a breakpoint placed where the
  target stopped is not hit at once. (Checked by `attach_step_at_breakpoint`.)
- The engine does not set `PTRACE_O_EXITKILL` for an attached target, and its destructor detaches instead of killing.
  So closing the debugger lets go of the target. **Quit still kills it**, as in the LLDB adapter.
- The target keeps its own terminal: no output reaches the console, and `WriteStdin` fails.
- The errors say "no such process", "already being traced by process N", and, for a refusal, the value of
  `kernel.yama.ptrace_scope` when it is not 0.
- **Not handled:** a target that is stopped by job control (`SIGSTOP`, `Ctrl-Z`) when it is attached to. The kernel lets the
  attach through, but the `SIGSTOP` that the attach sends may stay queued and show up as a stop after the first resume.
  Not tried. Also not tried: a target in a different PID namespace, or one that is a zombie.
- Tested at engine level, on arm64, as root, on targets that are not children (started with a double fork): threads, breakpoints,
  a breakpoint at the stopped PC, exit code of a target that is not a child, kill, detach, the destructor, both kinds of
  error, a target that creates and joins threads all the time (12 attaches), and a target that sleeps in a system call.
  The adapter's part was compiled on macOS but **never run**.

**`launch.redirectFileDescriptors`** (`PtraceEngine::FdRedirect`, `ParseFdRedirect`):

- Written like a shell: `0<in`, `1>out`, `2>>log`, `3<>data`, `2>&1`, `4>&-`. Applied in order, after the terminal is set up,
  so `["1>out", "2>&1"]` and `["2>&1", "1>out"]` are different, as in a shell. Checked by `redirect_stderr_merge`.
- The debugger opens the files, moves them above every descriptor that a redirect names, and the child `dup2`s them. So a
  file that cannot be opened is an error before the target starts, and the pipe that reports a failed `exec` cannot be
  overwritten by a redirect. Relative paths are relative to the working directory. Files are created with mode 0666 and
  the umask.
- A `>&M` where M is not open in the target fails in the child, and the message is the generic one:
  `failed to execute <path>: Bad file descriptor`.
- It replaces `launch.redirectStdin`, `launch.redirectStdout` and `launch.redirectStderr` of the LLDB adapter. It does not
  understand `&>file`, here-documents, pipes or quoting. Text after the path is part of the path.
- A descriptor that goes to a file no longer reaches the console. With `0` redirected, input written to the target is lost.
- Tested by 9 engine tests, including a check for leaked descriptors in the debugger over 25 launches (a failed one too).
  The setting was **never read by the adapter in Binary Ninja**.

## 8. Design drawbacks and trade-offs

1. **It re-implements things that a real debugger already does.** GDB and LLDB have battle-tested versions of stepping,
   breakpoint step-over, unwinding, symbol reading, and fork/exec handling. This adapter owns all of that now. The
   benefit is no dependency on LLDB or GDB. The cost is the list in sections 4 and 5, and that list will keep growing
   with real use.
2. **More files than the scaffold.** Two files became twelve, so the code can be tested without Binary Ninja. A reviewer
   may want that trimmed or renamed.
3. **Polling instead of events.** The tracer polls `waitpid` per thread with a backoff (yield 20 times, then sleep
   50 µs up to about 3 ms; `ptraceengine.cpp:633`). It costs 0.1% to 0.8% of a core while a target runs, and a stop can
   take up to a few milliseconds to be noticed after the target has been idle. A `pidfd` or `signalfd` design would be
   event-driven, but is more invasive in a process that Binary Ninja shares.
4. **One tracer thread does everything.** That is required by ptrace, but it means every register or thread query
   waits its turn. A register read costs about 23 µs.
5. **All-stop only.** When one thread stops, all threads stop. Only a single-step runs one thread alone.
6. **A separate event thread.** It exists because the controller blocks inside `PostDebuggerEvent`, and a callback that
   called back into the adapter would deadlock against the tracer. The price is a third and fourth thread (event, pty
   reader) and the ordering rules between them.
7. **The x86 restriction lives in one function** (`IsSupportedArchitecture`, `ptraceadapter.cpp:152`). That is what you
   asked for, but it also means nothing stops the adapter from being offered for an x86 view whose process is not x86.
8. **A duplicated function.** `ParseCommandLineArguments` is copied from `gdbmiadapter.cpp`, where it sits in an
   anonymous namespace.
9. **Scaffold leftovers.** `EventListener()` and `FixActiveThread()` are empty, kept only because they were declared.
   `Connect` returns false.
10. **`GetBestAdapterForCurrentSystem` still returns `"LLDB"` on Linux.** So this adapter is never the default. Is that
    what you want?
11. **The UI shows the raw identifier "PTRACE".** `ui/adapterdisplayname.h` only renames `X2WIN_RPC`. A friendlier name
    would need an entry there.
12. **`GetProcessList` returns every process on the machine**, including ones that cannot be attached.
13. **A launch without a stop.** With `debugger.stopAtSystemEntryPoint` off (the default) the target runs from the very
    first instruction until a breakpoint. If there is no entry-point breakpoint (`stopAtEntryPoint` off, or the module
    name does not match), it runs to the end.
14. **The first-stop path does a lot.** Architecture, entry breakpoint, loader breakpoint and pending breakpoints all
    happen on the event thread before the controller hears about the stop.
15. **`PTRACE_O_EXITKILL`.** If Binary Ninja crashes, the target is killed. That is the safe choice, but it is a
    behavior a user might not expect.

---

## 9. Performance (arm64 Linux in Docker, indicative only)

| Measurement | Result |
| --- | --- |
| Debugger CPU while a sleeping target runs | 0.8% of one core |
| Debugger CPU while a spinning target runs | 0.1% of one core |
| Single steps | 7,400 per second (135 µs each) |
| Breakpoint hit, resume and stop again | 6,200 per second (161 µs each) |
| One register set read | 23 µs |
| Reading memory | 17 GB/s in 1 MB reads, 0.3 µs for a 64-byte read |

These come from a VM on Apple silicon and will differ on real Linux hardware. A full `ReadAllRegisters` reads two
register sets, and the controller asks per thread, so a process with many threads pays per thread at every stop.

---

## 10. What the environment has to allow

- **Linux only.** `PTRACE_O_EXITKILL` needs kernel 3.8 or newer.
- **Ptrace permission.** The debugger launches its own child with `PTRACE_TRACEME`. That works under
  `kernel.yama.ptrace_scope` 0 and 1. Scope 2 allows it only with `CAP_SYS_PTRACE`, and scope 3 does not allow it at all.
  **Attach** needs scope 0, or a parent-child relation (scope 1), or `CAP_SYS_PTRACE`. When it is refused, the error says
  what the scope is. I only ran with whatever scope the Docker Desktop VM has and with `SYS_PTRACE` added, and as root,
  so the refusals of scope 1 and 2 were never seen. The error text for them is untested.
- **Containers.** They need `CAP_SYS_PTRACE`, and a seccomp profile that allows `ptrace` and `personality`. The default
  Docker profile blocks the `personality` flags that disable ASLR. The engine ignores that failure, so the target then
  simply runs with ASLR on.
- **`/proc`** has to be mounted, and `/proc/<pid>/mem` has to be writable by the tracer.
- **glibc** for the dynamic loader breakpoint (`_dl_debug_state` must be in the loader's dynamic symbols). With musl or a
  static executable, libraries that load later resolve their breakpoints only at the next stop.
- **The executable has to be an ELF** (`CanExecute`), of a supported architecture (`IsValidForData`).
- **The module files have to be readable by path** from the debugger's filesystem, for symbols. A file that was deleted
  (`(deleted)` is kept in the path) or is in another mount namespace gives no symbols.

---

## 11. What it takes to enable ARM

The engine has no x86 in it and was tested on arm64. Enabling arm64 means:

- [ ] An arm64 table in `ptracearch.cpp`: register layout (`x0` to `x30`, `sp`, `pc`, `pstate`; `NT_PRFPREG` for `v0` to
  `v31`), `pc`, `sp` and `fp` (`x29`) names, `BRK #0` as the breakpoint instruction, no PC rewind.
- [ ] A hardware-debug class for `NT_ARM_HW_BREAK` and `NT_ARM_HW_WATCH`, with `DataTrapsBeforeAccess()` true. The
  version in the harness works as a starting point.
- [ ] `EM_AARCH64` in `DetectPtraceArch`, and `aarch64` in `IsSupportedArchitecture`.
- [ ] A per-arch rule for `StepReturn`'s stack threshold (the adapter passes `sp` today, arm64 needs `sp + 1`), and for
  the caller's `sp` in frames (see C5).
- [ ] Frame-pointer unwinding assumes `[fp]` and `[fp + 8]`, which holds on arm64, so that part needs no change.
- [ ] Rerun the whole harness on arm64 against the real table, not the test table.

---

## 12. Checklist

### A. Must be done before anyone relies on it

- [ ] **Run the adapter inside Binary Ninja on x86_64 Linux.** Launch, stop at the entry point, step into, over and
  return, add and remove breakpoints, view registers, modules, memory map, symbols and threads, pause, quit, restart,
  detach. Nothing above `ptraceadapter.cpp` has been seen working.
- [ ] **Run the engine harness on real x86_64.** The harness needs an x86 version of its test architecture and its
  hand-decoded instructions (`bl`, `ret`, `x29`), then run it against the built-in x86 tables. This is the only way to
  test `0xCC`, the PC rewind, the debug registers, and the x86 single-step quirk on system calls.
- [ ] **Do a real build.** Full CMake build and link, both in the Binary Ninja internal build and the standalone build
  (`BN_API_PATH`), on Linux. Only syntax checks have been done.
- [x] **C1** (fork and `vfork`): fixed in `96efddf`.
- [x] **C2** (`execve`): fixed in `f605a6c`. Still to do: watch it work in Binary Ninja, and document that the view and the process disagree after an exec.
- [ ] **Add a `PtraceLinuxTest`** to `test/debugger_test.py`, like `GdbMiLinuxTest`, using `test/binaries/Linux-x86_64`.
- [ ] **Check the lock ordering** of `StepOver`/`StepReturn` and the event thread against the real controller.
- [ ] **Decide what to do about S1** (library breakpoints after unload).

### B. Should be done before a release

- [x] Implement **Attach** (`3784118`). Still to do: run it in the Binary Ninja UI, and try it as a user who is not root,
  under `ptrace_scope` 1.
- [x] Terminal window size (C4). The echo is kept; check in the UI whether it shows twice in the console.
- [ ] Fix `WriteRegister` for the instruction pointer during a restarted syscall (S2).
- [x] Reap detached targets (C3).
- [ ] Cap `ReadMemory` sizes (S6).
- [ ] Reset signal dispositions and close stray descriptors in the child (S8).
- [ ] Put a timeout or an escape hatch on the blocking waits (S10).
- [ ] Guard the worker threads against exceptions (S11).
- [ ] Handle non-thread clones (S5), and mark a failed resume (S4).
- [ ] Read only the ELF headers for the loader lookup (S13).
- [ ] **Documentation.** Update the adapter list at `docs/guide/index.md:415`, add a guide section for the adapter, its
  settings, its limits, and the permission requirements (section 10).
- [ ] Decide the **default adapter** on Linux (`core/debugadaptertype.cpp:77`) and the **display name** in the UI.
- [ ] State the frame-pointer limitation prominently in the docs, or implement `.eh_frame` unwinding (see Appendix A).
- [x] Redirection of file descriptors (`cf74e31`).
- [ ] Add the launch settings that users will expect: environment variables, follow-fork.
- [ ] Restore breakpoints that are not in a module after an exec (see the notes under C2), or say that they are lost.
- [ ] Watch the signal-handler stops in the Binary Ninja UI, and decide whether the frame walker should be improved so that
  the interrupted function is visible from inside a handler.
- [ ] Document the settings that this adapter adds (`launch.disableAslr`, `common.stopOnExec`,
  `common.debugSignalHandlers`, `common.resolveBreakpointsByNameOnExec`, `common.loadSymbolsAfterExec`).
- [ ] Watch the new messages after an exec in the Binary Ninja UI (view no longer applies, inactive breakpoints, breakpoints found by
  name, symbols refreshed), and try the two settings there. None of it has run in Binary Ninja. Load some symbols first, then exec, to see
  the refresh, and check for a hang while the symbols load (the lock order was only reasoned about).
- [ ] Decide whether the controller-side fixes (rebinding, cleanup of symbols, inactive breakpoints in the UI) are wanted after all.
  They were left out on purpose.
- [ ] Decide whether the LLDB and GDB MI adapters should get the same exec handling.
- [ ] Add a `PtraceLinuxTest` class to `test/debugger_test.py` for x86_64 and x86 (the only thing that runs the adapter through the
  controller), and run it on Linux with Binary Ninja.
- [ ] Let the adapter be offered for a mapped view (debugging without opening a file). `CanExecute` only accepts an ELF view today.
- [ ] Decide which of the other documented features are wanted: backend commands, redirection and environment, a follow-fork setting,
  the terminal emulator.
- [ ] Add a CI job that runs the harness (with `SYS_PTRACE`), and one that runs it under ASan and TSan.
- [ ] Review the hardware breakpoint story: allow it while running (stop, change, resume), and identify which slot hit.

### C. Nice to have

- [ ] `.eh_frame` (CFI) unwinding, which removes most of the frame-pointer limits.
- [ ] Event-driven waiting (`pidfd`) instead of polling.
- [ ] C++ demangling, DWARF and separate-debug-file symbols, `.gnu_debugdata`.
- [ ] `ymm`, `zmm` and mask registers, and sub-registers.
- [ ] Find the loader through `r_debug` instead of the `_dl_debug_state` symbol, so musl works.
- [ ] Catch fork, exec, clone and syscall events as user-visible stops.
- [ ] Per-signal handling settings.
- [ ] ARM (section 11).
- [ ] Share `ParseCommandLineArguments` with the GDB MI adapter.
- [ ] Remove the scaffold leftovers (`EventListener`, `FixActiveThread`).
- [ ] Trim or rename files if a reviewer wants fewer.

### D. Repository and process

- [ ] Decide the **target branch**. Today: pushed to `claude/ptrace-adapter-integration-de3ad7` up to Phase 4,
  the eleven commits after `ad42176` unpushed, `native-linux-adapter` not updated.
- [ ] Decide what goes in the repo: this file, and `test/ptrace_engine/` (which is not wired to CMake or CI).
- [ ] Clean up the harness: it needs `python3` for `elfref.sh`, its scripts assume `/src` and `/work` mounts, and its
  arm64 test architecture should be swapped or complemented by an x86 one.
- [ ] Open a pull request, with this document reduced to a description.
- [ ] Have someone review the ptrace code with a fresh eye. It is about 4,200 lines of concurrency and syscalls.

---

## Appendix A. Frame pointer unwinding, in detail

This is referred to from sections 2 and 5 and the checklist, and needs its own explanation.

- Frames stop at the first frame that is not valid, so code without frame pointers ends the trace early. Ubuntu builds
  its libraries with frame pointers, and the libc in my tests unwound fine, but other distributions do not.
- At the **first instruction of a function** (before `push rbp`) and just after the epilogue, the frame register still
  belongs to the caller, so the immediate caller is **missing** from the trace.
- The `sp` of outer frames is `fp + 16`, which is exact for the standard x86 layout and only a lower bound elsewhere.
- Return addresses are reported as they are, not as `pc - 1`, so a call at the very end of a function may be attributed
  to the next function.
- The trace is cut at 256 frames.
- `StepReturn` uses this only as its fallback, when Binary Ninja has no function at the PC.

---

## 13. How to reproduce everything

The harness is in `test/ptrace_engine/`. Its README has the command. Summary:

```bash
docker build -t ptrace-test test/ptrace_engine
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD/core/adapters:/src:ro" -v "$PWD/test/ptrace_engine:/work" ptrace-test bash /work/run_all.sh
```

The `repro_*` tests print the findings in sections 4 and 6. The `perf` test prints the numbers in section 9.

Compile check against the Binary Ninja API (what I used for "0 warnings"), run from `core/`:

```bash
g++ -std=c++20 -fsyntax-only -Wall -Wextra -I$BN_API -I$BN_API/vendor/fmt/include \
    adapters/ptraceadapter.cpp adapters/ptraceengine.cpp adapters/ptracearch.cpp \
    adapters/ptraceelf.cpp adapters/ptracemodule.cpp adapters/ptracestep.cpp
```

Do not add `-I.` for `core/`: `core/semaphore.h` shadows the system header.
