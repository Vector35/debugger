# Adapter fuzzer

A stateful fuzzer for the debug adapters (LLDB, GDB MI, PTRACE, DbgEng, Windows Native). It drives each adapter
through the controller's Python API with random sequences of operations on up to three sessions at once, checks
properties that hold for every adapter, and reports each distinct failure with the shortest sequence of operations
that reproduces it.

## Running it

```sh
uv run --locked python -m pytest --fuzz test/adapter_fuzz_test.py          # every adapter this host can run
ADAPTER_FUZZ_LENGTH=long uv run --locked python -m pytest --fuzz test/adapter_fuzz_test.py
```

`test/adapter_fuzz_harness_test.py`, `test/adapter_fuzz_session_test.py` and `test/adapter_fuzz_engine_test.py` test the
fuzzer itself, with no adapter and in seconds: that each check fails when its property does not hold, how failures are
grouped, shrunk and reported, and how the engine draws, runs and replays examples.

The default length (`ci`, 10 examples) takes about a minute when nothing fails; `long` runs 200. A failure, a
crash or a hang of the debugger does not stop the run. The test fails at the end if anything was found, with the
report as its message. It is not part of the build's default test run, because it needs minutes and many
processes.

Only one campaign runs at a time on a machine; a second one stops at once and names the process that holds the
lock, since two at once start many debug servers and targets and report failures that belong to neither.

## Reading a report

```
[1] AssertionError: the example opened 2 pipes or sockets and kept them after a session ended by exit or detach
    seen 15 time(s); detected in check_nothing_is_left
    shortest sequence found (3 of 3 steps, 7 replays):
      start(program='short_program')
      s0.launch()
      s0.detach()
```

- `seen` is how many examples failed this way. Failures are grouped by where they were detected and what they said,
  with numbers removed; a crash by the signal and the Python frames of the crashing thread.
- The sequence is the shortest one that still fails the same way, found by replaying the failing sequence in fresh
  processes with steps removed and numbers simplified. `s0.` is the session a step acted on.
- `did not reproduce when replayed` means the failure depends on timing or on earlier examples in the same process,
  so the sequence shown is the whole example, unshrunk.
- A crash prints what `faulthandler` wrote. The log of every worker, including the operation log that survives a
  crash, is in the directory the first line names, and `report.json` there has the same report in JSON.

## Settings

All are environment variables, read and validated together by `settings.py`; a bad value fails with a message that
names the variable. Workers inherit the environment, so every process sees the same values.

| Variable | Meaning |
|---|---|
| `ADAPTER_FUZZ_LENGTH` | `ci` (10 examples, 15 steps each) or `long` (200 examples, 40 steps) |
| `ADAPTER_FUZZ_EXAMPLES` | number of examples, instead of the length's |
| `ADAPTER_FUZZ_SEED` | first seed; a batch uses the seed plus its number, so a run can be repeated |
| `ADAPTER_FUZZ_SHRINK` | replays one failure may use to get smaller (default 25, 0 to skip) |
| `ADAPTER_FUZZ_SESSIONS` | sessions that may run at once (default 3) |
| `ADAPTER_FUZZ_PATIENCE` | multiplies every timeout and wait; use 2 or more on a slow or loaded machine |
| `ADAPTER_FUZZ_DIR` | where the logs go (default: a new temporary directory) |
| `ADAPTER_FUZZ_REPORT` | also write the JSON report to this file |
| `ADAPTER_FUZZ_ALLOW_PARALLEL=1` | let two campaigns run at once |
| `ADAPTER_FUZZ_LOCK` | a different lock file |

`test_fuzz` carries the `fuzz` pytest marker, and `test/conftest.py` skips them, with a message
that names the option, unless `--fuzz` is passed. Without it, `pytest test` runs the quick tests of the fuzzer itself
and skips the campaigns.

Workers run with `BN_DISABLE_USER_SETTINGS=true` unless the environment already sets it (the build and
`scripts/run_local_tests.py` set it the same way). The debugger settings that an adapter's profile changes are then
never written to your settings file, even when a hang or crash skips the restore on teardown.

## What it checks

After every operation: the controller state agrees with what happened, no call blocks past its timeout, a session
that ended left no process or events behind, state that was set (breakpoints, conditions, arguments, the active
thread) is still there, callbacks' reads do not fail, and memory and registers can be read while stopped. When an
example ends: no process from an ended session is left, and no pipe or socket that the debugger opened is still
open. Writes to registers and memory are read back and undone, so the program still runs unchanged. A write the
adapter should refuse (to unmapped memory) must leave the stack as it was.

Three checks depend on wall-clock windows: events that arrive after a session ended, a process that is still alive
after the wait, and a pipe that is still open after the settle time. Their messages say so; repeat the run with
`ADAPTER_FUZZ_PATIENCE=2` to rule out a loaded machine. The pipe count includes pipes opened by unrelated threads of
the host process, which is why the leak check compares against a count taken when the example began, not against
zero.

## How a run works

`campaign.py` starts worker processes (`worker.py`), each running a batch of examples with `engine.py`. Example `i` of
a batch with seed `s` draws from `random.Random(f's:i')`, so one example can be reproduced alone. An example runs the
starting operations, then up to the length's number of steps: each step draws one of the enabled operations in
proportion to its weight, then draws that operation's arguments, runs it, and runs the checks. A failing operation or check
is recorded (`recording.py`) and ends only its own example; the sessions it used are discarded, their targets
killed, and the next example starts clean. Every operation is written to a log before it runs, so when a bug
kills a worker the campaign knows what the example was doing, reports the crash, and starts another worker.
Failures are grouped, then shrunk by replaying their steps in fresh workers.

## Layout

| Module | |
|---|---|
| `machine.py` | the state machine: sessions, hooks, per-operation and end-of-example checks |
| `session.py` | one controller: the operations that start, resume and end its target, and the checks that follow every operation (`observe()` records how the session ended, `assert_consistent()` asserts) |
| `tracking.py` | what a session keeps track of: its controller (`ControllerHandle`, unusable once the session is dropped), breakpoints, event callbacks, how it ended, the target's process, the launch setup, and the pool of views |
| `lifecycle_ops.py`, `callback_ops.py`, `breakpoint_ops.py`, `thread_ops.py`, `data_ops.py`, `setup_ops.py`, `fault_ops.py` | the operations, one module per area |
| `operations.py` | `OperationModule`, the declared base of the operation modules (what they use of the machine), and `session_operation`, which declares an operation on one session |
| `recording.py` | operation and check declarations, failure recording, the operation log, and `WorkerFiles` (a worker's files, all in the one directory that `ADAPTER_FUZZ_WORKER_DIR` names) |
| `draws.py`, `engine.py` | the argument generators (`one_of`, `integers`, `booleans`), and running or replaying examples |
| `settings.py`, `common.py` | the `ADAPTER_FUZZ_*` variables as one validated object, and the names and timeouts derived from it |
| `campaign.py`, `worker.py`, `lock.py` | running workers and the campaign lock; `assert_clean` |
| `failures.py`, `shrink.py`, `report.py` | what a failure is and its key, reducing a failing sequence, text and JSON reports |
| `profile.py` | the adapters, what each cannot do, and the test programs |
| `callbacks.py`, `system/` | callback bodies, OS helpers (`posix.py`, `windows.py`) |

## Adding an operation

Put it in the module of its area, or in a new module whose class (a subclass of `OperationModule`, which declares
what a module may use of the machine) you add to `AdapterMachine`'s bases in `machine.py`:

```python
@session_operation(is_active, paused=True, weight=2, index=INDEX)
def select_thread(self, session, index):
    threads = list(session.dbg.threads)
    ...
    if session.dbg.active_thread.tid != threads[index % len(threads)].tid:
        raise AssertionError(f'{session}: ...')
```

- `is_active` says which sessions the operation applies to (`operations.py` has `is_idle`, `is_live`, `is_launched`
  and `is_unlaunched`; a lambda over a session's bookkeeping works too). The engine draws a `which` that picks among
  them and records the session in the step, and the operation is not drawn while there are none. `when=` limits it
  further, to a function of the machine.
- `paused=True` makes the body run only while the target is stopped and untouched from outside.
- `weight` makes it likelier. The engine draws every enabled operation equally unless weighted, so one that is
  enabled in many states otherwise crowds out the rest.
- The arguments after `weight` are draws from `draws.py` (`one_of`, `integers`, `booleans`), or any function of the
  example's `random.Random` and the machine; the body receives them by name. `one_of` also takes a function of the
  machine that returns the options, for a choice that depends on the machine's adapter.
- Raise `AssertionError` for a property that does not hold (not `assert`, which `python -O` removes). Anything else the body raises is a failure too.
- **Which operations are enabled may depend only on the session's model** (its `model`, `launched`, `breakpoints`,
  and the other bookkeeping that operations themselves change), never on what the target is doing. A replay of a
  failure skips a recorded step whose operation is not enabled, and shrinking removes steps; if enabled-ness
  followed the target, a replay could skip a step that the run took, or run one that it did not. When the target's
  state matters, test it in the body and return.
- Keep the model deterministic: record what the operation asked for, not what the adapter answered.

For a check that runs after every step, use `@check` (see `machine.check_sessions`). For something specific to
one platform, subclass `AdapterMachine` in a test module, override the `before_launch` and `session_ended` hooks, add
operations and checks, or name operations it cannot use in `excluded_operations`; an operation that the subclass
defines under the name of one of the machine's replaces it. Pass `'module:Class'` to `campaign.assert_clean(profile_name, ...)`.

## Adding an adapter

Add an `AdapterProfile` to `ADAPTERS` in `profile.py`. It names the adapter as `DebugAdapterType` does and lists the
platforms it runs on, and it is the one place for what is special about it: whether it can restart, whether a fault
signal reaches the program's handler, the debug server processes that `fault_ops.py` may kill, and a `configure`
function for debugger settings. A test is skipped, with the reason, when the adapter is not available on the host
or a test program has not been built (`unavailable_reason`); it never substitutes another program or mode.

What else differs between platforms is in `system/` (`posix.py` and `windows.py` each give process liveness, a
process's identity, signalling or ending a process, counting the pipes and sockets the process holds, and finding the
processes below it) and in
`fault_ops.py` (on Windows every signal is a termination, so only SIGTERM is sent). A process id can be reused once
its process is gone, so every signal goes through `signal_process`, which sends it only if the process still has the
identity (start time) that was read when the id was first noted.
