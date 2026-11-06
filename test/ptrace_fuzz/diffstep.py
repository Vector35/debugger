#!/usr/bin/env python3
"""Differential stepping test for the ptrace adapter.

A full single-step trace (step_into until exit) of a deterministic single-threaded program is the ground truth. Then
step_over and step_return are replayed against it:

  * step_over from a call instruction must land at the first later trace entry with the same stack pointer (the
    caller's frame again). From any other instruction it must land at the next trace entry.
  * step_return from inside a function of the program itself must land where the trace pops the return address.

usage: diffstep.py <mode> [--max N] [--seed S]
env: PTRACE_TEST_BUILD_DIR
Exits 0 on agreement, 3 on a mismatch.
"""
import os, random, sys
import ctypes
from binaryninja import load
from debugger import DebuggerController, DebugStopReason


def _exit(code):
    """os._exit, after writing the coverage counters of the plugin if it was built with coverage (FUZZ_COV_LIB=<.so>)"""
    lib = os.environ.get('FUZZ_COV_LIB')
    if lib:
        try:
            ctypes.CDLL(lib).__gcov_dump()
        except Exception:
            pass
    os._exit(code)


mode = sys.argv[1]
limit = int(sys.argv[sys.argv.index('--max') + 1]) if '--max' in sys.argv else 40000
seed = int(sys.argv[sys.argv.index('--seed') + 1]) if '--seed' in sys.argv else 1
rng = random.Random(seed)
progs = os.environ['PTRACE_TEST_BUILD_DIR'] + '/progs'
bv = load(progs)
T = 20000


# The program raises a signal that it ignores. The debugger reports it as a stop of its own, like gdb does, and a step that is
# interrupted by it ends there. So such a stop is a legitimate result of a step, at a position that the trace has too.
SIGNAL_STOPS = (DebugStopReason.SignalUsr1, DebugStopReason.SignalUsr2, DebugStopReason.SignalChld)



def start():
    d = DebuggerController(bv)
    d.adapter_type = 'PTRACE'
    d.cmd_line = mode
    r = d.launch_and_wait(T)
    assert r not in (DebugStopReason.ProcessExited, DebugStopReason.InternalError), r
    return d


# --- ground truth
d = start()
trace = [(d.ip, d.stack_pointer)]
while len(trace) < limit:
    r = d.step_into_and_wait(timeout=T)
    if r == DebugStopReason.ProcessExited:
        break
    if r not in (DebugStopReason.SingleStep, DebugStopReason.Breakpoint, DebugStopReason.UnknownReason) + SIGNAL_STOPS:
        print(f'FINDING: single-step trace stopped with {r} after {len(trace)} steps at {trace[-1][0]:#x}', flush=True)
        _exit(3)
    here = (d.ip, d.stack_pointer)
    if r in SIGNAL_STOPS and here == trace[-1]:
        continue  # reported at the position that the step before it arrived at: the same place, not a new one
    trace.append(here)
d.quit_and_wait(T)
print(f'trace of {len(trace)} instructions', flush=True)

# the program's own code, for step_return (the analysis can find where those functions return)
# .text of the fixture starts at its entry point; below it are the PLT stubs, which have no return to find
main_lo, main_hi = 0x400650, 0x402b01


def is_call(i):
    return (i + 1 < len(trace) and trace[i + 1][1] == trace[i][1] - 8 and abs(trace[i + 1][0] - trace[i][0]) > 16)


def landing_after_call(i):
    sp = trace[i][1]
    for j in range(i + 2, len(trace)):
        if trace[j][1] == sp:
            return j
    return None


def return_landing(entry):
    # entry is the index of the first instruction of the callee; the return pops sp_entry
    sp = trace[entry][1]
    for j in range(entry + 1, len(trace)):
        if trace[j][1] == sp + 8 and trace[j][0] != trace[entry][0]:
            return j
    return None


calls = [i for i in range(len(trace) - 1) if is_call(i)]
print(f'{len(calls)} calls in trace, {sum(1 for i in calls if main_lo <= trace[i + 1][0] < main_hi)} into the program; first ips {[hex(trace[i+1][0]) for i in calls[:6]]}', flush=True)
bad = 0
d = start()
i = 0
checked_over = checked_ret = 0
while i < len(trace) - 1:
    assert (d.ip, d.stack_pointer) == trace[i], f'drifted at {i}: {(d.ip, d.stack_pointer)} vs {trace[i]}'
    if is_call(i) and rng.random() < 0.5 and landing_after_call(i) is not None:
        j = landing_after_call(i)
        r = d.step_over_and_wait(timeout=T)
        checked_over += 1
        got = (d.ip, d.stack_pointer)
        if r == DebugStopReason.ProcessExited:
            if j < len(trace) - 1:
                print(f'FINDING: step_over at {trace[i][0]:#x} (trace {i}) ended the process, expected stop at {trace[j][0]:#x}', flush=True); bad += 1
            break
        if r in SIGNAL_STOPS and got != trace[j]:
            # interrupted by the signal, inside the call: carry on from where the trace has that position
            try:
                i = next(k for k in range(i, len(trace)) if trace[k] == got)
            except StopIteration:
                bad += 1
                print(f'FINDING: step_over from {trace[i][0]:#x} stopped for {r.name} at {got[0]:#x}, which the trace does not have', flush=True)
                break
            continue
        if got != trace[j]:
            bad += 1
            print(f'FINDING: step_over from {trace[i][0]:#x} (trace {i}) landed at {got[0]:#x} sp {got[1]:#x}, expected {trace[j][0]:#x} sp {trace[j][1]:#x} (trace {j})', flush=True)
            if bad > 5:
                break
            # resynchronise on the trace
            try:
                i = next(k for k in range(i, len(trace)) if trace[k] == got)
            except StopIteration:
                break
            continue
        i = j
        continue
    if is_call(i) and main_lo <= trace[i + 1][0] < main_hi and rng.random() < 0.95:
        # into the callee of the program itself, then out with step_return
        r = d.step_into_and_wait(timeout=T)
        i += 1
        assert (d.ip, d.stack_pointer) == trace[i]
        j = return_landing(i)
        if j is None:
            continue
        r = d.step_return_and_wait(timeout=T)
        checked_ret += 1
        got = (d.ip, d.stack_pointer)
        if r == DebugStopReason.ProcessExited:
            print(f'FINDING: step_return in {trace[i][0]:#x} ended the process, expected {trace[j][0]:#x}', flush=True); bad += 1
            break
        if r in SIGNAL_STOPS and got != trace[j]:
            try:
                i = next(k for k in range(i, len(trace)) if trace[k] == got)
            except StopIteration:
                bad += 1
                print(f'FINDING: step_return stopped for {r.name} at {got[0]:#x}, which the trace does not have', flush=True)
                break
            continue
        tail_call = got[1] == trace[i][1] and main_lo <= got[0] < main_hi and got != trace[j]
        if tail_call:
            # The function ends in a jump to another function of the program. Stopping at the target, with the stack as it
            # was at the entry, is a reasonable reading of "return", so it is not counted as a mismatch.
            try:
                i = next(k for k in range(i, len(trace)) if trace[k] == got)
            except StopIteration:
                break
            continue
        if got != trace[j]:
            bad += 1
            print(f'FINDING: step_return from callee {trace[i][0]:#x} (trace {i}) landed at {got[0]:#x} sp {got[1]:#x}, expected {trace[j][0]:#x} sp {trace[j][1]:#x} (trace {j})', flush=True)
            if bad > 5:
                break
            try:
                i = next(k for k in range(i, len(trace)) if trace[k] == got)
            except StopIteration:
                break
            continue
        i = j
        continue
    r = d.step_into_and_wait(timeout=T)
    if r == DebugStopReason.ProcessExited:
        break
    if r in SIGNAL_STOPS and (d.ip, d.stack_pointer) == trace[i]:
        continue  # the signal is reported before the next instruction runs; the step is still to be made
    i += 1

print(f'{mode}: {checked_over} step_over and {checked_ret} step_return checks, {bad} mismatches', flush=True)
try:
    d.quit_and_wait(T)
except Exception:
    pass
_exit(3 if bad else 0)
