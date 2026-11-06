"""One fixed scenario, run with exactly one injected failure (FAULT_NTH, see faultshim.c).

Prints one JSON line: the result of every operation, and whether the debugger wedged: an operation that timed out, a
relaunch that was refused, or a target that survived quit.
usage: sweep_session.py <progs>   (env: FAULT_NTH, LD_PRELOAD=faultshim.so, as for session.py)
"""
import json, os, sys, time
from binaryninja import load
from debugger import DebuggerController, DebugStopReason

progs = sys.argv[1]
T = 6000
bv = load(progs)
d = DebuggerController(bv)
d.adapter_type = 'PTRACE'
d.cmd_line = 'bploop'
d.add_breakpoint(bv.get_symbols_by_name('marker')[0].address)
steps = []


dumped = []


def run(name, fn):
    try:
        r = fn()
        steps.append([name, getattr(r, 'name', str(r))])
        if os.environ.get('SWEEP_GDB') and getattr(r, 'name', '') == 'TimedOut' and not dumped and not name.startswith('quit'):
            dumped.append(1)
            import subprocess
            subprocess.run(['gdb', '-p', str(os.getpid()), '-batch', '-x', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdb_controller.py'), '-ex', 'thread apply all bt 30'],
                           stdout=open(f'/tmp/sweep-{os.environ.get("FAULT_NTH")}-{os.getpid()}.txt', 'w'),
                           stderr=subprocess.DEVNULL, timeout=120, env={k: v for k, v in os.environ.items() if k not in ('LD_PRELOAD', 'FAULT_NTH')})
    except Exception as e:
        steps.append([name, 'EXC ' + repr(e)[:80]])


def children():
    me = os.getpid()
    out = []
    for p in os.listdir('/proc'):
        if p.isdigit():
            try:
                rest = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()
                if int(rest[1]) == me and rest[0] not in 'ZX':
                    out.append(int(p))
            except Exception:
                pass
    return out


run('launch', lambda: d.launch_and_wait(T))
run('go', lambda: d.go_and_wait(T))
run('over', lambda: d.step_over_and_wait(timeout=T))
run('into', lambda: d.step_into_and_wait(timeout=T))
run('go2', lambda: d.go_and_wait(T))
run('quit', lambda: d.quit_and_wait(T))
time.sleep(0.3)
leak = children()
run('relaunch', lambda: d.launch_and_wait(T))
run('quit2', lambda: d.quit_and_wait(T))
time.sleep(0.3)
leak += children()
timed_out = [n for n, r in steps if r == 'TimedOut' and n not in ('quit', 'quit2')]
refused = [n for n, r in steps if n == 'relaunch' and r in ('InvalidStatusOrOperation', 'TimedOut')]
print(json.dumps({'steps': steps, 'leak': bool(leak), 'wedged': bool(timed_out or refused or leak)}), flush=True)
os._exit(0)
