#!/usr/bin/env python3
"""Fail the Nth ptrace / memory I/O call, for every N, in one fixed scenario, and report which N wedge the debugger.

usage: sweep.py [--max N] [--jobs J]       env: PTRACE_TEST_BUILD_DIR, FAULT_SHIM (path to faultshim.so), BN_*/PYTHONPATH
"""
import argparse, concurrent.futures as cf, json, os, re, subprocess, sys

p = argparse.ArgumentParser()
p.add_argument('--max', type=int, default=600)
p.add_argument('--jobs', type=int, default=14)
p.add_argument('--start', type=int, default=1)
a = p.parse_args()
here = os.path.dirname(os.path.abspath(__file__))
progs = os.path.join(os.environ['PTRACE_TEST_BUILD_DIR'], 'progs')


def resolve(stderr):
    # The plugin offsets in the backtrace that the shim prints, as 'function file:line' (needs a build with symbols)
    lib = os.environ.get('SYMBOLIZED_PLUGIN')
    offsets = re.findall(r'libdebuggercore\.so\(\+(0x[0-9a-f]+)\)', stderr)
    if not lib or not offsets:
        return []
    out = subprocess.run(['addr2line', '-f', '-C', '-e', lib] + offsets, capture_output=True, text=True).stdout.splitlines()
    return [f'{out[i]} {os.path.basename(out[i + 1])}' for i in range(0, len(out) - 1, 2)]


def fault_text(stderr, stack):
    head = re.search(r'FAULT#\d+ .*', stderr).group(0)
    frames = [f for f in stack if 'PtraceEngine' in f or 'PtraceAdapter' in f or 'PtraceStepper' in f][:4]
    return head + ' via ' + ' < '.join(re.sub(r'BinaryNinjaDebugger::', '', f) for f in frames)


def run(n):
    env = dict(os.environ, FAULT_NTH=str(n), LD_PRELOAD=os.environ['FAULT_SHIM'])
    try:
        pr = subprocess.run([sys.executable, os.path.join(here, 'sweep_session.py'), progs], env=env, capture_output=True,
                            text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return n, None, 'TIMEOUT', ''
    fault = re.search(r'FAULT#\d+ .*', pr.stderr)
    if fault:
        fault = type('F', (), {'group': lambda self, i=0, stack=resolve(pr.stderr): fault_text(pr.stderr, stack)})()
    result = None
    for line in pr.stdout.splitlines():
        if line.startswith('{'):
            result = json.loads(line)
    return n, result, fault.group(0) if fault else '', pr.stderr[-300:] if pr.returncode else ''


rows = []
with cf.ThreadPoolExecutor(a.jobs) as ex:
    for r in ex.map(run, range(a.start, a.max + 1)):
        rows.append(r)
past = 0
for n, result, fault, err in rows:
    if not fault:
        past += 1
        continue
    if result is None:
        print(f'N={n:4d} {fault}  -> NO RESULT {err}')
    elif result['wedged']:
        bad = [f'{s}={r}' for s, r in result['steps'] if r in ('TimedOut', 'InvalidStatusOrOperation')]
        print(f'N={n:4d} {fault}  -> WEDGED leak={result["leak"]} {" ".join(bad)}')
print(f'{len(rows) - past} injected, {past} beyond the end of the scenario')
