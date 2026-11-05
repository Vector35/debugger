import os, sys, random
from binaryninja import load
from debugger import DebuggerController, DebugStopReason
mode = sys.argv[1]
bv = load(os.environ['PTRACE_TEST_BUILD_DIR'] + '/progs')
d = DebuggerController(bv); d.adapter_type = 'PTRACE'; d.cmd_line = mode
print('launch', d.launch_and_wait(8000))
r = d.pause_and_wait(timeout=8000) if mode in ('threads',) else None
print('state', r, 'tids', [t.tid for t in d.threads], 'active', d.active_thread.tid)
bad = {}
for i in range(300):
    reg = random.choice(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r15'])
    old = d.get_reg_value(reg); nv = random.getrandbits(64)
    ok = d.set_reg_value(reg, nv); got = d.get_reg_value(reg)
    if got != nv:
        bad[reg] = bad.get(reg, 0) + 1
        if bad[reg] == 1: print('MISMATCH', reg, 'ok', ok, hex(nv), '->', hex(got), 'old', hex(old))
    d.set_reg_value(reg, old)
print('mismatches', bad)
d.quit_and_wait(8000); os._exit(0)
