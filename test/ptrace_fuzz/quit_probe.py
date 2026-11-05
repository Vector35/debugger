import os, sys, time
from binaryninja import load
from debugger import DebuggerController
mode, pre = sys.argv[1], sys.argv[2:]
bv = load(os.environ['PTRACE_TEST_BUILD_DIR'] + '/progs')
d = DebuggerController(bv); d.adapter_type = 'PTRACE'; d.cmd_line = mode
print('launch', d.launch_and_wait(8000), flush=True)
pid = d.active_pid
for p in pre:
    if p == 'go': print('go', d.go_and_wait(timeout=3000), flush=True)  # target keeps running -> timeout
    if p == 'pause': print('pause', d.pause_and_wait(timeout=3000), flush=True)
    if p == 'over': print('over', d.step_over_and_wait(timeout=3000), flush=True)
    if p == 'ret': print('ret', d.step_return_and_wait(3000), flush=True)
    if p == 'into': print('into', d.step_into_and_wait(timeout=3000), flush=True)
t = time.time(); d.quit_and_wait(8000); print('quit took %.2fs' % (time.time() - t), flush=True)
time.sleep(1)
try:
    st = open(f'/proc/{pid}/stat').read().split(')')[1].split()[0]
    tr = [l for l in open(f'/proc/{pid}/status') if l.startswith('TracerPid')][0].strip()
    print('AFTER QUIT pid', pid, 'state', st, tr)
except FileNotFoundError:
    print('AFTER QUIT pid gone (ok)')
os._exit(0)
