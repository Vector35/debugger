"""One randomized ptrace-adapter session. Run by fuzz.py in its own process.

usage: session.py <progs path> <mode> <seed> <nops> [--no-pause]
Exit 0 = ok. Prints "FINDING: ..." lines for invariant violations / hangs and
exits 3 on a finding. A native crash shows up as a signal exit in the parent.
"""
import os, random, sys, threading, time, faulthandler, traceback

import binaryninja
from binaryninja import load
from debugger import DebuggerController, DebugStopReason, ModuleNameAndOffset

TIMEOUT_MS = 8000
progs, mode, seed, nops = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
use_pauser = '--no-pause' not in sys.argv
rng = random.Random(seed)
log = []
findings = []


def finding(msg):
    findings.append(msg)
    print('FINDING:', msg, flush=True)


def children():
    me = os.getpid()
    out = []
    for p in os.listdir('/proc'):
        if p.isdigit():
            try:
                with open(f'/proc/{p}/stat') as f:
                    s = f.read()
                rest = s[s.rindex(')') + 2:].split()
                if int(rest[1]) == me:
                    out.append((int(p), rest[0]))
            except Exception:
                pass
    return out


def raw_mem(pid, addr, n):
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as f:
        f.seek(addr)
        return f.read(n)


if os.environ.get('FUZZ_LOG'):
    binaryninja.log_to_stderr(binaryninja.LogLevel.WarningLog)
bv = load(progs)
dbg = DebuggerController(bv)
dbg.adapter_type = 'PTRACE'
dbg.cmd_line = mode
bps = set()          # absolute addresses we added
sym_bps = set()      # subset placed on function symbols (first byte is never 0xCC padding)
alive = False
last_reason = [None]
stop_flag = False
hang_deadline = [None]


def watchdog():
    while True:
        time.sleep(0.5)
        d = hang_deadline[0]
        if d and time.time() > d:
            print('FINDING: HANG in op: %s' % (log[-1] if log else '?'), flush=True)
            print('OPS:', log, flush=True)
            faulthandler.dump_traceback(all_threads=True)
            os._exit(4)


threading.Thread(target=watchdog, daemon=True).start()


def timed(label, fn, *a):
    log.append(label)
    hang_deadline[0] = time.time() + 40
    try:
        return fn(*a)
    finally:
        hang_deadline[0] = None


def pauser():
    while not stop_flag:
        time.sleep(rng2.uniform(0.01, 0.3))
        if alive and rng2.random() < 0.5:
            try:
                dbg.pause()
            except Exception:
                pass


rng2 = random.Random(seed + 1)
if use_pauser:
    threading.Thread(target=pauser, daemon=True).start()


def check_stopped_invariants(reason):
    global alive
    if reason in (DebugStopReason.ProcessExited, DebugStopReason.InternalError):
        alive = False
        if reason == DebugStopReason.InternalError:
            pid = dbg.active_pid
            try:
                st = open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()[0]
                tasks = len(os.listdir(f'/proc/{pid}/task'))
                per = []
                for t in sorted(os.listdir(f'/proc/{pid}/task')):
                    tst = open(f'/proc/{pid}/task/{t}/stat').read().rsplit(')', 1)[1].split()[0]
                    tr = [l.split()[1] for l in open(f'/proc/{pid}/task/{t}/status') if l.startswith('TracerPid')][0]
                    try:
                        wc = open(f'/proc/{pid}/task/{t}/wchan').read()
                    except Exception:
                        wc = '?'
                    per.append((int(t), tst, 'tracer=' + tr, wc))
                info = f'pid {pid} state {st} threads {tasks} {per} python_pid {os.getpid()}'
            except Exception as e:
                info = f'pid {pid} gone ({e.__class__.__name__})'
            finding(f'InternalError after {log[-1]}: target {info}')
        return
    if reason in (DebugStopReason.TimedOut, DebugStopReason.InvalidStatusOrOperation):
        return
    pid = dbg.active_pid
    if not pid or not os.path.exists(f'/proc/{pid}'):
        finding(f'stopped ({reason}) but pid {pid} gone after {log[-1]}')
        return
    try:
        ip = dbg.ip
        mods = list(dbg.modules)
    except Exception as e:
        finding(f'exception reading ip/modules: {e!r}')
        return
    # breakpoint bytes must be invisible through the API
    for a in list(sym_bps & bps)[:6]:
        try:
            api = bytes(dbg.read_memory(a, 1))
        except Exception:
            continue
        try:
            raw = raw_mem(pid, a, 1)
        except Exception:
            continue
        if api == b'\xcc' and raw == b'\xcc':
            # legit only if the original is cc; compare with a page we know: skip if module file says so
            finding(f'API memory read shows 0xCC at breakpoint 0x{a:x}')


def op_go():
    return dbg.go_and_wait(TIMEOUT_MS)


def op_into():
    return dbg.step_into_and_wait(timeout=TIMEOUT_MS)


def op_over():
    return dbg.step_over_and_wait(timeout=TIMEOUT_MS)


def op_ret():
    return dbg.step_return_and_wait(TIMEOUT_MS)


def op_pause():
    return dbg.pause_and_wait(TIMEOUT_MS)


def op_addbp():
    mods = list(dbg.modules)
    if not mods:
        return None
    m = rng.choice(mods)
    off = rng.randrange(0, 0x1000)
    if rng.random() < 0.5:
        dbg.add_breakpoint(ModuleNameAndOffset(m.short_name, off))
        bps.add(m.address + off)
    else:
        dbg.add_breakpoint(m.address + off)
        bps.add(m.address + off)


def op_addbp_sym():
    for name in ('marker', 'libfunc', 'level1', 'caller', 'main'):
        s = bv.get_symbols_by_name(name)
        if s and rng.random() < 0.5:
            try:
                dbg.add_breakpoint(s[0].address)
                bps.add(s[0].address)
                sym_bps.add(s[0].address)
            except Exception:
                pass


def op_delbp():
    if bps:
        a = rng.choice(sorted(bps))
        dbg.delete_breakpoint(a)
        bps.discard(a)
        sym_bps.discard(a)


def op_memrw():
    pid = dbg.active_pid
    sp = dbg.stack_pointer
    addr = sp - rng.randrange(64, 4096)
    data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    if not dbg.write_memory(addr, data):
        return
    back = bytes(dbg.read_memory(addr, len(data)))
    if back != data:
        finding(f'memory round trip mismatch at 0x{addr:x}')
    # unmapped / huge / boundary reads must not crash or hang
    for a, n in ((0, 8), (2**64 - 4, 8), (sp, 1 << 20), (0x7fffffffffff, 16)):
        try:
            dbg.read_memory(a, n)
        except Exception:
            pass
        try:
            dbg.write_memory(a, b'\x00' * 4)
        except Exception:
            pass


def op_regs():
    reg = rng.choice(['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r15', 'eflags', 'rip', 'rsp', 'xmm0', 'ymm0', 'st0', 'fs_base', 'bogus'])
    try:
        v = dbg.get_reg_value(reg)
    except Exception:
        return
    if reg in ('rip', 'rsp', 'eflags', 'xmm0', 'ymm0', 'st0', 'fs_base', 'bogus'):
        return  # read-only probing; writing these would just crash the target
    nv = rng.getrandbits(64)
    dbg.set_reg_value(reg, nv)
    got = dbg.get_reg_value(reg)
    if got != nv:
        finding(f'register {reg} write/read mismatch: wrote {nv:#x} read {got:#x} old {v:#x}; last stop reason {last_reason[0]}; '
                f'active tid {dbg.active_thread.tid} threads {[t.tid for t in dbg.threads]} reread {dbg.get_reg_value(reg):#x}')
    dbg.set_reg_value(reg, v)


def op_threads():
    ts = list(dbg.threads)
    if ts and rng.random() < 0.7:
        t = rng.choice(ts)
        try:
            dbg.active_thread = t
            dbg.frames_of_thread(t.tid)
        except Exception:
            pass
    list(dbg.memory_map)


def op_restart():
    return dbg.restart_and_wait(TIMEOUT_MS)


OPS = [(op_go, 6), (op_into, 5), (op_over, 3), (op_ret, 2), (op_pause, 2), (op_addbp, 3), (op_addbp_sym, 2),
       (op_delbp, 2), (op_memrw, 2), (op_regs, 2), (op_threads, 2), (op_restart, 1)]
POP = [f for f, w in OPS for _ in range(w)]


def launch():
    global alive
    r = timed('launch', dbg.launch_and_wait, TIMEOUT_MS)
    if r in (DebugStopReason.ProcessExited, DebugStopReason.InternalError):
        alive = False
        if r == DebugStopReason.InternalError:
            finding('InternalError on launch')
        return
    alive = True


try:
    launch()
    for i in range(nops):
        if not alive:
            launch()
            if not alive:
                continue
        op = rng.choice(POP)
        try:
            r = timed(op.__name__, op)
        except Exception as e:
            if alive:
                finding(f'exception in {op.__name__}: {e!r}\n{traceback.format_exc()}')
            continue
        if isinstance(r, DebugStopReason):
            last_reason[0] = (op.__name__, r)
            if op is op_pause or op is op_restart or True:
                check_stopped_invariants(r)
    stop_flag = True
    timed('quit', dbg.quit_and_wait, TIMEOUT_MS)
    time.sleep(1)
    left = children()
    live = [c for c in left if c[1] != 'Z']
    if live:
        det = []
        for pid, st in live:
            try:
                status = open(f'/proc/{pid}/status').read()
                tracer = [l for l in status.splitlines() if l.startswith('TracerPid')][0]
                cmd = open(f'/proc/{pid}/cmdline').read().replace('\0', ' ')
                det.append((pid, st, tracer, cmd, len(os.listdir(f'/proc/{pid}/task'))))
            except Exception as e:
                det.append((pid, st, repr(e)))
        finding(f'leaked live child processes after quit: {det}')
    # zombies of ours are reported but only as notes
except SystemExit:
    raise
except BaseException as e:
    finding(f'harness exception {e!r}\n{traceback.format_exc()}')

if findings:
    print('OPS:', log, flush=True)
    os._exit(3)
os._exit(0)
