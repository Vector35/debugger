"""One randomized ptrace-adapter session. Run by fuzz.py in its own process.

usage: session.py <progs path> <mode> <seed> <nops> [--no-pause]
Exit 0 = ok. Prints "FINDING: ..." lines for invariant violations / hangs and
exits 3 on a finding. A native crash shows up as a signal exit in the parent.
"""
import os, random, sys, threading, time, faulthandler, traceback, signal, subprocess, ctypes

import ctypes
import binaryninja
from binaryninja import load
from debugger import DebuggerController, DebugStopReason, ModuleNameAndOffset


def _exit(code):
    """os._exit, after writing the coverage counters of the plugin if it was built with coverage (FUZZ_COV_LIB=<.so>)"""
    lib = os.environ.get('FUZZ_COV_LIB')
    if lib:
        try:
            ctypes.CDLL(lib).__gcov_dump()
        except Exception:
            pass
    os._exit(code)


SCALE = float(os.environ.get('FUZZ_TIME_SCALE', '1'))
TIMEOUT_MS = int(8000 * SCALE)
progs, mode, seed, nops = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
use_pauser = '--no-pause' not in sys.argv
use_signals = '--signals' in sys.argv      # external signals / kills to the target
use_attach = '--attach' in sys.argv        # attach/detach to external processes
use_hammer = '--hammer' in sys.argv        # other threads hammering the API concurrently
rng = random.Random(seed)
log = []
findings = []


FAULTS = bool(os.environ.get('FUZZ_FAULTS'))
FAULT_TOLERATED = ('API memory read', 'memory round trip', 'register ', 'InternalError', 'exception in')


def finding(msg):
    if FAULTS and msg.startswith(FAULT_TOLERATED):
        return
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
dumped = [False]
stop_flag = False
hang_deadline = [None]


hammer_progress = {}


def watchdog():
    while True:
        time.sleep(0.5)
        for name, t in list(hammer_progress.items()):
            if time.time() - t > 60 * SCALE:
                print(f'FINDING: HANG in hammer thread {name}', flush=True)
                print('OPS:', log, flush=True)
                faulthandler.dump_traceback(all_threads=True)
                _exit(4)
        d = hang_deadline[0]
        if d and time.time() > d:
            print('FINDING: HANG in op: %s' % (log[-1] if log else '?'), flush=True)
            print('OPS:', log, flush=True)
            faulthandler.dump_traceback(all_threads=True)
            _exit(4)


threading.Thread(target=watchdog, daemon=True).start()


def timed(label, fn, *a):
    log.append(label)
    hang_deadline[0] = time.time() + 40 * SCALE
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
    if reason == DebugStopReason.InternalError and dbg.active_pid and not process_gone(dbg.active_pid):
        return
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
    if not pid or process_gone(pid):
        end = time.time() + 5 * SCALE
        while dbg.connected and time.time() < end:
            time.sleep(0.05)
        if dbg.connected:
            try:
                per = []
                for t in sorted(os.listdir(f'/proc/{pid}/task')):
                    tst = open(f'/proc/{pid}/task/{t}/stat').read().rsplit(')', 1)[1].split()[0]
                    tr = [l.split()[1] for l in open(f'/proc/{pid}/task/{t}/status') if l.startswith('TracerPid')][0]
                    per.append((int(t), tst, tr))
            except Exception as e:
                per = repr(e)
            finding(f'target pid {pid} is gone but the controller still reports it connected 5s after {log[-1]} (reason {reason}); tasks {per}; recent ops {log[-6:]}')
        alive = False
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


def process_gone(p):
    # A leader that exited while other threads still run is a zombie of a living process
    try:
        return all(open(f'/proc/{p}/task/{t}/stat').read().rsplit(')', 1)[1].split()[0] in 'ZX'
                   for t in os.listdir(f'/proc/{p}/task'))
    except OSError:
        return True


def op_regs():
    if not dbg.active_pid or process_gone(dbg.active_pid):
        return  # the target is gone (killed from outside, for one), and its registers with it
    if not alive or (last_reason[0] and last_reason[0][1] in (DebugStopReason.TimedOut, DebugStopReason.ProcessExited, DebugStopReason.InvalidStatusOrOperation)):
        return  # registers cannot be written while the target runs or is gone
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



libc = ctypes.CDLL(None, use_errno=True)
externals = []       # external processes we spawned (attach targets / detached children)
detached_pids = set()


def tgkill(pid, tid, sig):
    return libc.syscall(234, pid, tid, sig)


def op_signal():
    pid = dbg.active_pid
    if not pid:
        return
    sig = rng.choice([signal.SIGUSR1, signal.SIGUSR2, signal.SIGCHLD, signal.SIGWINCH, signal.SIGALRM, signal.SIGURG,
                      signal.SIGSTOP, signal.SIGCONT, signal.SIGTERM, signal.SIGHUP, signal.SIGSEGV, signal.SIGTRAP,
                      signal.SIGINT, signal.SIGPIPE])
    try:
        tids = [int(t) for t in os.listdir(f'/proc/{pid}/task')]
    except OSError:
        return
    if rng.random() < 0.5:
        try:
            os.kill(pid, sig)
        except OSError:
            pass
    else:
        tgkill(pid, rng.choice(tids), sig)
    time.sleep(rng.uniform(0, 0.05))
    if sig == signal.SIGSTOP:
        # an external stop must not wedge the debugger; resume it so the session can go on
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            pass


def op_extkill():
    pid = dbg.active_pid
    if not pid or rng.random() < 0.6:
        return
    try:
        if rng.random() < 0.5:
            os.kill(pid, signal.SIGKILL)
        else:
            tids = [int(t) for t in os.listdir(f'/proc/{pid}/task')]
            tgkill(pid, rng.choice(tids), signal.SIGKILL)
    except OSError:
        pass
    time.sleep(rng.uniform(0, 0.05))


def spawn_external():
    p = subprocess.Popen([progs, rng.choice(['loop', 'sleeper', 'threads', 'bploop'])], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
    externals.append(p)
    time.sleep(0.2)
    return p


def op_detach():
    global alive
    if not alive:
        return
    pid = dbg.active_pid
    dbg.detach_and_wait(timeout=TIMEOUT_MS)
    time.sleep(0.1)
    if dbg.connected and not process_gone(pid):
        return  # the detach failed (an injected failure, for one), and the target is still attached
    if pid:
        detached_pids.add(pid)
    alive = False


def op_attach():
    global alive
    if alive:
        return
    live = [p for p in externals if p.poll() is None]
    if live and rng.random() < 0.7:
        p = rng.choice(live)
    else:
        p = spawn_external()
    dbg.pid_attach = p.pid
    r = timed('attach', dbg.attach_and_wait, TIMEOUT_MS)
    if r in (DebugStopReason.ProcessExited, DebugStopReason.InternalError):
        if r == DebugStopReason.InternalError:
            finding('InternalError on attach')
        alive = False
    else:
        alive = True


def hammer(idx):
    hr = random.Random(seed * 31 + idx)
    name = f'hammer{idx}'
    while not stop_flag:
        hammer_progress[name] = time.time()
        time.sleep(hr.uniform(0, 0.02))
        if not alive:
            continue
        try:
            c = hr.randrange(9)
            if c == 0:
                dbg.read_memory(dbg.stack_pointer, hr.randrange(1, 256))
            elif c == 1:
                list(dbg.modules)
            elif c == 2:
                list(dbg.threads)
            elif c == 3:
                dbg.get_reg_value(hr.choice(['rax', 'rbx', 'rip', 'rsp', 'eflags']))
            elif c == 4:
                list(dbg.memory_map)
            elif c == 5:
                dbg.ip
            elif c == 6:
                mods = list(dbg.modules)
                if mods:
                    m = hr.choice(mods)
                    a = m.address + hr.randrange(0, 0x400)
                    dbg.add_breakpoint(a)
                    bps.add(a)
            elif c == 7:
                if bps:
                    a = hr.choice(sorted(bps))
                    dbg.delete_breakpoint(a)
                    bps.discard(a)
            elif c == 8:
                dbg.frames_of_thread(hr.choice([t.tid for t in dbg.threads]))
        except Exception:
            pass



def op_backend():
    cmd = rng.choice(['help', '?', 'syscall-info', 'syscall-set nr 0x27', 'syscall-set ret -5', 'syscall-set arg3 0xffffffffffffffff',
                      'syscall-set arg9 1', 'syscall-set ret', 'syscall-set nr zz', 'syscall', 'sysemu', '', '   ',
                      'x' * 5000, 'syscall-set ' + 'a ' * 50, '\x00\xff\xfe', 'syscall-set ret 99999999999999999999999'])
    if cmd in ('syscall', 'sysemu') and (os.environ.get('FUZZ_NO_SYSCALL_RESUME') or rng.random() < 0.7):
        cmd = 'syscall-info'
    return dbg.execute_backend_command(cmd)


OPS = [(op_go, 6), (op_into, 5), (op_over, 3), (op_ret, 2), (op_pause, 2), (op_addbp, 3), (op_addbp_sym, 2),
       (op_delbp, 2), (op_memrw, 2), (op_regs, 2), (op_threads, 2), (op_restart, 1), (op_backend, 2)]
if use_signals:
    OPS += [(op_signal, 6), (op_extkill, 1)]
if use_attach:
    OPS += [(op_detach, 2), (op_attach, 4)]
POP = [f for f, w in OPS for _ in range(w)]


def launch():
    global alive
    r = timed('launch', dbg.launch_and_wait, TIMEOUT_MS)
    if r in (DebugStopReason.InvalidStatusOrOperation, DebugStopReason.TimedOut):
        try:
            ppid = dbg.active_pid
            states = [(int(t), open(f'/proc/{ppid}/task/{t}/stat').read().rsplit(')', 1)[1].split()[0]) for t in sorted(os.listdir(f'/proc/{ppid}/task'))]
        except Exception as e:
            states = repr(e)
        print(f'WEDGE-STATE pid {dbg.active_pid} tasks {states}', flush=True)
        finding(f'launch refused with {r.name} (controller connected: {dbg.connected}, previous pid {dbg.active_pid}); recent ops {log[-6:]}')
        alive = False
        time.sleep(1)
        return
    if r in (DebugStopReason.ProcessExited, DebugStopReason.InternalError):
        alive = False
        if r == DebugStopReason.InternalError:
            finding('InternalError on launch')
        return
    alive = True


if use_hammer:
    for hi in range(3):
        threading.Thread(target=hammer, args=(hi,), daemon=True).start()

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
            if os.environ.get('FUZZ_TRACE'):
                print(f'TRACE {i} {op.__name__} -> {r!r:.200}', flush=True)
        except Exception as e:
            if alive:
                finding(f'exception in {op.__name__}: {e!r}\n{traceback.format_exc()}')
            continue
        if isinstance(r, DebugStopReason):
            last_reason[0] = (op.__name__, r)
            if (os.environ.get('FUZZ_GDB') and r == DebugStopReason.TimedOut and op in (op_pause, op_into, op_over, op_ret)
                    and not dumped[0]):
                dumped[0] = True
                subprocess.run(['gdb', '-p', str(os.getpid()), '-batch', '-x', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdb_controller.py'), '-ex', 'thread apply all bt 30'],
                               stdout=open(f'/tmp/wedge-{os.getpid()}.txt', 'w'), stderr=subprocess.DEVNULL, timeout=120, env={k: v for k, v in os.environ.items() if k != 'LD_PRELOAD'})
                finding(f'worker wedged: {op.__name__} timed out; native stacks in /tmp/wedge-{os.getpid()}.txt; recent ops {log[-8:]}')
            if op is op_pause or op is op_restart or True:
                check_stopped_invariants(r)
    stop_flag = True
    timed('quit', dbg.quit_and_wait, TIMEOUT_MS)
    for p in externals:
        try:
            p.kill()
            p.wait(5)
        except Exception:
            pass
    for dp in detached_pids:
        try:
            os.kill(dp, signal.SIGKILL)
        except OSError:
            pass
    time.sleep(0.3)
    for ch in list(children()):
        try:
            os.waitpid(ch[0], os.WNOHANG)
        except OSError:
            pass
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
        if os.environ.get('FUZZ_GDB'):
            subprocess.run(['gdb', '-p', str(os.getpid()), '-batch', '-x', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gdb_controller.py'), '-ex', 'thread apply all bt 30'],
                           stdout=open(f'/tmp/leak-{os.getpid()}.txt', 'w'), stderr=subprocess.DEVNULL, timeout=120, env={k: v for k, v in os.environ.items() if k != 'LD_PRELOAD'})
            det.append(f'stacks in /tmp/leak-{os.getpid()}.txt')
        finding(f'leaked live child processes after quit: {det}')
    # zombies of ours are reported but only as notes
except SystemExit:
    raise
except BaseException as e:
    finding(f'harness exception {e!r}\n{traceback.format_exc()}')

if findings:
    print('OPS:', log, flush=True)
    _exit(3)
_exit(0)
