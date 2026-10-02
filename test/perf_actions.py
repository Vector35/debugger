# The actions timed by perf_benchmark.py, and the session helpers they share.
#
# Each action group is one function registered with @action(group, [result names]). It gets the Bench (a live
# controller plus helpers) and the number of tries, and records timings through Bench.measure / Bench.run.
# Everything here goes through the public DebuggerController Python API, so no action knows which adapter it
# is running against. An adapter that cannot do something makes the action skip (raise Skip) rather than fail.
#
# To add an action, write a function below, register it with @action, and give it a docstring; the first line is
# what --list-actions shows. Result names end up in the JSON history, so keep them stable once published.

import contextlib
import math
import os
import statistics
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

DEFAULT_BINARY = 'perf_target'

# Scratch-register candidates, in order of preference. Matched case-insensitively against the names the adapter
# reports. The register's original value is restored before the target is resumed, so any register is safe.
SCRATCH_REGISTERS = ['x19', 'rbx', 'ebx', 's1', 'r4', 'r10', 't3']

# A command each adapter is known to understand, for the backend_command action. --backend-command overrides.
DEFAULT_BACKEND_COMMANDS = {
    'LLDB': 'version', 'DBGENG': 'version', 'DBGENG_TTD': 'version', 'GDB MI': 'show version',
}


class Skip(Exception):
    """The action cannot run against this target/adapter."""


class Abort(Exception):
    """The action cannot continue (e.g. its setup step failed); results gathered so far are kept."""


class TargetLost(Abort):
    """The target exited or the backend disconnected."""


class Result:
    def __init__(self, name: str):
        self.name = name
        self.samples_ns: List[int] = []
        self.failed_ns: List[int] = []
        self.details: List[str] = []
        self.skipped: Optional[str] = None
        self.aborted: Optional[str] = None

    def add(self, ns: int, verdict) -> None:
        if verdict is True:
            self.samples_ns.append(ns)
            return
        self.failed_ns.append(ns)
        if isinstance(verdict, str) and len(self.details) < 3 and verdict not in self.details:
            self.details.append(verdict)

    def stats(self) -> Optional[dict]:
        if not self.samples_ns:
            return None
        s = sorted(self.samples_ns)

        def pct(p):
            return s[min(len(s) - 1, max(0, math.ceil(p / 100 * len(s)) - 1))]

        mean = statistics.fmean(s)
        return {
            'n': len(s),
            'min_ns': s[0],
            'mean_ns': mean,
            'median_ns': statistics.median(s),
            'p95_ns': pct(95),
            'p99_ns': pct(99),
            'max_ns': s[-1],
            'stdev_ns': statistics.pstdev(s),
            'total_ns': sum(s),
            'ops_per_sec': 1e9 / mean if mean else 0.0,
        }

    def to_json(self, samples: bool) -> dict:
        out = {
            'name': self.name,
            'stats': self.stats(),
            'failures': len(self.failed_ns),
            'details': self.details,
            'skipped': self.skipped,
            'aborted': self.aborted,
        }
        if samples:
            out['samples_ns'] = self.samples_ns
            out['failed_samples_ns'] = self.failed_ns
        return out


@dataclass
class ActionDef:
    group: str
    fn: Callable
    results: List[str]
    description: str
    ends_session: bool  # leaves no usable target behind, so it runs after everything that needs one


ACTIONS: List[ActionDef] = []


def action(group: str, results: List[str], ends_session: bool = False):
    def register(fn):
        doc = (fn.__doc__ or '').strip().splitlines()
        ACTIONS.append(ActionDef(group, fn, results, doc[0] if doc else '', ends_session))
        return fn
    return register


def parse_property(item: str):
    import json
    key, _, value = item.partition('=')
    try:
        return key, json.loads(value)
    except ValueError:
        return key, value


def pattern_value(i: int, mask: int) -> int:
    return (0x1122334455667788 ^ (i * 0x9E3779B97F4A7C15)) & mask


def mem_pattern(i: int, size: int) -> bytes:
    return bytes((i * 31 + k) & 0xff for k in range(size))


class Bench:
    """One benchmark session: a controller for one adapter, plus the helpers the actions share."""

    def __init__(self, dbg, bv, api, opts, adapter: str, fpath: str):
        self.dbg = dbg
        self.bv = bv
        self.api = api  # the debugger module: DebugStopReason, ModuleNameAndOffset, ...
        self.opts = opts
        self.adapter = adapter
        self.fpath = fpath
        self.results: Dict[str, Result] = {}
        self.leaf = None
        self.work = None
        self.unused = None
        self.ready = False

    @property
    def R(self):
        return self.api.DebugStopReason

    # ---- measurement primitives -------------------------------------------------------------------------------

    def result(self, name: str) -> Result:
        if name not in self.results:
            self.results[name] = Result(name)
        return self.results[name]

    def measure(self, name: str, op: Callable, check: Optional[Callable] = None, record: bool = True):
        """Time op(). check(value) runs untimed afterwards and returns True, or a failure description."""
        t0 = time.perf_counter_ns()
        out = op()
        dt = time.perf_counter_ns() - t0
        verdict = True if check is None else check(out)
        if record:
            self.result(name).add(dt, verdict)
        if verdict is not True and not self.dbg.connected:
            raise TargetLost('target exited or the backend disconnected')
        return out

    def repeat(self, n: int, body: Callable[[int, bool], None], warmup: Optional[int] = None) -> None:
        w = self.opts.warmup if warmup is None else warmup
        for i in range(w + n):
            body(i, i >= w)

    def run(self, n: int, name: str, op: Callable, check: Optional[Callable] = None,
            prep: Optional[Callable] = None) -> None:
        """n timed tries of op(i). prep(i) runs untimed first; check(i, value) runs untimed afterwards."""
        def body(i, rec):
            if prep:
                prep(i)
            self.measure(name, lambda: op(i), (lambda v: check(i, v)) if check else None, rec)
        self.repeat(n, body)

    def section(self, names: List[str], fn: Callable) -> None:
        """Run one independent part of an action group; a failure in it does not stop the other parts."""
        try:
            fn()
        except TargetLost:
            raise
        except Skip as e:
            for name in names:
                self.result(name).skipped = str(e)
        except Abort as e:
            for name in names:
                self.result(name).aborted = str(e)
        except Exception as e:
            for name in names:
                self.result(name).aborted = f'{type(e).__name__}: {e}'
            if self.opts.verbose:
                traceback.print_exc()

    # ---- stop-reason checks -----------------------------------------------------------------------------------

    def expect(self, *expected):
        names = '/'.join(e.name for e in expected)

        def check(i, reason):
            return True if reason in expected else f'stop reason {reason.name}, expected {names}'
        return check

    def startup_failed(self, reason) -> bool:
        R = self.R
        return reason in (R.ProcessExited, R.InternalError, R.TimedOut) or not self.dbg.connected

    def not_failed(self, i, reason):
        return f'stop reason {reason.name}' if self.startup_failed(reason) else True

    # ---- session management -----------------------------------------------------------------------------------

    def connect_or_launch(self):
        if self.opts.connect:
            return self.dbg.connect_and_wait(self.opts.timeout)
        return self.dbg.launch_and_wait(self.opts.timeout)

    def start(self):
        reason = self.connect_or_launch()
        if self.startup_failed(reason):
            raise Abort(f'could not start the target (stop reason {reason.name})')
        return reason

    def kill(self) -> None:
        if self.dbg.connected:
            self.dbg.quit_and_wait(self.opts.timeout)
        self.ready = False

    def resolve(self, name: str):
        data = self.dbg.data
        for candidate in (name, '_' + name):
            funcs = data.get_functions_by_name(candidate)
            if funcs:
                return funcs[0]
        return None

    def refresh_symbols(self) -> None:
        # Addresses are only stable within one launch: the view is rebased to wherever the target was loaded.
        self.leaf = self.resolve('perf_leaf')
        self.work = self.resolve('perf_work')
        self.unused = self.resolve('perf_unused')

    def ensure_ready(self) -> None:
        """Make sure there is a live, stopped target sitting inside the benchmark loop."""
        dbg = self.dbg
        if self.ready and dbg.connected and not dbg.running:
            return
        if dbg.connected and dbg.running:
            dbg.pause_and_wait(self.opts.timeout)
        if not dbg.connected or dbg.running:
            if dbg.connected:
                self.kill()
            self.start()
        self.refresh_symbols()
        if self.leaf is not None:
            # Get out of process startup and into the loop, so stepping measures the target's steady state.
            dbg.add_breakpoint(self.leaf.start)
            try:
                reason = dbg.go_and_wait(self.opts.timeout)
            finally:
                dbg.delete_breakpoint(self.leaf.start)
            if reason != self.R.Breakpoint:
                raise Abort(f'could not reach perf_leaf (stop reason {reason.name})')
        self.ready = True

    def need_leaf(self):
        if self.leaf is None or self.work is None:
            raise Skip(f'needs the {DEFAULT_BINARY} symbols (perf_leaf, perf_work); pass --binary {DEFAULT_BINARY}')
        return self.leaf

    def hit_leaf(self) -> None:
        """Untimed: run to the next perf_leaf breakpoint."""
        reason = self.dbg.go_and_wait(self.opts.timeout)
        if reason != self.R.Breakpoint or self.dbg.ip != self.leaf.start:
            raise Abort(f'setup: expected to stop at perf_leaf, got {reason.name} at {self.dbg.ip:#x}')

    def step_untimed(self) -> None:
        reason = self.dbg.step_into_and_wait(timeout=self.opts.timeout)
        if reason != self.R.SingleStep:
            raise Abort(f'setup: step returned {reason.name}')

    # ---- targets for the actions ------------------------------------------------------------------------------

    def func_addrs(self) -> List[int]:
        """Instruction addresses to place breakpoints on, other than the current one.

        perf_unused is never executed, so whatever the breakpoint bookkeeping does, it cannot change where the
        target stops. Without it, fall back to the code the target runs."""
        func = self.unused or self.work
        if func is None:
            funcs = self.dbg.data.get_functions_containing(self.dbg.ip)
            func = funcs[0] if funcs else None
        if func is None:
            return []
        ip = self.dbg.ip
        return [a for _, a in func.instructions if a != ip]

    def module_of(self, address: int):
        for m in self.dbg.modules:
            if m.address <= address < m.address + m.size:
                return m
        return None

    def scratch_register(self):
        regs = self.dbg.regs.regs
        lower = {r.lower(): r for r in regs}
        if self.opts.scratch_register:
            name = lower.get(self.opts.scratch_register.lower())
            if name is None:
                raise Skip(f'register {self.opts.scratch_register!r} not reported by the adapter')
        else:
            name = next((lower[c] for c in SCRATCH_REGISTERS if c in lower), None)
            if name is None:
                raise Skip('no known scratch register; pass --scratch-register')
        width = regs[name].width or 64
        return name, (1 << width) - 1, regs[name].value

    def write_reg(self, name, value) -> None:
        if not self.dbg.set_reg_value(name, value):
            raise Abort(f'setup: writing {name} failed')

    @contextlib.contextmanager
    def scratch_reg(self):
        name, mask, original = self.scratch_register()
        try:
            yield name, mask
        finally:
            self.dbg.set_reg_value(name, original)

    @contextlib.contextmanager
    def scratch_mem(self):
        dbg, size = self.dbg, self.opts.mem_size
        sp = dbg.stack_pointer
        if not sp:
            raise Skip('stack pointer unavailable; cannot pick scratch memory')
        addr = (sp - 0x800) & ~0xf  # below the stack pointer: dead space, clear of any red zone
        original = dbg.read_memory(addr, size)
        if original is None or len(original) != size:
            raise Skip(f'cannot read {size} bytes of scratch memory at {addr:#x}')
        original = bytes(original)
        try:
            yield addr, size
        finally:
            dbg.write_memory(addr, original)

    @contextlib.contextmanager
    def breakpoints(self):
        """Breakpoints added through the yielded object are removed on exit, whatever happens."""
        added = []
        dbg = self.dbg

        class Added:
            @staticmethod
            def add(address):
                dbg.add_breakpoint(address)
                added.append(address)

            @staticmethod
            def track(address):
                """Remove address on exit, for a breakpoint the caller adds itself (e.g. the one being timed)."""
                added.append(address)
        try:
            yield Added
        finally:
            for a in added:
                dbg.delete_breakpoint(a)


# ==== execution =================================================================================================

@action('step_into', ['step_into'])
def act_step_into(b, n):
    """Step one instruction, following calls."""
    b.run(n, 'step_into', lambda i: b.dbg.step_into_and_wait(timeout=b.opts.timeout), b.expect(b.R.SingleStep))


@action('step_over', ['step_over'])
def act_step_over(b, n):
    """Step one instruction, running calls to completion."""
    b.run(n, 'step_over', lambda i: b.dbg.step_over_and_wait(timeout=b.opts.timeout), b.expect(b.R.SingleStep))


@action('step_return', ['step_return'])
def act_step_return(b, n):
    """Run until the current function returns."""
    dbg, leaf, work = b.dbg, b.need_leaf(), b.work

    def check(i, reason):
        ip = dbg.ip
        if not any(r.start <= ip < r.end for r in work.address_ranges):
            return f'stopped at {ip:#x}, outside perf_work (stop reason {reason.name})'
        return True
    with b.breakpoints() as bps:
        bps.add(leaf.start)
        b.run(n, 'step_return', lambda i: dbg.step_return_and_wait(b.opts.timeout), check,
              prep=lambda i: b.hit_leaf())


IL_LEVELS = (('llil', 'LowLevelILFunctionGraph'), ('mlil', 'MediumLevelILFunctionGraph'),
             ('hlil', 'HighLevelILFunctionGraph'))


@action('step_il', [f'step_{kind}_{lvl}' for kind in ('into', 'over') for lvl, _ in IL_LEVELS])
def act_step_il(b, n):
    """Step one LLIL/MLIL/HLIL instruction, into and over (built on disassembly stepping plus analysis)."""
    from binaryninja import FunctionGraphType
    for kind in ('into', 'over'):
        for lvl, attr in IL_LEVELS:
            name = f'step_{kind}_{lvl}'
            il = getattr(FunctionGraphType, attr)
            step = getattr(b.dbg, f'step_{kind}_and_wait')
            b.section([name], lambda: b.run(
                n, name, lambda i: step(il=il, timeout=b.opts.timeout), b.expect(b.R.SingleStep)))


@action('breakpoint_hit', ['breakpoint_hit'])
def act_breakpoint_hit(b, n):
    """Resume until a software breakpoint is hit."""
    dbg, leaf = b.dbg, b.need_leaf()

    def check(i, reason):
        if reason != b.R.Breakpoint or dbg.ip != leaf.start:
            return f'stop reason {reason.name} at {dbg.ip:#x}, expected Breakpoint at perf_leaf'
        return True
    with b.breakpoints() as bps:
        bps.add(leaf.start)
        b.run(n, 'breakpoint_hit', lambda i: dbg.go_and_wait(b.opts.timeout), check)


@action('run_to', ['run_to'])
def act_run_to(b, n):
    """Run to an address (the debugger sets and removes the breakpoint itself)."""
    dbg, leaf = b.dbg, b.need_leaf()
    b.run(n, 'run_to', lambda i: dbg.run_to_and_wait(leaf.start, b.opts.timeout),
          lambda i, reason: True if dbg.ip == leaf.start else
          f'stopped at {dbg.ip:#x} ({reason.name}), expected perf_leaf')


@action('pause', ['pause'])
def act_pause(b, n):
    """Interrupt a running target."""
    dbg = b.dbg

    def prep(i):
        if not dbg.go():
            raise Abort('setup: go() failed')
        time.sleep(b.opts.pause_delay_ms / 1000)
    b.run(n, 'pause', lambda i: dbg.pause_and_wait(b.opts.timeout),
          lambda i, _: True if dbg.connected and not dbg.running else 'target still running after pause', prep)


REVERSE_RESULTS = ['reverse_step_into', 'reverse_step_over', 'reverse_step_return', 'reverse_go', 'reverse_run_to']


@action('reverse', REVERSE_RESULTS)
def act_reverse(b, n):
    """Reverse execution: step into/over/return, go, run to (time-travel adapters only)."""
    dbg = b.dbg
    if not dbg.is_ttd:
        raise Skip('reverse execution needs a time-travel (TTD) adapter')
    t = b.opts.timeout
    for name, step in (('reverse_step_into', lambda i: dbg.step_into_reverse_and_wait(timeout=t)),
                       ('reverse_step_over', lambda i: dbg.step_over_reverse_and_wait(timeout=t)),
                       ('reverse_step_return', lambda i: dbg.step_return_reverse_and_wait(t))):
        b.section([name], lambda: b.run(n, name, step, b.not_failed))

    def go_reverse():
        with b.breakpoints() as bps:
            bps.add(b.need_leaf().start)
            b.run(n, 'reverse_go', lambda i: dbg.go_reverse_and_wait(t), b.not_failed)

    def run_to_reverse():
        leaf = b.need_leaf()
        b.run(n, 'reverse_run_to', lambda i: dbg.run_to_reverse_and_wait(leaf.start, t), b.not_failed)
    b.section(['reverse_go'], go_reverse)
    b.section(['reverse_run_to'], run_to_reverse)


# ==== registers ==================================================================================================

@action('reg_read', ['reg_read_cold', 'reg_read_warm'])
def act_reg_read(b, n):
    """Read one register: cold (cache invalidated by a write) and warm (cache hit)."""
    dbg = b.dbg
    with b.scratch_reg() as (name, mask):
        last = {}

        def check(i, got):
            return True if got == last['v'] else f'{name} read {got:#x}, expected {last["v"]:#x}'

        def prep(i):
            last['v'] = pattern_value(i, mask)
            b.write_reg(name, last['v'])
        b.run(n, 'reg_read_cold', lambda i: dbg.get_reg_value(name), check, prep)
        dbg.get_reg_value(name)
        b.run(n, 'reg_read_warm', lambda i: dbg.get_reg_value(name), check)


@action('reg_write', ['reg_write'])
def act_reg_write(b, n):
    """Write one register."""
    dbg = b.dbg
    with b.scratch_reg() as (name, mask):
        last = {}

        def check(i, ok):
            if not ok:
                return f'set_reg_value({name}) returned False'
            got = dbg.get_reg_value(name)
            return True if got == last['v'] else f'{name} read back {got:#x}, wrote {last["v"]:#x}'

        def prep(i):
            last['v'] = pattern_value(i, mask)
        b.run(n, 'reg_write', lambda i: dbg.set_reg_value(name, last['v']), check, prep)


@action('regs_all', ['regs_all'])
def act_regs_all(b, n):
    """Fetch every register with its hint, as the UI does on each stop."""
    dbg = b.dbg
    with b.scratch_reg() as (name, mask):
        last = {}

        def check(i, regs):
            r = regs[name]
            if len(regs) == 0 or r is None:
                return 'register list is empty or missing the scratch register'
            return True if r.value == last['v'] else f'{name} listed as {r.value:#x}, expected {last["v"]:#x}'

        def prep(i):
            last['v'] = pattern_value(i, mask)
            b.write_reg(name, last['v'])
        b.run(n, 'regs_all', lambda i: dbg.regs, check, prep)


@action('ip', ['ip_write', 'ip_read_cold', 'ip_read_warm'])
def act_ip(b, n):
    """Set and read the instruction pointer."""
    dbg = b.dbg
    original = dbg.ip
    addrs = b.func_addrs()
    if not addrs:
        raise Skip('no function at the current address to pick instruction addresses from')
    set_ip = lambda a: type(dbg).ip.fset(dbg, a)  # the property setter's bool is lost by `dbg.ip = a`
    cur = {}

    def prep(i):
        cur['a'] = addrs[i % len(addrs)]
    try:
        b.run(n, 'ip_write', lambda i: set_ip(cur['a']),
              lambda i, ok: True if ok and dbg.ip == cur['a'] else f'ip is {dbg.ip:#x} after writing {cur["a"]:#x}',
              prep)

        def prep_cold(i):
            prep(i)
            if not set_ip(cur['a']):
                raise Abort('setup: writing ip failed')
        check = lambda i, got: True if got == cur['a'] else f'ip read {got:#x}, expected {cur["a"]:#x}'
        b.run(n, 'ip_read_cold', lambda i: dbg.ip, check, prep_cold)
        b.run(n, 'ip_read_warm', lambda i: dbg.ip, check)
    finally:
        set_ip(original)


# ==== memory =====================================================================================================

@action('mem_write', ['mem_write'])
def act_mem_write(b, n):
    """Write target memory."""
    dbg = b.dbg
    with b.scratch_mem() as (addr, size):
        last = {}

        def check(i, ok):
            if not ok:
                return f'write_memory({addr:#x}, {size}) returned False'
            return True if bytes(dbg.read_memory(addr, size)) == last['d'] else 'memory read back differs'

        def prep(i):
            last['d'] = mem_pattern(i, size)
        b.run(n, 'mem_write', lambda i: dbg.write_memory(addr, last['d']), check, prep)


@action('mem_read', ['mem_read_cold', 'mem_read_warm'])
def act_mem_read(b, n):
    """Read target memory: cold (cache invalidated by a write) and warm (cache hit)."""
    dbg = b.dbg
    with b.scratch_mem() as (addr, size):
        last = {}

        def check(i, buf):
            return True if buf is not None and bytes(buf) == last['d'] else 'memory read back differs'

        def prep(i):
            last['d'] = mem_pattern(i, size)
            if not dbg.write_memory(addr, last['d']):
                raise Abort(f'setup: write_memory({addr:#x}) failed')
        b.run(n, 'mem_read_cold', lambda i: dbg.read_memory(addr, size), check, prep)
        dbg.read_memory(addr, size)
        b.run(n, 'mem_read_warm', lambda i: dbg.read_memory(addr, size), check)


@action('data_view', ['data_read_cold', 'data_read_warm'])
def act_data_view(b, n):
    """Read target memory through the debugger's BinaryView, the way the UI and scripts usually do."""
    dbg = b.dbg
    with b.scratch_mem() as (addr, size):
        view = dbg.data
        last = {}

        def check(i, data):
            return True if data is not None and bytes(data) == last['d'] else 'BinaryView read differs'

        def prep(i):
            last['d'] = mem_pattern(i, size)
            if not dbg.write_memory(addr, last['d']):
                raise Abort(f'setup: write_memory({addr:#x}) failed')
        b.run(n, 'data_read_cold', lambda i: view.read(addr, size), check, prep)
        view.read(addr, size)
        b.run(n, 'data_read_warm', lambda i: view.read(addr, size), check)


@action('addr_info', ['addr_info_code', 'addr_info_stack'])
def act_addr_info(b, n):
    """Describe an address (module, symbol, memory it points at), as register hints do."""
    dbg = b.dbg
    ok = lambda i, v: True if v is not None else 'no result'
    b.run(n, 'addr_info_code', lambda i: dbg.get_addr_info(dbg.ip), ok)
    b.run(n, 'addr_info_stack', lambda i: dbg.get_addr_info(dbg.stack_pointer), ok)


# ==== target state ===============================================================================================

PROPERTIES = [
    ('ip', lambda d: d.ip), ('last_ip', lambda d: d.last_ip), ('stack_pointer', lambda d: d.stack_pointer),
    ('active_pid', lambda d: d.active_pid), ('remote_arch', lambda d: d.remote_arch),
    ('connected', lambda d: d.connected), ('running', lambda d: d.running),
    ('connection_status', lambda d: d.connection_status), ('target_status', lambda d: d.target_status),
    ('stop_reason', lambda d: d.stop_reason), ('stop_reason_str', lambda d: d.stop_reason_str),
    ('exit_code', lambda d: d.exit_code), ('is_first_launch', lambda d: d.is_first_launch),
    ('is_ttd', lambda d: d.is_ttd),
]


@action('properties', [f'prop_{name}' for name, _ in PROPERTIES])
def act_properties(b, n):
    """Read the controller's cheap state properties (what the UI polls)."""
    for name, read in PROPERTIES:
        b.section([f'prop_{name}'], lambda: b.run(n, f'prop_{name}', lambda i: read(b.dbg)))


@action('processes', ['processes'])
def act_processes(b, n):
    """List the processes on the target system."""
    b.run(n, 'processes', lambda i: b.dbg.processes, lambda i, v: True if len(v) >= 1 else 'no processes listed')


@action('threads', ['threads'])
def act_threads(b, n):
    """List threads: the first read after a stop, with an untimed step before each try."""
    def prep(i):
        b.step_untimed()
    b.run(n, 'threads', lambda i: b.dbg.threads, lambda i, t: True if len(t) >= 1 else 'no threads reported', prep)


@action('modules', ['modules'])
def act_modules(b, n):
    """List loaded modules: the first read after a stop, with an untimed step before each try."""
    def prep(i):
        b.step_untimed()
    b.run(n, 'modules', lambda i: b.dbg.modules, lambda i, m: True if len(m) >= 1 else 'no modules reported', prep)


@action('memory_map', ['memory_map'])
def act_memory_map(b, n):
    """Read the memory map: the first read after a stop, with an untimed step before each try."""
    # Not every adapter can report a memory map, so an empty answer is not treated as a failure.
    def prep(i):
        b.step_untimed()
    b.run(n, 'memory_map', lambda i: b.dbg.memory_map, None, prep)


@action('frames', ['frames'])
def act_frames(b, n):
    """Unwind the stack: the first read after a stop, with an untimed step before each try."""
    dbg = b.dbg
    tid = {}

    def prep(i):
        b.step_untimed()
        tid['v'] = dbg.active_thread.tid
    b.run(n, 'frames', lambda i: dbg.frames_of_thread(tid['v']),
          lambda i, f: True if len(f) >= 1 else 'no frames reported', prep)


@action('thread_ops', ['active_thread_get', 'active_thread_set', 'thread_suspend', 'thread_resume'])
def act_thread_ops(b, n):
    """Get/set the active thread, and suspend/resume a thread."""
    dbg = b.dbg
    threads = list(dbg.threads)
    if not threads:
        raise Abort('no threads reported')
    thread = threads[0]

    def set_active(i):
        dbg.active_thread = thread
    b.section(['active_thread_get'], lambda: b.run(n, 'active_thread_get', lambda i: dbg.active_thread))
    b.section(['active_thread_set'], lambda: b.run(
        n, 'active_thread_set', set_active,
        lambda i, _: True if dbg.active_thread.tid == thread.tid else 'active thread did not change'))

    def suspend_resume():
        def body(i, rec):
            try:
                b.measure('thread_suspend', lambda: dbg.suspend_thread(thread.tid),
                          lambda ok: True if ok else 'suspend_thread returned False', rec)
            finally:
                b.measure('thread_resume', lambda: dbg.resume_thread(thread.tid),
                          lambda ok: True if ok else 'resume_thread returned False', rec)
        b.repeat(n, body)
    b.section(['thread_suspend', 'thread_resume'], suspend_resume)


# ==== breakpoints ================================================================================================

def breakpoint_sites(b) -> List[int]:
    addrs = b.func_addrs()
    if not addrs:
        raise Skip('no function at the current address to place breakpoints in')
    return addrs


@action('breakpoint', ['breakpoint_add', 'breakpoint_remove'])
def act_breakpoint(b, n):
    """Add and remove software breakpoints."""
    dbg, addrs = b.dbg, breakpoint_sites(b)
    with b.breakpoints() as bps:
        def body(i, rec):
            a = addrs[i % len(addrs)]
            bps.track(a)
            b.measure('breakpoint_add', lambda: dbg.add_breakpoint(a),
                      lambda _: True if dbg.has_breakpoint(a) else f'no breakpoint at {a:#x} after add', rec)
            b.measure('breakpoint_remove', lambda: dbg.delete_breakpoint(a),
                      lambda _: True if not dbg.has_breakpoint(a) else f'breakpoint at {a:#x} after remove', rec)
        b.repeat(n, body)


@action('breakpoint_toggle', ['breakpoint_disable', 'breakpoint_enable'])
def act_breakpoint_toggle(b, n):
    """Disable and re-enable a breakpoint."""
    dbg, a = b.dbg, breakpoint_sites(b)[0]

    def enabled():
        return next((x.enabled for x in dbg.breakpoints if x.address == a), None)
    with b.breakpoints() as bps:
        bps.add(a)

        def body(i, rec):
            b.measure('breakpoint_disable', lambda: dbg.disable_breakpoint(a),
                      lambda _: True if enabled() is False else f'breakpoint enabled={enabled()} after disable', rec)
            b.measure('breakpoint_enable', lambda: dbg.enable_breakpoint(a),
                      lambda _: True if enabled() is True else f'breakpoint enabled={enabled()} after enable', rec)
        try:
            b.repeat(n, body)
        finally:
            if enabled() is False:  # enabling an enabled breakpoint is not a no-op on every adapter
                dbg.enable_breakpoint(a)


@action('breakpoint_condition', ['breakpoint_condition_set', 'breakpoint_condition_get'])
def act_breakpoint_condition(b, n):
    """Set and read a breakpoint condition."""
    dbg, a = b.dbg, breakpoint_sites(b)[0]
    reg = b.scratch_register()[0]
    cond = {}

    def prep(i):
        cond['c'] = f'${reg} == {0x1234 + i:#x}'

    def prep_and_set(i):
        prep(i)
        if not dbg.set_breakpoint_condition(a, cond['c']):
            raise Abort('setup: set_breakpoint_condition failed')
    with b.breakpoints() as bps:
        bps.add(a)
        try:
            b.run(n, 'breakpoint_condition_set', lambda i: dbg.set_breakpoint_condition(a, cond['c']),
                  lambda i, ok: True if ok else 'set_breakpoint_condition returned False', prep)
            b.run(n, 'breakpoint_condition_get', lambda i: dbg.get_breakpoint_condition(a),
                  lambda i, got: True if got == cond['c'] else f'condition {got!r}, expected {cond["c"]!r}',
                  prep_and_set)
        finally:
            dbg.set_breakpoint_condition(a, '')


@action('breakpoint_relative', ['breakpoint_add_relative', 'breakpoint_remove_relative'])
def act_breakpoint_relative(b, n):
    """Add and remove module+offset (ASLR-safe) breakpoints."""
    dbg, addrs = b.dbg, breakpoint_sites(b)
    module = b.module_of(addrs[0])
    if module is None:
        raise Skip('no loaded module contains the function being run')
    added = []
    try:
        def body(i, rec):
            rel = b.api.ModuleNameAndOffset(module.short_name, addrs[i % len(addrs)] - module.address)
            added.append(rel)
            b.measure('breakpoint_add_relative', lambda: dbg.add_breakpoint(rel),
                      lambda _: True if dbg.has_breakpoint(rel) else 'no breakpoint after add', rec)
            b.measure('breakpoint_remove_relative', lambda: dbg.delete_breakpoint(rel),
                      lambda _: True if not dbg.has_breakpoint(rel) else 'breakpoint remains after remove', rec)
        b.repeat(n, body)
    finally:
        for rel in added:
            dbg.delete_breakpoint(rel)


@action('breakpoint_list', ['breakpoint_list'])
def act_breakpoint_list(b, n):
    """List breakpoints (20 set)."""
    dbg, addrs = b.dbg, breakpoint_sites(b)
    count = min(20, len(addrs))
    with b.breakpoints() as bps:
        for a in addrs[:count]:
            bps.add(a)
        b.run(n, 'breakpoint_list', lambda i: dbg.breakpoints,
              lambda i, v: True if len(v) >= count else f'{len(v)} breakpoints listed, expected {count}')


HW_KINDS = (('exec', 'BNHardwareExecuteBreakpoint'), ('read', 'BNHardwareReadBreakpoint'),
            ('write', 'BNHardwareWriteBreakpoint'), ('access', 'BNHardwareAccessBreakpoint'))


@action('hw_breakpoint', [f'hw_{kind}_{op}' for kind, _ in HW_KINDS for op in ('add', 'remove')])
def act_hw_breakpoint(b, n):
    """Add and remove hardware execute breakpoints and read/write/access watchpoints."""
    dbg = b.dbg
    exec_addr = b.leaf.start if b.leaf is not None else dbg.ip
    exec_size = 4 if (b.bv.arch.name or '').startswith(('aarch64', 'arm', 'thumb')) else 1
    sp = dbg.stack_pointer
    if not sp:
        raise Skip('stack pointer unavailable; cannot pick a watchpoint address')
    watch_addr = (sp - 0x800) & ~0xf

    def one(kind, bp_type):
        addr, size = (exec_addr, exec_size) if kind == 'exec' else (watch_addr, 8)
        if not dbg.add_hardware_breakpoint(addr, bp_type, size):
            raise Skip(f'adapter does not support hardware {kind} breakpoints')
        dbg.delete_hardware_breakpoint(addr, bp_type, size)

        def body(i, rec):
            b.measure(f'hw_{kind}_add', lambda: dbg.add_hardware_breakpoint(addr, bp_type, size),
                      lambda ok: True if ok else 'add returned False', rec)
            b.measure(f'hw_{kind}_remove', lambda: dbg.delete_hardware_breakpoint(addr, bp_type, size),
                      lambda ok: True if ok else 'remove returned False', rec)
        try:
            b.repeat(n, body)
        finally:
            dbg.delete_hardware_breakpoint(addr, bp_type, size)
    for kind, attr in HW_KINDS:
        b.section([f'hw_{kind}_add', f'hw_{kind}_remove'], lambda: one(kind, getattr(b.api.DebugBreakpointType, attr)))


# ==== symbols, rebasing ==========================================================================================

@action('symbols', ['symbols_load', 'symbols_list', 'symbols_count', 'symbols_remove'])
def act_symbols(b, n):
    """Load, query and remove one module's backend symbols."""
    dbg = b.dbg
    main = os.path.realpath(b.fpath)
    module = None
    for m in dbg.modules:
        name = m.name or m.short_name
        if not name or os.path.realpath(name) == main:
            continue
        if dbg.load_symbols_for_module(name) > 0:
            dbg.remove_symbols_for_module(name)
            module = name
            break
    if module is None:
        raise Skip('no non-main module reported backend symbols for this adapter')
    positive = lambda c: True if c > 0 else f'count was {c}'

    def body(i, rec):
        b.measure('symbols_load', lambda: dbg.load_symbols_for_module(module), positive, rec)
        b.measure('symbols_list', lambda: dbg.modules_with_loaded_symbols,
                  lambda v: True if v else 'no module listed as loaded', rec)
        b.measure('symbols_count', lambda: dbg.loaded_symbol_count_for_module(module), positive, rec)
        b.measure('symbols_remove', lambda: dbg.remove_symbols_for_module(module), positive, rec)
    try:
        b.repeat(n, body)
    finally:
        dbg.remove_all_loaded_symbols()


@action('symbols_all', ['symbols_load_all', 'symbols_remove_all'])
def act_symbols_all(b, n):
    """Load and remove the backend symbols of every module."""
    dbg = b.dbg
    positive = lambda c: True if c > 0 else f'count was {c}'

    def body(i, rec):
        b.measure('symbols_load_all', dbg.load_symbols_for_all_modules, positive, rec)
        b.measure('symbols_remove_all', dbg.remove_all_loaded_symbols, positive, rec)
    try:
        b.repeat(n, body)
    finally:
        dbg.remove_all_loaded_symbols()


@action('rebase', ['remote_base_get', 'rebase_to_remote_base', 'rebase_to_address'])
def act_rebase(b, n):
    """Get the remote base and rebase the BinaryView to it."""
    dbg = b.dbg
    base = dbg.get_remote_base()
    if base is None:
        raise Skip('adapter does not report a remote base')
    try:
        b.section(['remote_base_get'], lambda: b.run(
            n, 'remote_base_get', lambda i: dbg.get_remote_base(),
            lambda i, v: True if v == base else f'remote base {v} != {base:#x}'))
        ok = lambda i, v: True if v else 'rebase was refused'
        b.section(['rebase_to_remote_base'], lambda: b.run(n, 'rebase_to_remote_base',
                                                           lambda i: dbg.rebase_to_remote_base(), ok))
        b.section(['rebase_to_address'], lambda: b.run(n, 'rebase_to_address',
                                                       lambda i: dbg.rebase_to_address(base), ok))
    finally:
        b.refresh_symbols()


# ==== events and I/O =============================================================================================

@action('events', ['event_register', 'event_remove', 'step_into_with_events'])
def act_events(b, n):
    """Register/remove an event callback, and step with a callback registered."""
    dbg = b.dbg
    seen = []
    callback = lambda event: seen.append(event.type)

    def register_remove():
        def body(i, rec):
            handle = b.measure('event_register', lambda: dbg.register_event_callback(callback, 'perf'),
                               lambda h: True if h is not None else 'no handle returned', rec)
            b.measure('event_remove', lambda: dbg.remove_event_callback(handle), None, rec)
        b.repeat(n, body)
    b.section(['event_register', 'event_remove'], register_remove)

    def step_with_callback():
        handle = dbg.register_event_callback(callback, 'perf')
        try:
            b.run(n, 'step_into_with_events', lambda i: dbg.step_into_and_wait(timeout=b.opts.timeout),
                  b.expect(b.R.SingleStep))
        finally:
            dbg.remove_event_callback(handle)
    b.section(['step_into_with_events'], step_with_callback)


@action('stdin', ['stdin_write'])
def act_stdin(b, n):
    """Write to the target's stdin (Linux and macOS only)."""
    if sys.platform == 'win32':
        raise Skip('write_stdin only works on Linux and macOS')
    b.run(n, 'stdin_write', lambda i: b.dbg.write_stdin(b'x\n'))


@action('backend_command', ['backend_command'])
def act_backend_command(b, n):
    """Run a command in the backend debugger and read its output (--backend-command)."""
    command = b.opts.backend_command or DEFAULT_BACKEND_COMMANDS.get(b.adapter)
    if not command:
        raise Skip(f'no known backend command for adapter {b.adapter!r}; pass --backend-command')
    b.run(n, 'backend_command', lambda i: b.dbg.execute_backend_command(command),
          lambda i, out: True if isinstance(out, str) else f'returned {type(out).__name__}, not a string')


@action('adapter_property', ['adapter_property_get', 'adapter_property_set'])
def act_adapter_property(b, n):
    """Get and set an adapter property (the first --adapter-property key)."""
    if not b.opts.adapter_property:
        raise Skip('no adapter property configured; pass --adapter-property KEY=VALUE')
    key, value = parse_property(b.opts.adapter_property[0])
    b.section(['adapter_property_get'], lambda: b.run(n, 'adapter_property_get',
                                                      lambda i: b.dbg.get_adapter_property(key)))
    b.section(['adapter_property_set'], lambda: b.run(
        n, 'adapter_property_set', lambda i: b.dbg.set_adapter_property(key, value),
        lambda i, ok: True if ok else 'set_adapter_property returned False'))


# ==== time-travel debugging (TTD adapters only) ==================================================================

TTD_RESULTS = ['ttd_position_get', 'ttd_position_set', 'ttd_bookmark_add', 'ttd_bookmark_list',
               'ttd_bookmark_remove', 'ttd_next_mem_access', 'ttd_prev_mem_access', 'ttd_mem_access_range',
               'ttd_next_reg_write', 'ttd_prev_reg_write', 'ttd_events_all', 'ttd_calls', 'ttd_coverage_run',
               'ttd_coverage_query']


@action('ttd', TTD_RESULTS)
def act_ttd(b, n):
    """Trace positions, bookmarks, memory/register history, events, calls and code coverage (TTD adapters only)."""
    dbg = b.dbg
    if not dbg.is_ttd:
        raise Skip('needs a time-travel (TTD) adapter')
    position = dbg.current_ttd_position
    if position is None:
        raise Abort('no current TTD position')
    access = b.api.DebuggerTTDMemoryAccessType
    sp = dbg.stack_pointer
    reg = b.scratch_register()[0]

    b.section(['ttd_position_get'], lambda: b.run(
        n, 'ttd_position_get', lambda i: dbg.current_ttd_position,
        lambda i, p: True if p is not None else 'no position'))
    b.section(['ttd_position_set'], lambda: b.run(
        n, 'ttd_position_set', lambda i: dbg.set_ttd_position(position),
        lambda i, ok: True if ok else 'navigation failed'))

    def bookmarks():
        def body(i, rec):
            b.measure('ttd_bookmark_add', lambda: dbg.add_ttd_bookmark(position, 'perf', dbg.ip),
                      lambda ok: True if ok else 'add returned False', rec)
            b.measure('ttd_bookmark_list', lambda: dbg.ttd_bookmarks,
                      lambda v: True if v else 'bookmark not listed', rec)
            b.measure('ttd_bookmark_remove', lambda: dbg.remove_ttd_bookmark(position),
                      lambda ok: True if ok else 'remove returned False', rec)
        try:
            b.repeat(n, body)
        finally:
            dbg.remove_ttd_bookmark(position)
    b.section(['ttd_bookmark_add', 'ttd_bookmark_list', 'ttd_bookmark_remove'], bookmarks)

    b.section(['ttd_next_mem_access'], lambda: b.run(
        n, 'ttd_next_mem_access', lambda i: dbg.get_ttd_next_memory_access(sp, 8, access.DebuggerTTDMemoryWrite)))
    b.section(['ttd_prev_mem_access'], lambda: b.run(
        n, 'ttd_prev_mem_access', lambda i: dbg.get_ttd_prev_memory_access(sp, 8, access.DebuggerTTDMemoryWrite)))
    b.section(['ttd_mem_access_range'], lambda: b.run(
        n, 'ttd_mem_access_range', lambda i: dbg.get_ttd_memory_access_for_address(sp - 0x100, sp, 'rw')))
    b.section(['ttd_next_reg_write'], lambda: b.run(n, 'ttd_next_reg_write',
                                                    lambda i: dbg.get_ttd_next_register_write(reg)))
    b.section(['ttd_prev_reg_write'], lambda: b.run(n, 'ttd_prev_reg_write',
                                                    lambda i: dbg.get_ttd_prev_register_write(reg)))
    b.section(['ttd_events_all'], lambda: b.run(n, 'ttd_events_all', lambda i: dbg.get_all_ttd_events()))

    def calls():
        if not b.opts.ttd_symbol:
            raise Skip('no symbol to query calls for; pass --ttd-symbol')
        b.run(n, 'ttd_calls', lambda i: dbg.get_ttd_calls_for_symbols(b.opts.ttd_symbol))
    b.section(['ttd_calls'], calls)

    def coverage():
        work = b.need_leaf() and b.work
        rng = next(iter(work.address_ranges))
        b.run(n, 'ttd_coverage_run', lambda i: dbg.run_code_coverage_analysis(rng.start, rng.end),
              lambda i, ok: True if ok else 'analysis failed')
        b.run(n, 'ttd_coverage_query', lambda i: dbg.get_executed_instruction_count(),
              lambda i, c: True if c > 0 else 'no instructions reported as executed')
    b.section(['ttd_coverage_run', 'ttd_coverage_query'], coverage)


# ==== actions that end the session ===============================================================================
# These leave no usable target (or a restarted one), so they run last; later work relaunches as needed.

@action('restart', ['restart'], ends_session=True)
def act_restart(b, n):
    """Restart the target."""
    b.run(n, 'restart', lambda i: b.dbg.restart_and_wait(b.opts.timeout), b.not_failed)
    b.ready = False


@action('attach_detach', ['attach', 'detach'], ends_session=True)
def act_attach_detach(b, n):
    """Attach to a running process and detach from it (the script starts the process itself)."""
    dbg = b.dbg
    if b.opts.connect:
        raise Skip('attach needs a process the script can start locally, not --connect')
    b.kill()
    exe = b.opts.executable_path or b.fpath
    posix = os.name == 'posix'

    def body(i, rec):
        proc = subprocess.Popen([exe], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=posix)
        try:
            time.sleep(0.05)  # let it get past exec before attaching
            dbg.pid_attach = proc.pid
            b.measure('attach', lambda: dbg.attach_and_wait(b.opts.timeout), lambda reason: b.not_failed(0, reason), rec)
            b.measure('detach', lambda: dbg.detach_and_wait(b.opts.timeout),
                      lambda _: True if not dbg.connected else 'still connected after detach', rec)
        finally:
            if dbg.connected:
                dbg.quit_and_wait(b.opts.timeout)
            proc.kill()  # detaching leaves it running
            proc.wait(timeout=10)
    try:
        b.repeat(n, body)
    finally:
        b.ready = False


@action('lifecycle', ['launch', 'quit'], ends_session=True)
def act_lifecycle(b, n):
    """Launch (or connect to) the target and quit it, n full cycles."""
    dbg = b.dbg
    b.kill()

    def body(i, rec):
        try:
            b.measure('connect' if b.opts.connect else 'launch', b.connect_or_launch,
                      lambda reason: b.not_failed(i, reason), rec)
        finally:
            # Always try to tear down so a failed iteration does not leak a target.
            if dbg.connected:
                b.measure('quit', lambda: dbg.quit_and_wait(b.opts.timeout),
                          lambda _: True if not dbg.connected else 'still connected after quit', rec)
    b.repeat(n, body, warmup=0)
    b.ready = False


GROUPS = [a.group for a in ACTIONS]
