#!/usr/bin/env python3
#
# Adapter-agnostic performance benchmark for the debugger.
#
# Runs each debugger action N times against a live target and reports how long each call took. It only uses
# the public DebuggerController Python API, so it works with any registered debug adapter; the adapter is just
# a name string (see --list-adapters). Numbers are wall-clock time of the blocking controller call, so they
# include the controller's own work (state updates, cache invalidation, events), not only the adapter's.
#
#   python3 perf_benchmark.py -n 100                    # 100 tries of every action, default adapter
#   python3 perf_benchmark.py -n 100 --adapter LLDB --adapter "GDB MI"
#   python3 perf_benchmark.py -n 100 --out history.json --label "after register cache change"
#   python3 perf_benchmark.py --list-adapters
#   python3 perf_benchmark.py --list-actions
#
# The actions live in perf_actions.py. See the "Performance benchmark" section of test/README.md.

import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional

from perf_actions import ACTIONS, DEFAULT_BINARY, GROUPS, Abort, Bench, Skip, parse_property

DEFAULT_ITERATIONS = 100
DEFAULT_WARMUP = 3
DEFAULT_TIMEOUT_MS = 30000

# Version of the --out file layout. Bump it when a field is renamed or changes meaning, not when one is added.
HISTORY_SCHEMA = 1


def fmt_ns(ns: float) -> str:
    if ns < 1e3:
        return f'{ns:.0f} ns'
    if ns < 1e6:
        return f'{ns / 1e3:.1f} us'
    if ns < 1e9:
        return f'{ns / 1e6:.2f} ms'
    return f'{ns / 1e9:.2f} s'


# ---- running ----------------------------------------------------------------------------------------------------

def run_actions(bench: Bench, selected: List[str], counts: Dict[str, int], default_n: int) -> None:
    for act in ACTIONS:
        if act.group not in selected:
            continue
        n = counts.get(act.group, default_n)
        print(f'  {act.group:<20} x{n} ...', end='', flush=True, file=sys.stderr)
        t0 = time.perf_counter()
        try:
            # Session-ending actions manage their own target, except restart, which needs a live one.
            if not act.ends_session or act.group == 'restart':
                bench.ensure_ready()
            act.fn(bench, n)
            status = 'done'
        except Skip as e:
            for name in act.results:
                bench.result(name).skipped = str(e)
            status = f'skipped ({e})'
        except Abort as e:
            for name in act.results:
                if name in bench.results:
                    bench.results[name].aborted = str(e)
            bench.ready = False
            status = f'aborted ({e})'
        except KeyboardInterrupt:
            raise
        except Exception as e:
            for name in act.results:
                bench.result(name).aborted = f'{type(e).__name__}: {e}'
            bench.ready = False
            status = f'error ({type(e).__name__}: {e})'
            if bench.opts.verbose:
                import traceback
                traceback.print_exc()
        print(f' {status} [{time.perf_counter() - t0:.1f}s]', file=sys.stderr)


class EntryStopSettings:
    """Launching only returns once the target stops, so make it stop at its entry point, and restore on exit.

    The settings are registered when the first controller is constructed, so apply() must come after that."""
    KEYS = (('debugger.stopAtEntryPoint', True), ('debugger.stopAtSystemEntryPoint', False))

    def __init__(self):
        self.saved = {}

    def apply(self) -> None:
        if self.saved:
            return
        from binaryninja import Settings
        settings = Settings()
        for key, value in self.KEYS:
            self.saved[key] = settings.get_bool(key)
            settings.set_bool(key, value)

    def restore(self) -> None:
        from binaryninja import Settings
        settings = Settings()
        for key, value in self.saved.items():
            settings.set_bool(key, value)


def run_adapter(adapter: Optional[str], fpath: str, args, api, selected, counts, entry_settings) -> dict:
    from binaryninja import load
    bv = load(fpath)
    dbg = api.DebuggerController(bv)
    if not args.connect:
        entry_settings.apply()
    if adapter:
        available = api.DebugAdapterType.get_available_adapters(bv)
        if not args.connect and adapter not in available:
            raise SystemExit(f'adapter {adapter!r} cannot debug this target; available: {", ".join(available)}')
        dbg.adapter_type = adapter
    adapter = dbg.adapter_type
    if args.executable_path:
        dbg.executable_path = args.executable_path
    if args.connect:
        host, _, port = args.connect.rpartition(':')
        dbg.remote_host, dbg.remote_port = host, int(port)
    for item in args.adapter_property:
        key, value = parse_property(item)
        if not dbg.set_adapter_property(key, value):
            print(f'warning: adapter rejected property {key!r}', file=sys.stderr)

    bench = Bench(dbg, bv, api, args, adapter, fpath)
    print(f'\nadapter {adapter}', file=sys.stderr)
    try:
        run_actions(bench, selected, counts, args.iterations)
    finally:
        try:
            bench.kill()
        except Exception as e:
            print(f'warning: could not shut the target down: {e}', file=sys.stderr)
    return {'adapter': adapter, 'bench': bench}


# ---- reporting --------------------------------------------------------------------------------------------------

def print_table(bench: Bench, header: str) -> None:
    print(f'\n{header}')
    cols = f'{"action":<28}{"n":>5}{"fail":>6}{"min":>11}{"mean":>11}{"median":>11}{"p95":>11}{"max":>11}{"ops/s":>10}'
    print(cols)
    print('-' * len(cols))
    for res in bench.results.values():
        s = res.stats()
        fails = len(res.failed_ns)
        if res.skipped:
            print(f'{res.name:<28}  skipped: {res.skipped}')
            continue
        if s is None:
            print(f'{res.name:<28}{0:>5}{fails:>6}  {res.aborted or "no successful samples"}')
        else:
            print(f'{res.name:<28}{s["n"]:>5}{fails:>6}{fmt_ns(s["min_ns"]):>11}{fmt_ns(s["mean_ns"]):>11}'
                  f'{fmt_ns(s["median_ns"]):>11}{fmt_ns(s["p95_ns"]):>11}{fmt_ns(s["max_ns"]):>11}'
                  f'{s["ops_per_sec"]:>10.1f}')
            if res.aborted:
                print(f'{"":<28}  aborted early: {res.aborted}')
        for d in res.details:
            print(f'{"":<28}  ! {d}')


def print_comparison(runs: List[dict]) -> None:
    names = []
    for r in runs:
        for n in r['bench'].results:
            if n not in names:
                names.append(n)
    print('\nMedian per action (ratio is relative to the first adapter)')
    print(f'{"action":<28}' + ''.join(f'{r["adapter"][:20]:>22}' for r in runs))
    for name in names:
        row, base = f'{name:<28}', None
        for r in runs:
            res = r['bench'].results.get(name)
            s = res.stats() if res else None
            if s is None:
                row += f'{"-":>22}'
                continue
            med = s['median_ns']
            base = med if base is None else base
            ratio = '' if med == base or not base else f' ({med / base:.2f}x)'
            row += f'{fmt_ns(med) + ratio:>22}'
        print(row)


# ---- the --out history file -------------------------------------------------------------------------------------

def git_info() -> dict:
    """The debugger repository's state, so a run can be placed on a timeline of commits."""
    here = os.path.dirname(os.path.realpath(__file__))

    def git(*cmd) -> Optional[str]:
        try:
            out = subprocess.run(['git', '-C', here, *cmd], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out.stdout.strip() if out.returncode == 0 else None
    commit = git('rev-parse', 'HEAD')
    if commit is None:
        return {}
    status = git('status', '--porcelain', '--untracked-files=no')
    return {
        'commit': commit,
        'branch': git('rev-parse', '--abbrev-ref', 'HEAD'),
        'commit_date': git('log', '-1', '--format=%cI'),
        'subject': git('log', '-1', '--format=%s'),
        'dirty': bool(status),  # tracked files differ from the commit, so the numbers may not match it
    }


def build_record(args, runs: List[dict], fpath: str, selected: List[str], counts: Dict[str, int],
                 interrupted: bool) -> dict:
    import binaryninja
    return {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'label': args.label,
        'git': git_info(),
        'binaryninja': binaryninja.core_version(),
        'host': {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'machine': platform.machine(),
            'cpus': os.cpu_count(),
            'python': platform.python_version(),
        },
        'target': {'binary': os.path.basename(fpath), 'arch': args.arch},
        'config': {
            'iterations': args.iterations,
            'warmup': args.warmup,
            'timeout_ms': args.timeout,
            'mem_size': args.mem_size,
            'groups': selected,
            'group_iterations': {g: counts.get(g, args.iterations) for g in selected},
            'connect': args.connect,
        },
        'complete': not interrupted,
        'adapters': [{'name': r['adapter'],
                      'results': [x.to_json(args.samples) for x in r['bench'].results.values()]} for r in runs],
    }


def append_history(path: str, record: dict) -> int:
    """Add a run to the history file, creating it if needed. Returns how many runs it now holds.

    An existing file that is not a history file is left alone rather than overwritten."""
    doc = {'schema': HISTORY_SCHEMA, 'runs': []}
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path) as f:
                doc = json.load(f)
            valid = isinstance(doc, dict) and doc.get('schema') == HISTORY_SCHEMA and isinstance(doc.get('runs'), list)
        except ValueError:
            valid = False
        if not valid:
            raise SystemExit(f'{path} exists but is not a schema {HISTORY_SCHEMA} perf history file; '
                             f'refusing to overwrite it. Choose another --out path.')
    doc['runs'].append(record)
    # Write beside the target and rename, so an interrupted write cannot corrupt the history so far.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return len(doc['runs'])


def write_csv(path: str, runs: List[dict]) -> None:
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['adapter', 'action', 'ok', 'duration_ns'])
        for r in runs:
            for res in r['bench'].results.values():
                for ns in res.samples_ns:
                    w.writerow([r['adapter'], res.name, 1, ns])
                for ns in res.failed_ns:
                    w.writerow([r['adapter'], res.name, 0, ns])


# ---- command line -----------------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='Time debugger actions against a live target, N tries each, for any debug adapter.',
        epilog='action groups: ' + ', '.join(GROUPS),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('-n', '--iterations', type=int, default=DEFAULT_ITERATIONS,
                   help=f'tries per action (default {DEFAULT_ITERATIONS})')
    p.add_argument('--set', action='append', default=[], metavar='GROUP=N',
                   help='override the tries for one action group, e.g. --set lifecycle=10 (repeatable)')
    p.add_argument('--warmup', type=int, default=DEFAULT_WARMUP,
                   help=f'untimed tries before each timed run (default {DEFAULT_WARMUP}; not used for lifecycle)')
    p.add_argument('--adapter', action='append', default=[], metavar='NAME',
                   help='adapter name, e.g. LLDB or "GDB MI"; repeat to compare (default: the platform default)')
    p.add_argument('--adapter-property', action='append', default=[], metavar='KEY=VALUE',
                   help='adapter property, e.g. gdb.path=/usr/bin/gdb (repeatable)')
    p.add_argument('--connect', metavar='HOST:PORT',
                   help='connect to a debug server instead of launching the target')
    p.add_argument('--binary', default=DEFAULT_BINARY,
                   help=f'target: a test-binary name or a path (default {DEFAULT_BINARY})')
    p.add_argument('--arch', default=platform.machine(), help='architecture directory of the test binaries')
    p.add_argument('--executable-path', help='executable path to give the debugger, if not the analyzed binary')
    p.add_argument('--actions', help='comma-separated action groups to run (default: all)')
    p.add_argument('--skip', help='comma-separated action groups to leave out')
    p.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT_MS, help='per-call timeout in ms')
    p.add_argument('--scratch-register', help='register the write/read actions use (default: chosen per arch)')
    p.add_argument('--mem-size', type=int, default=256, help='bytes per memory read/write (default 256)')
    p.add_argument('--pause-delay-ms', type=int, default=10, help='how long the target runs before pause is timed')
    p.add_argument('--backend-command', help='command for the backend_command action (default: per adapter)')
    p.add_argument('--ttd-symbol', help='symbol whose calls the ttd action queries')
    p.add_argument('--out', '--json', dest='out', metavar='PATH',
                   help='add this run to a JSON history file (created if missing), to track performance over time')
    p.add_argument('--label', help='free-text label stored with the run in --out, e.g. what changed')
    p.add_argument('--samples', action='store_true', help='also store every raw timing in --out')
    p.add_argument('--csv', metavar='PATH', help='write one row per timed call as CSV')
    p.add_argument('--list-adapters', action='store_true', help='list the adapters usable with the target and exit')
    p.add_argument('--list-actions', action='store_true', help='list the action groups and exit')
    p.add_argument('-v', '--verbose', action='store_true')
    return p


def parse_selection(args, parser) -> List[str]:
    selected = args.actions.split(',') if args.actions else list(GROUPS)
    skipped = args.skip.split(',') if args.skip else []
    for g in selected + skipped:
        if g not in GROUPS:
            parser.error(f'unknown action group {g!r}; choose from: {", ".join(GROUPS)}')
    return [g for g in selected if g not in skipped]


def parse_counts(args, parser) -> Dict[str, int]:
    counts = {}
    for item in args.set:
        group, _, value = item.partition('=')
        if group not in GROUPS or not value.isdigit() or int(value) < 1:
            parser.error(f'--set expects GROUP=N with GROUP in {", ".join(GROUPS)} and N >= 1, got {item!r}')
        counts[group] = int(value)
    return counts


def import_debugger():
    """Import the debugger Python API, from the standalone plugin or Binary Ninja's bundled copy."""
    import importlib
    failures = []
    for module in ('debugger', 'binaryninja.debugger'):
        try:
            api = importlib.import_module(module)
        except Exception as e:  # a broken plugin can fail in many ways, e.g. a missing native library
            failures.append(f'  import {module}: {type(e).__name__}: {e}')
            continue
        if hasattr(api, 'DebuggerController'):
            return api
        failures.append(f'  import {module}: loaded, but it does not export DebuggerController')
    hint = ''
    if os.environ.get('BN_STANDALONE_DEBUGGER') or os.environ.get('BN_DISABLE_CORE_DEBUGGER'):
        hint = ('\nBN_STANDALONE_DEBUGGER or BN_DISABLE_CORE_DEBUGGER is set in this environment. With '
                'BN_STANDALONE_DEBUGGER the debugger is only loaded from the user plugin directory (which needs '
                'libdebuggercore there); unset it to use the copy bundled with Binary Ninja.')
    raise SystemExit('could not import the debugger Python API:\n' + '\n'.join(failures) + hint)


def resolve_binary(opts) -> str:
    from debugger_test import name_to_fpath
    if os.path.sep in opts.binary or os.path.isfile(opts.binary):
        return os.path.realpath(opts.binary)
    return name_to_fpath(opts.binary, opts.arch)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.iterations < 1 or args.warmup < 0:
        parser.error('--iterations must be >= 1 and --warmup >= 0')
    if args.list_actions:
        for act in ACTIONS:
            note = '  (ends the session; runs last)' if act.ends_session else ''
            print(f'{act.group:<20} {act.description}{note}')
            print(f'{"":<20}   -> {", ".join(act.results)}')
        return 0
    selected = parse_selection(args, parser)
    counts = parse_counts(args, parser)

    api = import_debugger()
    fpath = resolve_binary(args)
    if not os.path.exists(fpath):
        parser.error(f'target binary not found: {fpath}\n'
                     f'Build the test binaries (-DBUILD_DEBUGGER_TEST_BINARIES=ON) or pass --binary.')

    if args.list_adapters:
        from binaryninja import load
        for name in api.DebugAdapterType.get_available_adapters(load(fpath)):
            print(name)
        return 0

    entry_settings = EntryStopSettings()
    runs: List[dict] = []
    interrupted = False
    try:
        for adapter in args.adapter or [None]:
            try:
                runs.append(run_adapter(adapter, fpath, args, api, selected, counts, entry_settings))
            except KeyboardInterrupt:
                interrupted = True
                break
    finally:
        entry_settings.restore()

    import binaryninja
    for r in runs:
        header = (f'adapter: {r["adapter"]}   target: {os.path.basename(fpath)}   '
                  f'binaryninja {binaryninja.core_version()}   {args.iterations} tries + {args.warmup} warmup')
        print_table(r['bench'], header)
    if len(runs) > 1:
        print_comparison(runs)
    if interrupted:
        print('\ninterrupted; results above are partial')
    if args.out and runs:
        count = append_history(args.out, build_record(args, runs, fpath, selected, counts, interrupted))
        print(f'\nappended this run to {args.out} ({count} run{"s" if count != 1 else ""} in the history)')
    if args.csv:
        write_csv(args.csv, runs)

    problems = any(res.failed_ns or res.aborted for r in runs for res in r['bench'].results.values())
    return 1 if problems or interrupted else 0


if __name__ == '__main__':
    sys.exit(main())
