"""Run the standalone C++ ptrace scenarios through the debugger's pytest runner.

CMake builds the fixtures. Each case runs in a separate supervised process, so a
native hang, signal-handler change or crash cannot take down the rest of pytest.
This module also serves as that supervisor; it does not load Binary Ninja.
"""

import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time


def _children(pid):
    """Include children forked by any thread, and children in new sessions."""
    result = set()
    for task in Path(f'/proc/{pid}/task').glob('*/children'):
        try:
            result.update(int(child) for child in task.read_text().split())
        except FileNotFoundError:
            pass
    return result


def _descendants(pid):
    found = set()
    pending = [pid]
    while pending:
        for child in _children(pending.pop()) - found:
            found.add(child)
            pending.append(child)
    return found


def _kill(pids):
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _worker(timeout, command):
    import resource

    # Inferiors can create sessions or become detached. A subreaper adopts those
    # orphans so even a crashing driver cannot leave them behind or leave zombies.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    timed_out = False
    with tempfile.TemporaryFile() as output:
        proc = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            _kill(_descendants(os.getpid()))
            proc.wait(timeout=5)
            deadline = time.monotonic() + 5
            while True:
                _kill(_descendants(os.getpid()))
                try:
                    while os.waitpid(-1, os.WNOHANG)[0]:
                        pass
                except ChildProcessError:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('Could not reap all ptrace test descendants')
                time.sleep(0.01)
        output.seek(0)
        return {'returncode': proc.returncode, 'timed_out': timed_out,
                'output': output.read().decode('utf-8', errors='replace')}


if __name__ == '__main__':
    print(json.dumps(_worker(float(sys.argv[1]), sys.argv[2:])))
    sys.exit(0)


import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='ptrace requires Linux')
ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / 'test' / 'ptrace_engine'
SANITIZER_ERROR = re.compile(r'ERROR: (?:AddressSanitizer|LeakSanitizer)|WARNING: ThreadSanitizer|runtime error:')


def _case_names(driver):
    source = (SOURCES / f'{driver}.cpp').read_text().split('int main(', 1)[1]
    names = re.findall(r'\{"([a-z0-9_]+)",\s*\w+\}', source)
    if not names:
        raise ValueError(f'No scenarios found in {driver}.cpp')
    return names


CASES = [(driver, name) for driver in ('driver', 'fault_driver', 'review_driver')
         for name in _case_names(driver)]


def _run(command, directory, timeout=120, env=None):
    worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), str(timeout), *map(str, command)],
                              cwd=directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              start_new_session=True)
    try:
        output, _ = worker.communicate(timeout=timeout + 15)
    except subprocess.TimeoutExpired:
        os.killpg(worker.pid, signal.SIGKILL)
        output, _ = worker.communicate(timeout=5)
        pytest.fail(f'Test supervisor exceeded its deadline: {command}\n{output.decode(errors="replace")}')
    finally:
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        worker.wait(timeout=5)
    assert worker.returncode == 0, output.decode(errors='replace')
    result = json.loads(output)
    assert not result['timed_out'], f'Native test exceeded {timeout}s: {command}\n{result["output"]}'
    return result


def _extras():
    extras = set(filter(None, os.environ.get('PTRACE_TEST_EXTRAS', '').split(',')))
    unknown = extras - {'review', 'diagnostics', 'benchmark'}
    if unknown:
        pytest.fail(f'Unknown PTRACE_TEST_EXTRAS: {sorted(unknown)}')
    return extras


@pytest.fixture(scope='module')
def native():
    directory = Path(os.environ.get('PTRACE_TEST_BUILD_DIR', ROOT / 'build' / 'test' / 'ptrace_engine')).resolve()
    config_file = directory / 'ptrace_test_config.json'
    if not config_file.is_file():
        message = f'Build ptrace_tests and set PTRACE_TEST_BUILD_DIR to its output directory: {directory}'
        if 'PTRACE_TEST_BUILD_DIR' in os.environ:
            pytest.fail(message)
        pytest.skip(message)
    config = json.loads(config_file.read_text())
    for name in ('driver', 'fault_driver', 'review_driver', 'event_exception_demo', 'elfcmp', 'layout', 'hwabi',
                 'progs', 'progs_pad', 'libtest.so'):
        assert (directory / name).is_file(), f'Missing built ptrace fixture: {directory / name}'
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    # A caller can still provide runtime-specific options; diagnostics below also
    # catch recoverable sanitizer reports whose process happened to exit zero.
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    env.setdefault('UBSAN_OPTIONS', 'halt_on_error=1:print_stacktrace=1')
    env.setdefault('TSAN_OPTIONS', 'halt_on_error=1:report_signal_unsafe=0:second_deadlock_stack=1')
    env['PTRACE_TEST_DIR'] = str(directory)
    prefix = []
    if cpus := env.get('PTRACE_TEST_CPUS'):
        selected = {int(cpu) for cpu in cpus.split(',')}
        assert selected and selected <= os.sched_getaffinity(0), f'Unavailable CPUs: {cpus}'
        taskset = shutil.which('taskset')
        assert taskset, 'PTRACE_TEST_CPUS requires taskset'
        prefix = [taskset, '--cpu-list', cpus]
    timeout = float(env.get('PTRACE_TEST_TIMEOUT', '120'))
    repeat = int(env.get('PTRACE_TEST_REPEAT', '1'))
    assert timeout > 0 and repeat > 0, 'PTRACE_TEST_TIMEOUT and PTRACE_TEST_REPEAT must be positive'

    def run(program, *arguments):
        return _run([*prefix, directory / program, *arguments], directory, timeout, env)

    return directory, config, repeat, run


def _assert_success(result):
    assert result['returncode'] == 0, result['output']
    assert not SANITIZER_ERROR.search(result['output']), result['output']
    # The C++ harness prints skips for unavailable kernel/architecture features.
    # Do not turn a failing test into a skip just because it also printed SKIP.
    if re.search(r'^\s*SKIP\b', result['output'], re.MULTILINE):
        pytest.skip(result['output'])


@pytest.mark.parametrize('driver,name', CASES, ids=[f'{driver}-{name}' for driver, name in CASES])
def test_native_scenario(native, driver, name):
    extras = _extras()
    if driver == 'review_driver' and name != 'maps_cost' and 'review' not in extras:
        pytest.skip('Known review repro; enable with PTRACE_TEST_EXTRAS=review')
    if name.startswith('repro_') and 'diagnostics' not in extras:
        pytest.skip('Diagnostic repro; enable with PTRACE_TEST_EXTRAS=diagnostics')
    if name in ('perf', 'maps_cost') and 'benchmark' not in extras:
        pytest.skip('Measurement; enable with PTRACE_TEST_EXTRAS=benchmark')
    _, _, repeat, run = native
    for iteration in range(repeat):
        result = run(driver, name)
        print(f'{driver}/{name} iteration {iteration + 1}/{repeat}\n{result["output"]}', end='')
        _assert_success(result)


@pytest.mark.parametrize('driver', ['driver', 'fault_driver', 'review_driver'])
def test_driver_selection(native, driver):
    *_, run = native
    result = run(driver, '--list')
    _assert_success(result)
    assert result['output'].splitlines() == _case_names(driver)
    result = run(driver, 'not-a-real-test')
    assert result['returncode'] == 2, result['output']
    assert 'Unknown test:' in result['output']


@pytest.mark.parametrize('program', ['layout', 'hwabi'])
def test_register_abi(native, program):
    *_, run = native
    _assert_success(run(program))


@pytest.mark.parametrize('name', ['progs', 'progs_pad', 'libtest.so',
                                  'Linux-x86/helloworld', 'Linux-x86_64/helloworld'])
def test_elf_symbols(native, name):
    directory, _, _, run = native
    binary = ROOT / 'test' / 'binaries' / name if name.startswith('Linux-') else directory / name
    _compare_elf_symbols(binary, run)


def _compare_elf_symbols(binary, run):
    readelf = shutil.which('readelf')
    assert readelf, 'ELF comparison requires binutils/readelf'
    result = run('elfcmp', str(binary))
    _assert_success(result)
    actual = set()
    for line in result['output'].splitlines():
        symbol, address, size, function = line.split()
        actual.add((symbol, int(address, 16), int(size), int(function)))
    reference = subprocess.run([readelf, '-sW', str(binary)], check=True,
                               capture_output=True, text=True, timeout=10, env={**os.environ, 'LC_ALL': 'C'})
    expected = set()
    for line in reference.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r'\d+:', fields[0]):
            continue
        _, address, size, kind, _, _, section, symbol = fields[:8]
        if kind not in ('FUNC', 'OBJECT', 'IFUNC') or section in ('UND', 'ABS', 'COM') or int(address, 16) == 0:
            continue
        expected.add((symbol.split('@', 1)[0], int(address, 16), int(size, 0), int(kind != 'OBJECT')))
    assert actual == expected, f'Only in engine: {actual - expected}\nOnly in readelf: {expected - actual}'


@pytest.mark.parametrize('damage', ['not-elf', 'short-header', 'short-program-table', 'bad-program-offset',
                                  'bad-symbol-entry-size', 'bad-symbol-name',
                                  'bad-interpreter-offset', 'unterminated-interpreter'])
def test_elf_rejects_malformed_metadata(native, tmp_path, damage):
    directory, _, _, run = native
    data = bytearray((directory / 'progs').read_bytes())
    assert data[:6] == b'\x7fELF\x02\x01', 'Fixture must be ELF64 little-endian'
    if damage == 'not-elf':
        data[:4] = b'nope'
    elif damage == 'short-header':
        data = data[:24]
    elif damage == 'short-program-table':
        data = data[:64]
    elif damage == 'bad-program-offset':
        struct.pack_into('<Q', data, 32, len(data) + 4096)  # e_phoff
    elif damage.startswith('bad-symbol'):
        section_offset = struct.unpack_from('<Q', data, 40)[0]
        section_size, section_count = struct.unpack_from('<HH', data, 58)
        symbol_header = next(offset for offset in range(section_offset, section_offset + section_size * section_count,
                                                        section_size)
                             if struct.unpack_from('<I', data, offset + 4)[0] == 2)  # SHT_SYMTAB
        if damage == 'bad-symbol-entry-size':
            struct.pack_into('<Q', data, symbol_header + 56, 1)  # sh_entsize
        else:
            symbol_offset, symbol_size = struct.unpack_from('<QQ', data, symbol_header + 24)
            function = next(offset for offset in range(symbol_offset, symbol_offset + symbol_size, 24)
                            if data[offset + 4] & 15 == 2 and struct.unpack_from('<Q', data, offset + 8)[0])
            struct.pack_into('<I', data, function, 0xffffffff)  # st_name outside .strtab
    else:
        program_offset = struct.unpack_from('<Q', data, 32)[0]
        program_size, program_count = struct.unpack_from('<HH', data, 54)
        interp_header = next(offset for offset in range(program_offset, program_offset + program_size * program_count,
                                                        program_size)
                             if struct.unpack_from('<I', data, offset)[0] == 3)  # PT_INTERP
        if damage == 'bad-interpreter-offset':
            struct.pack_into('<Q', data, interp_header + 8, len(data) + 4096)
        else:
            offset = struct.unpack_from('<Q', data, interp_header + 8)[0]
            size = struct.unpack_from('<Q', data, interp_header + 32)[0]
            data[offset:offset + size] = b'x' * size
    binary = tmp_path / damage
    binary.write_bytes(data)
    result = run('elfcmp', str(binary))
    assert result['returncode'] == 1, result['output']
    assert 'read failed' in result['output']
    assert not SANITIZER_ERROR.search(result['output']), result['output']


def test_elf_without_section_headers(native, tmp_path):
    directory, _, _, run = native
    data = bytearray((directory / 'progs').read_bytes())
    assert data[:6] == b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 0)  # e_shoff
    struct.pack_into('<HH', data, 60, 0, 0)  # e_shnum, e_shstrndx
    binary = tmp_path / 'no-section-headers'
    binary.write_bytes(data)
    _compare_elf_symbols(binary, run)


@pytest.mark.parametrize('mode', ['task', 'handler'])
def test_event_exception_demo(native, mode):
    if 'diagnostics' not in _extras():
        pytest.skip('Known abort demonstration; enable with PTRACE_TEST_EXTRAS=diagnostics')
    *_, run = native
    result = run('event_exception_demo', mode)
    assert result['returncode'] == -signal.SIGABRT, result['output']
    assert not SANITIZER_ERROR.search(result['output']), result['output']
    assert 'throwing std::runtime_error' in result['output']


def test_supervisor_preserves_failure(tmp_path):
    result = _run([sys.executable, '-c', 'print("failure details"); raise SystemExit(7)'], tmp_path)
    assert result['returncode'] == 7
    assert 'failure details' in result['output']


@pytest.mark.parametrize('hang', [False, True], ids=['normal-exit', 'timeout'])
def test_supervisor_reaps_detached_children(tmp_path, hang):
    # A detached inferior escapes process-group cleanup. The subreaper must kill
    # and reap it both after a successful driver exit and after a timeout.
    pid_file = tmp_path / 'child.pid'
    source = ('import os, subprocess, sys, time; from pathlib import Path; '
              'p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True); '
              f'Path({str(pid_file)!r}).write_text(str(p.pid)); '
              f'time.sleep({60 if hang else 0})')
    worker = subprocess.run([sys.executable, str(Path(__file__).resolve()), '1', sys.executable, '-c', source],
                            capture_output=True, text=True, timeout=15)
    assert worker.returncode == 0, worker.stderr
    result = json.loads(worker.stdout)
    assert result['timed_out'] == hang
    pid = int(pid_file.read_text())
    assert not Path(f'/proc/{pid}').exists(), f'Detached child {pid} was not reaped'
