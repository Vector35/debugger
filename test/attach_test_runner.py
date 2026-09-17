"""Supervise the attach test outside the process making potentially blocking native calls."""

import faulthandler
import os
import signal
import subprocess
import sys
import tempfile
import time


def kill_process(proc):
    if proc is None:
        return
    if os.name == 'posix':
        # Each process has its own session. Include debugserver/other children even
        # if the session leader has already exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            # macOS can report EPERM for a group containing only the already-dead
            # debuggee. Reap it; if still live, fall back to its owned process handle.
            if proc.poll() is None:
                proc.kill()
    elif proc.poll() is None:
        try:
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)


def run_attach_test(target_command, worker_command, timeout=60):
    """worker_command(pid) returns argv. Kill/reap the owned target on every path.

    Use files, not pipes: a stuck debugserver inheriting stdout must not prevent
    the supervisor from finishing. Never ask the wedged debugger to clean up.
    """
    deadline = time.monotonic() + timeout
    target = worker = None
    with tempfile.TemporaryFile(mode='w+b') as output:
        try:
            target_options = {'start_new_session': True} if os.name == 'posix' else {
                'creationflags': subprocess.CREATE_NEW_CONSOLE}
            # The loop fixture can print continuously; don't fill CI logs or disk
            # while waiting for attach. Only retain the worker's diagnostic stages.
            target = subprocess.Popen(target_command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                                      **target_options)
            print(f'attach test: target pid={target.pid}, deadline={timeout}s', flush=True)
            # Preserve the Python environment of pytest as well as direct unittest runs.
            env = os.environ.copy()
            env['PYTHONPATH'] = os.pathsep.join(sys.path)
            worker = subprocess.Popen(worker_command(target.pid), env=env, stdout=output,
                                      stderr=subprocess.STDOUT, start_new_session=os.name == 'posix')
            try:
                if sys.platform == 'darwin' and timeout >= 10:
                    try:
                        worker.wait(timeout=max(0, deadline - time.monotonic() - 5))
                    except subprocess.TimeoutExpired:
                        # Capture native LLDB/controller stacks, not just the Python
                        # frame blocked in ctypes. Sampling must not extend the deadline.
                        try:
                            subprocess.run(['/usr/bin/sample', str(worker.pid), '1', '10'],
                                           stdout=output, stderr=subprocess.STDOUT,
                                           timeout=min(3, max(0, deadline - time.monotonic())),
                                           check=False)
                        except (OSError, subprocess.TimeoutExpired) as error:
                            print(f'attach test: native stack sample unavailable: {error}', flush=True)
                result = worker.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                print(f'attach test: TIMEOUT after {timeout}s; starting process cleanup', flush=True)
                raise AssertionError(f'attach test exceeded {timeout} seconds (target pid={target.pid}, '
                                     f'worker pid={worker.pid}); killing worker and target') from None
            if result != 0:
                raise AssertionError(f'attach test worker failed with exit code {result}')
        finally:
            try:
                kill_process(worker)
            finally:
                try:
                    kill_process(target)
                finally:
                    print(f'attach test: cleanup attempted; worker exit={worker.poll() if worker else None}, '
                          f'target exit={target.poll() if target else None}; worker diagnostics follow', flush=True)
                    output.seek(0)
                    print(output.read().decode('utf-8', errors='replace').split('Binary Images:')[0],
                          end='', flush=True)
                    print('\nattach test: diagnostics complete; returning result to pytest', flush=True)


def attach_worker(fpath, pid, adapter):
    faulthandler.enable()
    faulthandler.dump_traceback_later(55)

    def stage(message):
        print(f'attach test: {message}', flush=True)

    stage('import Binary Ninja/debugger')
    import binaryninja as bn
    from binaryninja import load
    stage(f'Python={sys.version}; executable={sys.executable}; Binary Ninja={bn.core_version()}')
    # Use the native logger directly: unlike Python log listeners it does not
    # need a callback to acquire the GIL during plugin initialization.
    bn.log_to_stdout(bn.LogLevel.DebugLog)
    try:
        from debugger import DebuggerController, DebugStopReason
    except ImportError:
        from binaryninja.debugger import DebuggerController, DebugStopReason

    stage('initialize Binary Ninja plugins')
    bn._init_plugins()
    stage('plugin initialization returned')
    # Keep plugin diagnostics, but don't flood CI with per-instruction analysis logs.
    bn.log_to_stdout(bn.LogLevel.InfoLog)
    stage(f'load {fpath}')
    bv = load(fpath)
    stage(f'create debugger (adapter={adapter}, pid={pid})')
    dbg = DebuggerController(bv)
    if adapter:
        dbg.adapter_type = adapter
    dbg.pid_attach = pid
    stage('enumerate processes')
    if not dbg.processes:
        raise AssertionError('empty process list')
    stage('attach_and_wait')
    reason = dbg.attach_and_wait()
    stage(f'attach returned {reason}')
    if reason in (DebugStopReason.InternalError, DebugStopReason.ProcessExited,
                  DebugStopReason.InvalidStatusOrOperation, DebugStopReason.TimedOut):
        raise AssertionError(f'attach failed: {reason}')
    stage('read registers')
    if not dbg.regs:
        raise AssertionError('empty register list after attach')
    stage('quit_and_wait')
    dbg.quit_and_wait()
    stage('quit returned')
    stage('close BinaryView')
    bv.file.close()
    stage('done; shutting down Python')


if __name__ == '__main__':
    attach_worker(sys.argv[1], int(sys.argv[2]), sys.argv[3])
