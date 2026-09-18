"""Supervise the attach test outside the process making potentially blocking native calls."""

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
            # while waiting for attach. Retain worker output for failures.
            target = subprocess.Popen(target_command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                                      **target_options)
            # Preserve the Python environment of pytest as well as direct unittest runs.
            env = os.environ.copy()
            env['PYTHONPATH'] = os.pathsep.join(sys.path)
            worker = subprocess.Popen(worker_command(target.pid), env=env, stdout=output,
                                      stderr=subprocess.STDOUT, start_new_session=os.name == 'posix')
            try:
                result = worker.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
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
                    output.seek(0)
                    print(output.read().decode('utf-8', errors='replace'), end='', flush=True)


def attach_worker(fpath, pid, adapter):
    from binaryninja import load
    try:
        from debugger import DebuggerController, DebugStopReason
    except ImportError:
        from binaryninja.debugger import DebuggerController, DebugStopReason

    bv = load(fpath)
    dbg = DebuggerController(bv)
    if adapter:
        dbg.adapter_type = adapter
    dbg.pid_attach = pid
    if not dbg.processes:
        raise AssertionError('empty process list')
    reason = dbg.attach_and_wait()
    if reason in (DebugStopReason.InternalError, DebugStopReason.ProcessExited,
                  DebugStopReason.InvalidStatusOrOperation, DebugStopReason.TimedOut):
        raise AssertionError(f'attach failed: {reason}')
    if not dbg.regs:
        raise AssertionError('empty register list after attach')
    dbg.quit_and_wait()
    bv.file.close()


if __name__ == '__main__':
    attach_worker(sys.argv[1], int(sys.argv[2]), sys.argv[3])
