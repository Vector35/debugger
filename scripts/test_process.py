"""External CI test supervisor; deliberately does not import Binary Ninja."""

import os
import signal
import subprocess
import sys
import tempfile
import time


def sample_process(pid):
    # Avoid pipes: inherited descriptors must not make diagnostics block forever.
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(['/usr/bin/sample', str(pid), '1', '10'], stdout=output,
                           stderr=subprocess.STDOUT, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f'CI watchdog: sample unavailable: {error}', flush=True)
        output.seek(0)
        # Keep the actionable stacks without hundreds of lines of system images.
        print(output.read().decode('utf-8', errors='replace').split('Binary Images:')[0], flush=True)


def run_tests(command, env, timeout=900, diagnostic_after=120):
    started = time.monotonic()
    proc = subprocess.Popen(command, env=env, start_new_session=os.name == 'posix')
    print(f'CI watchdog: pytest pid={proc.pid}, outer deadline={timeout}s', flush=True)
    try:
        if sys.platform == 'darwin' and diagnostic_after < timeout:
            try:
                returncode = proc.wait(timeout=diagnostic_after)
                return returncode if returncode >= 0 else 1
            except subprocess.TimeoutExpired:
                print('CI watchdog: pytest still running; collecting parent native stacks '
                      '(this alone does not imply failure)', flush=True)
                sample_process(proc.pid)
        returncode = proc.wait(timeout=max(0, timeout - (time.monotonic() - started)))
        return returncode if returncode >= 0 else 1
    except subprocess.TimeoutExpired:
        print(f'CI watchdog: tests exceeded {timeout}s; failing and killing pytest', flush=True)
        return 1
    finally:
        if os.name == 'posix':
            # Also remove descendants that survived a normally exiting pytest.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                if proc.poll() is None:
                    proc.kill()
        elif proc.poll() is None:
            try:
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                               timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
