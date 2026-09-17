"""External CI test supervisor; deliberately does not import Binary Ninja."""

import os
import signal
import subprocess


def run_tests(command, env, timeout=900):
    proc = subprocess.Popen(command, env=env, start_new_session=os.name == 'posix')
    print(f'CI watchdog: pytest pid={proc.pid}, outer deadline={timeout}s', flush=True)
    try:
        returncode = proc.wait(timeout=timeout)
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
