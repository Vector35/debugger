"""Process and descriptor helpers for POSIX."""

import os
import signal
import stat
import subprocess


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def process_identity(pid):
    """What tells this process from a later one that is given the same id: its start time, or None if it cannot be
    read."""
    try:
        with open(f'/proc/{pid}/stat') as stat_file:
            # Field 22, the start time in ticks since boot. The name before it may hold spaces and parentheses.
            return stat_file.read().rpartition(')')[2].split()[19]
    except (OSError, IndexError):
        pass
    try:
        started = subprocess.run(['ps', '-o', 'lstart=', '-p', str(pid)], capture_output=True, text=True,
                                 env={**os.environ, 'LC_ALL': 'C'}).stdout.strip()
    except OSError:
        return None
    return started or None


def signal_process(pid, identity, number):
    """Sends a signal to the process `pid` if it is still the one that had `identity`, and says whether it did."""
    if identity is None or process_identity(pid) != identity:
        return False
    try:
        os.kill(pid, number)
    except OSError:
        return False
    return True


def kill_process(pid, identity):
    """Ends the process `pid` if it is still the one that had `identity`, and says whether it did."""
    return signal_process(pid, identity, signal.SIGKILL)


def available_signals(names):
    """The signals among `names` that this host has."""
    return [name for name in names if hasattr(signal, name)]


def open_pipe_count():
    """Number of pipes and sockets this process holds, or None where they cannot be counted.

    The adapters leak pipes (target stdio, event wake-ups), whereas files that a BinaryView keeps open are
    legitimate and grow with the number of views, so only pipes and sockets are counted."""
    for directory in ('/dev/fd', '/proc/self/fd'):
        if os.path.isdir(directory):
            break
    else:
        return None
    count = 0
    for name in os.listdir(directory):
        try:
            mode = os.fstat(int(name)).st_mode
        except (OSError, ValueError):
            continue
        if stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
            count += 1
    return count


def descendants(pid):
    """Process ids and names of everything below `pid`."""
    children, names = {}, {}
    listing = subprocess.run(['ps', '-A', '-o', 'pid=,ppid=,comm='], capture_output=True, text=True).stdout
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append(int(parts[0]))
            names[int(parts[0])] = os.path.basename(parts[2])
    found, queue = {}, [pid]
    while queue:
        for child in children.get(queue.pop(), []):
            found[child] = names[child]
            queue.append(child)
    return found
