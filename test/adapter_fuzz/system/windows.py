"""Process and descriptor helpers for Windows."""

import ctypes
import os
import signal
from ctypes import wintypes

_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.GetFileType.argtypes = [wintypes.HANDLE]
_kernel32.GetFileType.restype = wintypes.DWORD
_kernel32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
STILL_ACTIVE = 259
FILE_TYPE_PIPE = 3
TH32CS_SNAPPROCESS = 2
MAX_HANDLE_VALUE = 1 << 18


class _ProcessEntry(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                ('th32DefaultHeapID', ctypes.c_size_t), ('th32ModuleID', wintypes.DWORD),
                ('cntThreads', wintypes.DWORD), ('th32ParentProcessID', wintypes.DWORD),
                ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD), ('szExeFile', ctypes.c_wchar * 260)]


_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
_kernel32.Process32FirstW.restype = wintypes.BOOL
_kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry)]
_kernel32.Process32NextW.restype = wintypes.BOOL


def process_exists(pid):
    # os.kill(pid, 0) would terminate the process on Windows
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED
    try:
        code = wintypes.DWORD()
        return bool(_kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == STILL_ACTIVE
    finally:
        _kernel32.CloseHandle(handle)


def process_identity(pid):
    """What tells this process from a later one that is given the same id: its creation time, or None if it cannot be
    read."""
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        created, ignored = (wintypes.FILETIME() for _ in range(2))
        if not _kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(ignored), ctypes.byref(ignored),
                                         ctypes.byref(ignored)):
            return None
        return (created.dwHighDateTime << 32) | created.dwLowDateTime
    finally:
        _kernel32.CloseHandle(handle)


def signal_process(pid, identity, number):
    """Sends a signal to the process `pid` if it is still the one that had `identity`, and says whether it did. On
    Windows os.kill terminates whatever the signal."""
    if identity is None or process_identity(pid) != identity:
        return False
    try:
        os.kill(pid, number)
    except OSError:
        return False
    return True


def kill_process(pid, identity):
    """Ends the process `pid` if it is still the one that had `identity`, and says whether it did."""
    return signal_process(pid, identity, signal.SIGTERM)


def available_signals(names):
    """The signals among `names` that os.kill delivers as that signal. Windows delivers every signal as a termination,
    so only SIGTERM is of use."""
    return [name for name in names if name == 'SIGTERM']


def open_pipe_count():
    """Number of pipes and sockets this process holds.

    The adapters leak pipes (target stdio, event wake-ups), whereas files that a BinaryView keeps open are
    legitimate and grow with the number of views, so only pipes and sockets are counted."""
    # Handle values are small multiples of four, so try them in turn until every open handle has been seen. A pipe
    # or a socket reports FILE_TYPE_PIPE; a closed value fails with ERROR_INVALID_HANDLE.
    total = wintypes.DWORD()
    _kernel32.GetProcessHandleCount(_kernel32.GetCurrentProcess(), ctypes.byref(total))
    seen = pipes = 0
    for value in range(4, MAX_HANDLE_VALUE, 4):
        ctypes.set_last_error(0)
        kind = _kernel32.GetFileType(value)
        if kind == 0 and ctypes.get_last_error() != 0:
            continue
        seen += 1
        pipes += kind == FILE_TYPE_PIPE
        if seen >= total.value:
            break
    return pipes


def descendants(pid):
    """Process ids and names of everything below `pid`."""
    children, names = {}, {}
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = _ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    more = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
    while more:
        children.setdefault(entry.th32ParentProcessID, []).append(entry.th32ProcessID)
        names[entry.th32ProcessID] = entry.szExeFile
        more = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    _kernel32.CloseHandle(snapshot)
    found, queue = {}, [pid]
    while queue:
        for child in children.get(queue.pop(), []):
            found[child] = names[child]
            queue.append(child)
    return found
