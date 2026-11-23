"""What the fuzzer needs to know about each adapter. A new adapter is one entry in ADAPTERS."""

import os
import platform
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple

from binaryninja import load, Settings
try:
    from debugger import DebugAdapterType
except ImportError:
    from binaryninja.debugger import DebugAdapterType

from debugger_test import name_to_fpath

SYSTEM = platform.system()


def host_architecture():
    machine = platform.machine().lower()
    if machine in ('arm64', 'aarch64'):
        return 'arm64'
    return 'x86_64' if machine in ('x86_64', 'amd64') else 'x86'


ARCH = host_architecture()

# The programs that a session may debug, by what they are for
PROGRAMS = {
    'short_program': 'helloworld',
    'long_program': 'helloworld_thread',
    'recursive': 'helloworld_recursion',
    'loop': 'helloworld_loop',
    'arguments': 'commandline_test',
    'directory': 'getcwd',
    'stdin': 'read_input',
}


def fixture_path(name):
    return name_to_fpath(name, ARCH)


def _stop_at_program_entry():
    settings_store = Settings()
    names = ('debugger.stopAtSystemEntryPoint', 'debugger.stopAtEntryPoint')
    previous = [settings_store.get_bool(name) for name in names]
    settings_store.set_bool(names[0], False)
    settings_store.set_bool(names[1], True)

    def restore():
        for index, name in enumerate(names):
            settings_store.set_bool(name, previous[index])
    return restore


@dataclass(frozen=True)
class AdapterProfile:
    # The adapter's name in DebugAdapterType
    name: str
    platforms: Tuple[str, ...]
    # Whether the adapter can restart a session
    restart: bool = True
    # Whether continuing from a stop caused by a fault (SIGSEGV) delivers it to the program's own handler
    fault_signals: bool = True
    # Runs after the first controller exists, because debugger settings are registered lazily. Returns a cleanup.
    configure: Optional[Callable[[], Optional[Callable[[], None]]]] = None
    # Names of the debug server processes that the adapter starts, which fault_ops can kill. Empty for an adapter
    # that debugs the target itself.
    server_processes: Tuple[str, ...] = ()


ADAPTERS = [
    # LLDB on macOS re-executes the faulting instruction when continued, and delivers the signal only when it is
    # sent explicitly, which the controller cannot do
    AdapterProfile('LLDB', ('Darwin', 'Linux'), fault_signals=SYSTEM != 'Darwin',
                   server_processes=('debugserver', 'lldb-server')),
    AdapterProfile('GDB MI', ('Linux',), configure=_stop_at_program_entry, server_processes=('gdb',)),
    AdapterProfile('PTRACE', ('Linux',), configure=_stop_at_program_entry),
    AdapterProfile('DBGENG', ('Windows',), restart=False),
    AdapterProfile('WINDOWS_NATIVE', ('Windows',), restart=False),
]


def host_profiles():
    return [profile for profile in ADAPTERS if SYSTEM in profile.platforms]


def unavailable_reason(profile, programs: Iterable[str] = PROGRAMS.values()):
    """Why `profile` cannot be fuzzed on this host with the given test programs, or None if it can."""
    programs = list(programs)
    missing = [name for name in programs if not os.path.exists(fixture_path(name))]
    if missing:
        return f'{", ".join(missing)} not built for {SYSTEM}-{ARCH}; see test/CMakeLists.txt'
    if profile.name not in DebugAdapterType.get_available_adapters(load(fixture_path(programs[0]))):
        return f'{profile.name} is not available on this host'
    return None
