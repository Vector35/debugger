"""Fuzz debugging a program that is driven by signal handlers.

test/src/signal_target.c raises signals that its handlers count, and exits 0 only if every handler ran as
often, and in the order, that the signals it raised require. The machine below adds breakpoints in those
handlers and drives the program to its end. It fails if the program exits nonzero (the debugger changed what
the program did) or a breakpoint stop happens somewhere nothing asked for one.
"""

import time

import pytest

from adapter_fuzz import ACTIVE, PAUSED, AdapterMachine, host_profiles
from adapter_fuzz.campaign import assert_clean
from adapter_fuzz.common import FINISH_SECONDS
from adapter_fuzz.draws import booleans, one_of
from adapter_fuzz.operations import is_active, session_operation
from adapter_fuzz.profile import unavailable_reason
from adapter_fuzz.recording import check, operation, starting_operation
from adapter_fuzz.tracking import End

try:
    from debugger import DebugStopReason
except ImportError:
    from binaryninja.debugger import DebugStopReason

PROGRAM = 'signal_target'
MODES = ['sync', 'segv', 'timer', 'sleep', 'thread']
# A machine offers only the modes that its adapter supports
MODE = one_of(lambda machine: machine.supported_modes())
HANDLERS = ['handler_usr1', 'handler_usr2', 'handler_segv', 'handler_alarm', 'handler_thread']


def handler_address(session, name):
    # The view is rebased to where the target was loaded, so this is only valid for the current launch
    data = session.dbg.data if session.dbg.data is not None else session.view
    for candidate in (name, '_' + name):
        functions = data.get_functions_by_name(candidate)
        if functions:
            return functions[0].start
    return None


class SignalMachine(AdapterMachine):
    # The program's mode is its argument, and the fixture is the program that is being debugged
    excluded_operations = frozenset({'set_arguments', 'set_executable'})

    def supported_modes(self):
        return [mode for mode in MODES if mode != 'segv' or self.profile.fault_signals]

    def add_signal_session(self, mode):
        session = self.add_session(PROGRAM)
        session.dbg.cmd_line = mode
        return session

    def starting_session(self):
        return self.add_signal_session('sync')

    @starting_operation(mode=MODE)
    def start(self, mode):
        self.add_signal_session(mode)

    @operation(when=lambda self: self.can_spawn(), mode=MODE)
    def spawn_session(self, mode):
        self.add_signal_session(mode)

    @session_operation(is_active, handler=one_of(HANDLERS), add=booleans())
    def toggle_handler_breakpoint(self, session, handler, add):
        address = handler_address(session, handler)
        if address is None:
            raise AssertionError(f'{handler} is not in the program')
        (session.breakpoints.add if add else session.breakpoints.delete)(address)

    @session_operation(is_active)
    def run_to_the_end(self, session):
        deadline = time.monotonic() + FINISH_SECONDS
        while session.dbg.connected and time.monotonic() < deadline:
            if session.state == PAUSED:
                session.dbg.go()
            time.sleep(0.01)
        if session.dbg.connected:
            raise AssertionError(f'{session}: the program did not finish within {FINISH_SECONDS}s')

    def session_ended(self, session, end):
        if end is End.BY_ITSELF:
            if session.dbg.exit_code != 0:
                raise AssertionError(
                    f'{session}: the program checked its handlers and exited with {session.dbg.exit_code}')

    @check
    def breakpoint_stops_are_requested(self):
        for session in self.sessions_in(ACTIVE):
            requested = session.breakpoints.stop_addresses()
            if requested is not None and session.state == PAUSED and session.dbg.stop_reason == DebugStopReason.Breakpoint:
                requested = requested | {session.dbg.data.entry_point}
                if session.dbg.ip not in requested:
                    raise AssertionError(f'{session} stopped at {session.dbg.ip:#x} as a breakpoint, but none is there')


@pytest.mark.fuzz
@pytest.mark.parametrize('adapter', host_profiles(), ids=lambda adapter: adapter.name)
def test_signal_fuzz(adapter):
    reason = unavailable_reason(adapter, [PROGRAM])
    if reason:
        pytest.skip(reason)
    assert_clean(adapter.name, 'adapter_signal_fuzz_test:SignalMachine')
