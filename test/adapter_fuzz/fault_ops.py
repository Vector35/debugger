"""Faults from outside the debugger: signals to the target, and killing or stopping a debug server."""

import os
import signal
import time

from .draws import one_of

from .common import SERVER_PAUSE_SECONDS
from .operations import OperationModule, is_active, session_operation
from .session import ACTIVE, IDLE
from .system import available_signals, descendants, kill_process, process_identity, signal_process

TARGET_SIGNALS = available_signals(['SIGKILL', 'SIGTERM', 'SIGSTOP', 'SIGCONT', 'SIGUSR1', 'SIGINT', 'SIGHUP'])
# Stopping and continuing need signals that Windows does not have
SERVER_FAULTS = ['kill'] + (['stop_briefly'] if hasattr(signal, 'SIGSTOP') else [])


class FaultOperations(OperationModule):
    @session_operation(is_active, weight=2, name=one_of(TARGET_SIGNALS))
    def send_signal(self, session, name):
        session.remember_pid()
        # Only a process that the controller reports as its target, since a pid can be reused once the target is gone
        pid = session.process.pid
        if session.state == IDLE or not pid or session.dbg.active_pid != pid:
            return
        session.interfered = True
        session.process.send_signal(getattr(signal, name))

    @session_operation(is_active, when=lambda self: self.profile.server_processes, fault=one_of(SERVER_FAULTS))
    def fault_debug_server(self, session, fault):
        targets = {pid for other in self.sessions for pid in other.process.pids}
        servers = {pid: process_identity(pid) for pid, name in descendants(os.getpid()).items()
                   if name in self.profile.server_processes and pid not in targets}
        if not servers:
            return
        # The server of a particular session cannot be told apart, so every live session counts as interfered with
        for other in self.sessions_in(ACTIVE):
            other.interfered = True
        for pid, identity in servers.items():
            if fault == 'kill':
                kill_process(pid, identity)
            else:
                signal_process(pid, identity, signal.SIGSTOP)
                time.sleep(SERVER_PAUSE_SECONDS)
                signal_process(pid, identity, signal.SIGCONT)
