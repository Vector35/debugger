"""What a session keeps track of, in parts that each own their bookkeeping."""

import enum
import time

from binaryninja import load
try:
    from debugger import DebugBreakpointType
except ImportError:
    from binaryninja.debugger import DebugBreakpointType

from .system import kill_process, process_exists, process_identity, signal_process


class ViewPool:
    """BinaryViews for sessions. A controller binds to its view for good, so sessions that run at the same time
    need their own, and a view is handed out again only after the example that used it has ended."""

    def __init__(self):
        self.free = {}
        self.abandoned = []

    def take(self, path):
        free = self.free.setdefault(path, [])
        return free.pop() if free else load(path)

    def give(self, path, view):
        self.free.setdefault(path, []).append(view)

    def abandon(self, view):
        # Kept alive for the rest of the run: freeing a view while the debugger still holds a controller for it is a
        # different thing to test, and a later view could be given its address
        self.abandoned.append(view)


class ControllerHandle:
    """The controller of one session, shared by the parts that use it. Dropping the session invalidates it, so that
    a part used afterwards fails with a message that says so instead of calling into a controller that is gone."""

    def __init__(self, controller, label):
        self._controller = controller
        self.label = label

    @property
    def dropped(self):
        return self._controller is None

    @property
    def controller(self):
        if self._controller is None:
            raise RuntimeError(f'{self.label} used its controller after the controller was dropped')
        return self._controller

    def invalidate(self):
        self._controller = None


class Breakpoints:
    """The breakpoints a session set, with each change made on the controller and recorded together. What the
    controller must still report after any operation is checked by verify()."""

    def __init__(self, handle):
        self.handle = handle
        self.software = set()
        self.hardware = set()
        self.disabled = set()
        self.conditions = {}

    def add(self, address):
        self.handle.controller.add_breakpoint(address)
        self.software.add(address)
        self.disabled.discard(address)

    def delete(self, address):
        self.handle.controller.delete_breakpoint(address)
        self.forget(address)

    def clear(self):
        for address in sorted(self.software):
            self.delete(address)

    def set_enabled(self, address, enable):
        dbg = self.handle.controller
        (dbg.enable_breakpoint if enable else dbg.disable_breakpoint)(address)
        (self.disabled.discard if enable else self.disabled.add)(address)

    def set_condition(self, address, condition):
        if self.handle.controller.set_breakpoint_condition(address, condition):
            self.conditions[address] = condition

    def add_hardware(self, address, kind, size):
        # An adapter that has no such breakpoint, or no free slot, may refuse. It is recorded either way: what an
        # operation may do next must not depend on what the adapter answered.
        self.handle.controller.add_hardware_breakpoint(address, kind, size)
        self.hardware.add((address, kind, size))

    def delete_hardware(self, address, kind, size):
        self.handle.controller.delete_hardware_breakpoint(address, kind, size)
        self.hardware.discard((address, kind, size))

    def forget(self, address):
        self.software.discard(address)
        self.disabled.discard(address)
        self.conditions.pop(address, None)

    def pick(self, index):
        return sorted(self.software)[index % len(self.software)]

    def pick_hardware(self, index):
        return sorted(self.hardware)[index % len(self.hardware)]

    def stop_addresses(self):
        """Where a breakpoint stop may happen, or None if a hardware breakpoint can stop anywhere near its access."""
        if any(kind != DebugBreakpointType.BNHardwareExecuteBreakpoint for _, kind, _ in self.hardware):
            return None
        return (self.software - self.disabled) | {address for address, _, _ in self.hardware}

    def verify(self):
        dbg = self.handle.controller
        label = self.handle.label
        for address in self.software:
            if not dbg.has_breakpoint(address):
                raise AssertionError(f'{label} lost the breakpoint at {address:#x}')
        for address, condition in self.conditions.items():
            if dbg.get_breakpoint_condition(address) != condition:
                raise AssertionError(f'{label} lost the condition of the breakpoint at {address:#x}')

    def release(self):
        dbg = self.handle.controller
        for address in self.software:
            dbg.delete_breakpoint(address)
        for address, kind, size in self.hardware:
            dbg.delete_hardware_breakpoint(address, kind, size)


class Observer:
    """The event callbacks registered on a controller: one that records every event, and generated ones that read
    the target (callbacks.py), whose failures are collected in `errors`."""

    def __init__(self, handle):
        self.handle = handle
        self.events = []
        self.errors = []
        self.extra = []
        self.recorder = handle.controller.register_event_callback(
            lambda event: self.events.append((time.monotonic(), event.type)))

    def add(self, callback):
        self.extra.append(self.handle.controller.register_event_callback(callback))

    def remove(self):
        if self.extra:
            self.handle.controller.remove_event_callback(self.extra.pop())

    def release(self):
        dbg = self.handle.controller
        for callback in [self.recorder] + self.extra:
            dbg.remove_event_callback(callback)

    def events_after(self, moment):
        return [kind for when, kind in self.events if when > moment]


class TargetProcess:
    """The target's process id, and every id it has had, since a restart starts a new process.

    A process id is reused once its process is gone, so each id is kept with what identifies the process that had it,
    and a signal is only sent to an id that still belongs to that process."""

    def __init__(self):
        self.pid = 0
        self.identities = {}

    @property
    def pids(self):
        return set(self.identities)

    def note(self, pid):
        self.pid = pid or self.pid
        if self.pid and self.pid not in self.identities:
            self.identities[self.pid] = process_identity(self.pid)

    def is_alive(self, pid):
        identity = self.identities.get(pid)
        if identity is None:
            return process_exists(pid)
        return process_identity(pid) == identity

    def alive_pids(self):
        return {pid for pid in self.identities if self.is_alive(pid)}

    def wait_until_gone(self, seconds):
        deadline = time.monotonic() + seconds
        while self.is_alive(self.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        return not self.is_alive(self.pid)

    def send_signal(self, number):
        """Signals the current process, and says whether it was still the one that was noted."""
        return signal_process(self.pid, self.identities.get(self.pid), number)

    def kill(self):
        for pid, identity in self.identities.items():
            kill_process(pid, identity)


class LaunchSetup:
    """What the next launch has been told to use."""

    def __init__(self):
        # A working directory or executable that does not exist, so that a launch is expected to fail
        self.bad_directory = False
        self.bad_executable = False
        # The controller keeps its launch settings, so a view whose settings were changed is not reused
        self.changed = False

    @property
    def bad(self):
        return self.bad_directory or self.bad_executable


class End(enum.Enum):
    """What EndTracking.observe() found out about a session's end."""

    NONE = 'the session has not ended since it was last observed'
    BY_OPERATION = 'an operation ended it (quit, detach)'
    BY_ITSELF = 'the target exited, or the debugger ended the session, with nothing asked of it'
    AFTER_INTERFERENCE = 'it ended after something outside the debugger acted on the target or its debug server'


class EndTracking:
    """How a session's end is told apart: by an operation, by itself, or after interference. observe() is the one
    method that changes anything the others report."""

    def __init__(self):
        self.asked_to_end = False
        # Something outside the debugger acted on the target or its debug server (fault_ops.py)
        self.interfered = False
        self.was_connected = False
        self.idle_since = None
        # Ends that no operation asked for, whether interfered with or not, and detaches: both can leave pipes open
        self.natural_ends = 0
        self.detaches = 0

    def start_run(self):
        """A launch or restart begins a run that nothing has yet asked to end or acted on."""
        self.asked_to_end = False
        self.interfered = False

    def ask_to_end(self):
        self.asked_to_end = True

    def observe(self, connected, now):
        if not connected and self.was_connected:
            self.was_connected = False
            self.idle_since = now
            self.natural_ends += not self.asked_to_end
            if self.asked_to_end:
                return End.BY_OPERATION
            return End.AFTER_INTERFERENCE if self.interfered else End.BY_ITSELF
        if connected:
            self.was_connected = True
            self.idle_since = None
        return End.NONE

    def ended_without_being_asked(self):
        return bool(self.natural_ends or self.detaches)

    def events_cutoff(self, grace):
        """After this moment no event may arrive, or None while the session has not ended."""
        return None if self.idle_since is None else self.idle_since + grace
