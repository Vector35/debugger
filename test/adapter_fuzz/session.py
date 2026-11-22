"""One debugging session: a controller, its program, and what the fuzzer expects of it."""

import time

try:
    from debugger import DebuggerController, DebugStopReason
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason

from .common import OPERATION_TIMEOUT_MS, PROCESS_EXIT_SECONDS, RESUME_SETTLE_SECONDS, TEARDOWN_GRACE_SECONDS
from .profile import fixture_path
from .tracking import Breakpoints, ControllerHandle, End, EndTracking, LaunchSetup, Observer, TargetProcess

IDLE, PAUSED, RUNNING = 'idle', 'paused', 'running'
# Appended to the message of every check that depends on a wall-clock window
TIMING_NOTE = 'This check depends on timing: repeat with ADAPTER_FUZZ_PATIENCE=2 to rule out a loaded machine.'
# A session's `model` is the fuzzer's own bookkeeping, which only operations change: IDLE (not started, or ended by
# an operation), ACTIVE (started by an operation, though it may have ended by itself since) and GONE (the controller
# was dropped). See README.md for why it must not follow the target.
ACTIVE, GONE = 'active', 'gone'


def check_returned(reason, what, allow=()):
    bad = {DebugStopReason.TimedOut, DebugStopReason.InternalError} - set(allow)
    if reason in bad:
        raise AssertionError(f'{what} returned {reason!r}')


class Session:
    """The lifecycle of one controller, and the checks that hold after every operation. What it keeps track of is in
    tracking.py: breakpoints, event callbacks, the target's process, the launch setup and how the session ended.
    Operations that start, resume or end the target are methods here; the rest are in the *_ops.py modules and use
    those parts."""

    def __init__(self, profile, index, program, view, dbg, pool):
        self.profile = profile
        self.index = index
        self.program = program
        self.path = fixture_path(program)
        self.view = view
        self.pool = pool
        self.handle = ControllerHandle(dbg, str(self))
        self.breakpoints = Breakpoints(self.handle)
        self.observer = Observer(self.handle)
        self.process = TargetProcess()
        self.setup = LaunchSetup()
        self.ends = EndTracking()
        self.model = IDLE
        self.launched = False

    @classmethod
    def open(cls, profile, index, program, pool):
        view = pool.take(fixture_path(program))
        dbg = DebuggerController(view)
        dbg.adapter_type = profile.name
        return cls(profile, index, program, view, dbg, pool)

    def __str__(self):
        return f's{self.index}({self.program})'

    @property
    def dbg(self):
        return self.handle.controller

    @property
    def dropped(self):
        return self.handle.dropped

    @property
    def interfered(self):
        return self.ends.interfered

    @interfered.setter
    def interfered(self, value):
        self.ends.interfered = value

    def refusals(self):
        """Stop reasons that are the right answer to a request once something outside has broken the session."""
        return (DebugStopReason.InternalError,) if self.interfered else ()

    @property
    def state(self):
        if self.dropped or not self.dbg.connected:
            return IDLE
        return RUNNING if self.dbg.running else PAUSED

    def wait_until_resumed(self):
        # go() returns once the resume is queued; the controller reports running a moment later
        deadline = time.monotonic() + RESUME_SETTLE_SECONDS
        while self.state == PAUSED and time.monotonic() < deadline:
            time.sleep(0.01)

    def remember_pid(self):
        if self.state != IDLE:
            self.process.note(self.dbg.active_pid)

    def assert_over(self, what):
        if self.dbg.connected:
            raise AssertionError(f'{self} {what}: still connected')
        if self.dbg.running:
            raise AssertionError(f'{self} {what}: still running')
        if self.process.pid and not self.interfered:
            if not self.process.wait_until_gone(PROCESS_EXIT_SECONDS):
                raise AssertionError(f'{self} {what}: process {self.process.pid} is still alive. {TIMING_NOTE}')

    def launch(self):
        self.model = ACTIVE
        self.launched = True
        self.ends.start_run()
        refused = (DebugStopReason.InternalError,) if self.setup.bad else ()
        reason = self.dbg.launch_and_wait(OPERATION_TIMEOUT_MS)
        check_returned(reason, f'{self} launch', allow=refused)
        if reason == DebugStopReason.InternalError and self.setup.bad:
            # The launch was refused, as it should be for a directory or program that is not there
            if self.state != IDLE:
                raise AssertionError(f'{self} launch failed but the controller is {self.state}')
            return
        self.ends.was_connected = True
        if reason == DebugStopReason.ProcessExited:
            if self.state != IDLE:
                raise AssertionError(f'{self} launch reported the exit but the controller is connected')
        elif self.state != PAUSED:
            raise AssertionError(f'{self} launch returned {reason!r} but the state is {self.state}')
        self.remember_pid()

    def go(self):
        if self.state == PAUSED:
            if not self.dbg.go():
                raise AssertionError(f'{self} go was refused while paused')
            self.wait_until_resumed()

    def step(self, into):
        if self.state == PAUSED:
            reason = (self.dbg.step_into_and_wait if into else self.dbg.step_over_and_wait)(timeout=OPERATION_TIMEOUT_MS)
            check_returned(reason, f'{self} step', allow=self.refusals())

    def pause(self):
        if self.state == RUNNING:
            reason = self.dbg.pause_and_wait(OPERATION_TIMEOUT_MS)
            check_returned(reason, f'{self} pause', allow=self.refusals())
            if reason == DebugStopReason.UserRequestedBreak and self.state != PAUSED:
                raise AssertionError(f'{self} paused but the state is {self.state}')
            self.remember_pid()

    def read_stopped_state(self):
        if self.state != PAUSED:
            return
        if self.dbg.ip == 0:
            raise AssertionError(f'{self} has no instruction pointer while paused')
        if len(self.dbg.regs) == 0:
            raise AssertionError(f'{self} has no registers while paused')
        stack = self.dbg.stack_pointer
        if stack == 0:
            # A target that ended or resumed by itself while it was read has no stack pointer to check
            if self.state != PAUSED:
                return
            raise AssertionError(f'{self} has no stack pointer while paused')
        before = self.dbg.read_memory(stack, 16)
        if len(before) != 16:
            raise AssertionError(f'{self} read {len(before)} bytes of the stack')
        if not self.dbg.write_memory(stack, before):
            raise AssertionError(f'{self} could not write the stack back')
        if self.dbg.read_memory(stack, 16) != before:
            raise AssertionError(f'{self} stack changed under a write of its own contents')

    def quit(self):
        self.model = IDLE
        self.ends.ask_to_end()
        self.remember_pid()
        self.dbg.quit_and_wait(OPERATION_TIMEOUT_MS)
        self.assert_over('quit')

    def restart(self):
        if self.state == IDLE:
            return
        reason = self.dbg.restart_and_wait(OPERATION_TIMEOUT_MS)
        self.ends.start_run()
        check_returned(reason, f'{self} restart', allow=self.refusals())
        if reason != DebugStopReason.ProcessExited and self.state != PAUSED:
            raise AssertionError(f'{self} restart returned {reason!r} but the state is {self.state}')
        self.remember_pid()

    def detach(self):
        self.model = IDLE
        self.ends.ask_to_end()
        if self.state == IDLE:
            return
        self.remember_pid()
        self.ends.detaches += 1
        self.dbg.detach_and_wait(OPERATION_TIMEOUT_MS)
        if self.dbg.connected:
            raise AssertionError(f'{self} detach: still connected')
        self.process.kill()

    def drop(self):
        """Let go of the controller while the target may still be running."""
        self.remember_pid()
        self.model = GONE
        self.handle.invalidate()
        self.pool.abandon(self.view)
        self.view = None

    def observe(self):
        """Records whether the session has ended since the last call, and how. The one step of checking that changes
        what the session keeps track of."""
        if self.model == GONE:
            return End.NONE
        return self.ends.observe(self.state != IDLE, time.monotonic())

    def assert_consistent(self):
        """The properties that hold after every operation. Changes nothing."""
        if self.model == GONE:
            return
        if self.observer.errors:
            raise AssertionError(f'{self} callback failed: {self.observer.errors[0]}')
        if self.dbg.running and not self.dbg.connected:
            raise AssertionError(f'{self} is running but not connected')
        if self.state != RUNNING:
            self.breakpoints.verify()
        cutoff = self.ends.events_cutoff(TEARDOWN_GRACE_SECONDS)
        if cutoff is not None:
            late = self.observer.events_after(cutoff)
            if late:
                raise AssertionError(f'{self}: events {late} arrived after the session ended. {TIMING_NOTE}')

    def check(self):
        """Observes the session, then asserts what must hold. Returns how it ended, if it did since the last check."""
        end = self.observe()
        self.assert_consistent()
        return end

    def finish(self, reuse_view=True):
        """Ends the session if it is still going, and gives its view back for the next example.

        After a failure the controller may be in any state, so its view is set aside instead (reuse_view=False)."""
        if self.model == GONE:
            return
        self.remember_pid()
        try:
            if self.dbg.connected:
                self.dbg.quit_and_wait(OPERATION_TIMEOUT_MS)
                if self.dbg.connected:
                    raise AssertionError(f'{self} teardown: quit left the controller connected')
        finally:
            if self.interfered:
                self.process.kill()
            self.observer.release()
            self.breakpoints.release()
            if reuse_view and not self.setup.changed:
                self.pool.give(self.path, self.view)
            else:
                self.pool.abandon(self.view)
