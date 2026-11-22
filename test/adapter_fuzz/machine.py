"""The state machine that combines the operation modules, with the checks that run after every operation and when
an example ends."""

import collections
import faulthandler
import gc
import sys
import time

from .breakpoint_ops import BreakpointOperations
from .callback_ops import CallbackOperations
from .common import HANG_SECONDS, MAX_SESSIONS, PIPE_SETTLE_SECONDS, PROCESS_EXIT_SECONDS
from .data_ops import DataOperations
from .fault_ops import FaultOperations
from .lifecycle_ops import LifecycleOperations
from .profile import PROGRAMS
from .recording import Recorder, check, crash_stream
from .session import ACTIVE, GONE, IDLE, TIMING_NOTE, Session
from .setup_ops import SetupOperations
from .system import open_pipe_count
from .thread_ops import ThreadOperations
from .tracking import End, ViewPool

TIMELINE_LENGTH = 25


class AdapterMachine(Recorder, LifecycleOperations, CallbackOperations, BreakpointOperations, ThreadOperations,
                     DataOperations, SetupOperations, FaultOperations):
    profile = None
    pool = None
    warmed = False

    def __init__(self, warm_up=False):
        self.sessions = []
        self.history = collections.deque(maxlen=TIMELINE_LENGTH)
        self.timeline = collections.deque(maxlen=TIMELINE_LENGTH)
        self.cleanup = None
        self.pipes_at_start = open_pipe_count()
        self.begin_example(warm_up=warm_up)
        self.arm_watchdog()

    def arm_watchdog(self):
        # A native deadlock cannot be interrupted from Python; this dumps every thread's stack and exits
        faulthandler.dump_traceback_later(HANG_SECONDS, exit=True, file=crash_stream() or sys.stderr)

    def sessions_in(self, model):
        return [session for session in self.sessions if session.model == model]

    def live_sessions(self):
        return self.sessions_in(ACTIVE) + self.sessions_in(IDLE)

    def pick_live(self, which, wanted=None):
        """A session that has not been dropped, optionally one that satisfies `wanted`."""
        candidates = [session for session in self.live_sessions() if wanted is None or wanted(session)]
        return candidates[which % len(candidates)]

    def pick(self, model, which):
        candidates = self.sessions_in(model)
        return candidates[which % len(candidates)]

    def act(self, session, what):
        self.history.append(f'{session} {what}')

    def add_session(self, program):
        session = Session.open(self.profile, len(self.sessions), program, self.pool)
        self.sessions.append(session)
        if self.profile.configure and self.cleanup is None:
            self.cleanup = self.profile.configure()
        self.act(session, 'created')
        return session

    def can_spawn(self):
        return len(self.live_sessions()) < MAX_SESSIONS

    @check
    def check_sessions(self):
        self.arm_watchdog()
        self.timeline.append((round(time.monotonic() % 1000, 3),
                              [f'{session}:{session.model}/{session.state}' for session in self.sessions]))
        for session in self.sessions:
            end = session.check()
            if end is not End.NONE:
                self.session_ended(session, end)

    def check_nothing_is_left(self):
        """Run after every session has been ended: no process and no pipe may outlive the example."""
        self.check_dropped_targets()
        if self.pipes_at_start is None or not type(self).warmed:
            return
        # The first session also pays for starting the debugger, which warm_up() does beforehand
        allowed = self.pipes_at_start
        deadline = time.monotonic() + PIPE_SETTLE_SECONDS
        while open_pipe_count() > allowed and time.monotonic() < deadline:
            gc.collect()
            time.sleep(0.05)
        count = open_pipe_count()
        if count > allowed:
            if any(session.process.pids for session in self.sessions_in(GONE)):
                cause = 'after a launched controller was dropped'
            elif any(session.ends.ended_without_being_asked() for session in self.sessions):
                cause = 'after a session ended by exit or detach'
            else:
                cause = 'with no session ended by exit, detach or drop'
            raise AssertionError(f'the example opened {count - self.pipes_at_start} pipes or sockets and kept them {cause}. {TIMING_NOTE}')

    def check_dropped_targets(self):
        # Nothing can be asked of a dropped controller, so the targets are ended from outside
        processes = [session.process for session in self.sessions if session.model == GONE]
        deadline = time.monotonic() + PROCESS_EXIT_SECONDS
        while any(process.alive_pids() for process in processes) and time.monotonic() < deadline:
            time.sleep(0.05)
        alive = sorted(pid for process in processes for pid in process.alive_pids())
        for process in processes:
            process.kill()
        if alive:
            raise AssertionError(f'targets {alive} outlived their dropped controller. {TIMING_NOTE}')

    def starting_session(self):
        """The first session of a warm-up run. A machine with its own programs overrides this."""
        return self.add_session(PROGRAMS['short_program'])

    @classmethod
    def warm_up(cls):
        """Starts and ends one session before the first example, so that the debugger's own start-up cost, such as
        the descriptors it opens once, is not mistaken for a leak."""
        machine = cls(warm_up=True)
        try:
            session = machine.starting_session()
            session.launch()
            session.quit()
        except Exception as error:
            raise RuntimeError(f'the warm-up session failed to start: {type(error).__name__}: {error}') from error
        finally:
            machine.teardown()
        cls.warmed = True

    def teardown(self):
        faulthandler.cancel_dump_traceback_later()
        for session in self.sessions:
            try:
                session.finish(reuse_view=self.failure is None)
            except Exception as error:
                self.record_failure(error)
        if self.cleanup:
            self.cleanup()
        if self.failure is None:
            try:
                self.check_nothing_is_left()
            except Exception as error:
                self.record_failure(error)
        else:
            # The sessions are in an unknown state, so make sure that no target outlives the example
            for session in self.sessions:
                session.process.kill()
        self.end_example()


def machine_for(profile, base=AdapterMachine):
    return type(f'{base.__name__}[{profile.name}]', (base,),
                {'profile': profile, 'pool': ViewPool(), 'warmed': False, 'example_counter': 0})
