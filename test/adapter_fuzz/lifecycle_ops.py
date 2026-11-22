"""Operations that start, run, end and drop sessions."""

import gc
import time

from .draws import booleans, one_of

from .operations import OperationModule, is_active, is_idle, is_launched, session_operation
from .profile import PROGRAMS
from .recording import operation, starting_operation

SLEEPS = [0, 0.005, 0.05, 0.3, 0.7]


class LifecycleOperations(OperationModule):
    @starting_operation(program=one_of(sorted(PROGRAMS)))
    def start(self, program):
        self.add_session(PROGRAMS[program])

    @operation(when=lambda self: self.can_spawn(), program=one_of(sorted(PROGRAMS)))
    def spawn_session(self, program):
        self.add_session(PROGRAMS[program])

    @session_operation(is_idle, weight=8)
    def launch(self, session):
        self.before_launch(session)
        session.launch()

    @session_operation(is_active, weight=3)
    def go(self, session):
        session.go()

    @session_operation(is_active, weight=3, into=booleans())
    def step(self, session, into):
        session.step(into)

    @session_operation(is_active, weight=2)
    def pause(self, session):
        session.pause()

    @operation(seconds=one_of(SLEEPS))
    def let_time_pass(self, seconds):
        self.history.append(f'sleep {seconds}')
        time.sleep(seconds)

    @session_operation(is_active, weight=2)
    def read_stopped_target(self, session):
        session.read_stopped_state()

    @session_operation(is_active, weight=2)
    def quit(self, session):
        session.quit()

    @session_operation(is_active, weight=2, when=lambda self: self.profile.restart)
    def restart(self, session):
        session.restart()

    @session_operation(is_active)
    def detach(self, session):
        session.detach()

    @session_operation(is_launched)
    def drop_controller(self, session):
        session.drop()
        gc.collect()
