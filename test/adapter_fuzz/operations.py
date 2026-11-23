"""`OperationModule`, which declares what the operation modules use of the machine, and `session_operation`, which
declares an operation on one session."""

import collections
from typing import Optional

from .common import WHICH
from .profile import AdapterProfile
from .recording import operation
from .session import ACTIVE, GONE, IDLE, PAUSED, Session


class OperationModule:
    """The base of every operation module, a mixin of `AdapterMachine`. A module may use only what is declared here;
    the machine provides it. Methods with a body are hooks that a machine may override."""

    profile: AdapterProfile
    sessions: list
    history: collections.deque
    # Set by a replay to the index of the session that a recorded step acted on, so that removing steps cannot
    # change which session it acts on
    forced_session: Optional[int]

    def act(self, session: Session, what: str):
        """Writes what a session is doing to the history that a failure's report shows."""
        raise NotImplementedError

    def note_target(self, session: Session):
        """Records which session the current step acted on."""
        raise NotImplementedError

    def sessions_in(self, model: str) -> list:
        raise NotImplementedError

    def add_session(self, program) -> Session:
        raise NotImplementedError

    def can_spawn(self) -> bool:
        """Whether another session may be opened."""
        raise NotImplementedError

    def before_launch(self, session: Session):
        """Called before a session launches. A machine overrides it to set up the session's target."""

    def session_ended(self, session: Session, end):
        """Called when the controller first reports no session. `end` is how it ended, an `End`."""


def is_active(session):
    return session.model == ACTIVE


def is_idle(session):
    return session.model == IDLE


def is_live(session):
    return session.model != GONE


def is_launched(session):
    return session.model != GONE and session.launched


def is_unlaunched(session):
    return session.model != GONE and not session.launched


def describe_call(function, arguments):
    name = function.__name__.replace('_', ' ')
    return ' '.join([name] + [f'{key}={value!r}' for key, value in arguments.items()])


def session_operation(where, *, paused=False, weight=1, when=None, **arguments):
    """Declares an operation on one session that satisfies `where`. `which` is drawn to choose among them, and is
    recorded with the session the step acted on. `when` may further limit the machine's state in which it is enabled.
    With `paused=True` the body runs only while the target is stopped and untouched from outside."""
    def decorate(function):
        def body(self, which, **kwargs):
            candidates = [session for session in self.sessions if where(session)]
            if self.forced_session is not None:
                candidates = [session for session in candidates if session.index == self.forced_session]
                if not candidates:
                    return
                session = candidates[0]
            else:
                session = candidates[which % len(candidates)]
            self.note_target(session)
            self.act(session, describe_call(function, kwargs))
            if paused and (session.state != PAUSED or session.interfered):
                return
            function(self, session, **kwargs)

        body.__name__ = function.__name__
        body.__qualname__ = function.__qualname__
        body.__doc__ = function.__doc__
        return operation(
            weight=weight,
            when=lambda self: any(where(session) for session in self.sessions) and (when is None or when(self)),
            which=WHICH, **arguments)(body)
    return decorate
