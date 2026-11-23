"""Event callback operations: register a callback whose body reads the target, and remove one."""

from .draws import one_of

from .callbacks import READS, make_callback
from .operations import OperationModule, is_live, session_operation

MAX_CALLBACKS = 3


class CallbackOperations(OperationModule):
    @session_operation(lambda s: is_live(s) and len(s.observer.extra) < MAX_CALLBACKS,
                       read=one_of(sorted(READS)), events=one_of(['all', 'stop']))
    def add_callback(self, session, read, events):
        session.observer.add(make_callback(session, read, events))

    @session_operation(lambda s: is_live(s) and s.observer.extra)
    def remove_callback(self, session):
        session.observer.remove()
