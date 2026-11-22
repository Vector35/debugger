"""Thread and stack operations on a stopped target."""

from .draws import one_of

try:
    from debugger import DebugStopReason
except ImportError:
    from binaryninja.debugger import DebugStopReason

from .breakpoint_ops import resolve_address
from .common import INDEX, OPERATION_TIMEOUT_MS
from .operations import OperationModule, is_active, session_operation
from .session import check_returned

MAX_THREADS_READ = 8


class ThreadOperations(OperationModule):
    @session_operation(is_active, paused=True, weight=2, index=INDEX)
    def select_thread(self, session, index):
        threads = list(session.dbg.threads)
        if not threads:
            return
        thread = threads[index % len(threads)]
        session.dbg.active_thread = thread
        if session.dbg.active_thread.tid != thread.tid:
            raise AssertionError(
                f'{session}: the active thread is {session.dbg.active_thread.tid} after selecting {thread.tid}')

    @session_operation(is_active, paused=True, weight=2)
    def read_stacks(self, session):
        for thread in list(session.dbg.threads)[:MAX_THREADS_READ]:
            frames = session.dbg.frames_of_thread(thread.tid)
            indexes = [frame.index for frame in frames]
            if indexes != list(range(len(frames))):
                raise AssertionError(f'{session}: thread {thread.tid} has frame indexes {indexes}')

    @session_operation(is_active, paused=True, index=INDEX)
    def suspend_and_resume_thread(self, session, index):
        threads = list(session.dbg.threads)
        if threads:
            tid = threads[index % len(threads)].tid
            session.dbg.suspend_thread(tid)
            session.dbg.resume_thread(tid)

    @session_operation(is_active, paused=True, weight=2)
    def step_out(self, session):
        # With no caller to return to, as at the entry point, a refusal is the right answer
        outermost = len(session.dbg.frames_of_thread(session.dbg.active_thread.tid)) <= 1
        reason = session.dbg.step_return_and_wait(timeout=OPERATION_TIMEOUT_MS)
        check_returned(reason, f'{session} step out', allow=(DebugStopReason.InternalError,) if outermost else ())

    @session_operation(is_active, paused=True, weight=2, kind=one_of(['entry', 'function', 'instruction']),
                       index=INDEX)
    def run_to(self, session, kind, index):
        session.dbg.run_to(resolve_address(session, kind, index))
        session.wait_until_resumed()
