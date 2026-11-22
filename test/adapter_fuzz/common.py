"""Names that the machine and the operation modules share, with every wait and timeout in one place."""

from .draws import integers
from .settings import from_environment

SETTINGS = from_environment()

MAX_SESSIONS = SETTINGS.sessions

# Which of several sessions in a given state an operation acts on, as an index modulo how many there are
WHICH = integers(0, MAX_SESSIONS - 1)

# Which of a session's breakpoints, threads, registers or functions an operation acts on, likewise modulo
INDEX = integers(0, 63)

# A machine that is slow or heavily loaded can multiply every wait. 2 doubles each timeout and settle time.
PATIENCE = SETTINGS.patience

# How long a call into the debugger may take before it counts as hung
OPERATION_TIMEOUT_MS = int(20000 * PATIENCE)
# How long a worker may go without an operation finishing before its watchdog ends it
HANG_SECONDS = 180 * PATIENCE
# How long after a session ends an event may still arrive without being reported
TEARDOWN_GRACE_SECONDS = 0.5 * PATIENCE
# How long go() may take to show the target as running
RESUME_SETTLE_SECONDS = 0.5 * PATIENCE
# How long a target may take to disappear after its session ended
PROCESS_EXIT_SECONDS = 5 * PATIENCE
# How long the debugger may take to close the pipes of an ended session
PIPE_SETTLE_SECONDS = 3 * PATIENCE
# How long a debug server stays stopped by a fault
SERVER_PAUSE_SECONDS = 0.3 * PATIENCE
# How long one example may take, for the campaign's own limit on a worker
WORKER_SECONDS_PER_EXAMPLE = 400 * PATIENCE
# How long a program that is driven by signals may take to finish
FINISH_SECONDS = 60 * PATIENCE
