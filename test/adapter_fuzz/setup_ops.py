"""Operations on the target's arguments, working directory, executable and stdin."""

import os
import tempfile

from .draws import one_of

from .operations import OperationModule, is_active, is_idle, session_operation
from .session import IDLE

SCRATCH = tempfile.gettempdir()
ARGUMENTS = ['', 'a', 'a b "c d"', '--flag=1 -x', 'x' * 2000, 'caf\u00e9 \u2603']
DIRECTORIES = {'temporary': SCRATCH, 'root': os.path.abspath(os.sep),
               'missing': os.path.join(SCRATCH, 'adapter-fuzz-missing-directory')}
EXECUTABLES = ['original', 'missing']
MISSING_EXECUTABLE = os.path.join(SCRATCH, 'adapter-fuzz-missing-program')
STDIN = ['', 'x', 'line\n', 'y' * 4096]


class SetupOperations(OperationModule):
    @session_operation(is_idle, text=one_of(ARGUMENTS))
    def set_arguments(self, session, text):
        session.setup.changed = True
        session.dbg.cmd_line = text
        if session.dbg.cmd_line != text:
            raise AssertionError(f'{session}: the arguments read back as {session.dbg.cmd_line!r}')

    @session_operation(is_idle, kind=one_of(sorted(DIRECTORIES)))
    def set_working_directory(self, session, kind):
        session.setup.changed = True
        session.dbg.working_directory = DIRECTORIES[kind]
        session.setup.bad_directory = kind == 'missing'
        if session.dbg.working_directory != DIRECTORIES[kind]:
            raise AssertionError(f'{session}: the working directory reads back as {session.dbg.working_directory!r}')

    @session_operation(is_idle, kind=one_of(EXECUTABLES))
    def set_executable(self, session, kind):
        path = session.path if kind == 'original' else MISSING_EXECUTABLE
        session.setup.changed = True
        session.dbg.executable_path = path
        session.setup.bad_executable = kind == 'missing'
        if session.dbg.executable_path != path:
            raise AssertionError(f'{session}: the executable reads back as {session.dbg.executable_path!r}')

    @session_operation(is_active, text=one_of(STDIN))
    def write_stdin(self, session, text):
        if session.state != IDLE:
            session.dbg.write_stdin(text)
