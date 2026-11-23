"""Failure and operation records, so that a run survives its own failures."""

import dataclasses
import json
import os
import traceback
from pathlib import Path
from typing import Callable, Optional

WORKER_DIRECTORY = 'ADAPTER_FUZZ_WORKER_DIR'


@dataclasses.dataclass(frozen=True)
class WorkerFiles:
    """The files one worker process writes, all in one directory that the campaign hands it through the environment."""

    directory: Path

    @property
    def log(self):
        return self.directory / 'log.jsonl'

    @property
    def failures(self):
        return self.directory / 'failures.jsonl'

    @property
    def crash(self):
        return self.directory / 'crash.txt'

    @property
    def output(self):
        return self.directory / 'output.txt'

    def environment(self):
        return {WORKER_DIRECTORY: str(self.directory)}


def worker_files() -> Optional[WorkerFiles]:
    """The files of the worker this process is, or None when it is not a campaign's worker."""
    directory = os.environ.get(WORKER_DIRECTORY)
    return WorkerFiles(Path(directory)) if directory else None


_crash_stream = None


def append(kind, record):
    """Adds a record to the worker's `log` or `failures` file, if this is a worker."""
    files = worker_files()
    if files:
        with open(getattr(files, kind), 'a') as stream:
            stream.write(json.dumps(record, default=repr) + '\n')


def crash_stream():
    """Where faulthandler writes. A bug that kills the process leaves its stacks here."""
    global _crash_stream
    files = worker_files()
    if files and _crash_stream is None:
        _crash_stream = open(files.crash, 'a')
    return _crash_stream


@dataclasses.dataclass(frozen=True)
class Operation:
    """An operation as the engine draws it. `arguments` maps each argument's name to the draw (see draws.py) that
    produces it."""

    name: str
    function: Callable
    weight: int
    when: Optional[Callable]
    arguments: dict
    starting: bool

    def enabled(self, machine):
        return self.when is None or bool(self.when(machine))


def operation(weight=1, when=None, **arguments):
    """Declares an operation. The engine draws among the operations that are enabled, each in proportion to its
    `weight`, so one that is enabled in many states does not crowd out the rest. Do not weight one that a subclass
    overrides. `when(machine)` says whether the operation is enabled; see the README for what it may depend on."""
    def decorate(function):
        function.fuzz_operation = Operation(function.__name__, function, weight, when, arguments, False)
        return function
    return decorate


def starting_operation(**arguments):
    """Declares an operation that every example runs first, in the order the machine declares them."""
    def decorate(function):
        function.fuzz_operation = Operation(function.__name__, function, 1, None, arguments, True)
        return function
    return decorate


def check(function):
    """Declares a check that runs after every step. Its failure is recorded."""
    function.fuzz_check = True
    return function


def collect(cls, marker):
    """The members of a class and its bases that have the attribute `marker`, by name. A member of a subclass
    replaces the one of its base with the same name, even one that does not have the attribute."""
    found = {}
    for klass in reversed(cls.__mro__):
        for name, member in vars(klass).items():
            if hasattr(member, marker):
                found[name] = member
            else:
                found.pop(name, None)
    return found


class Recorder:
    """Mixed into the state machine. The engine calls begin_example() first and teardown() last, which ends the
    example."""

    example_counter = 0
    # Names of operations that this machine does not run, for a machine whose program makes them meaningless
    excluded_operations = frozenset()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        operations = {name: member.fuzz_operation for name, member in collect(cls, 'fuzz_operation').items()}
        unknown = sorted(set(cls.excluded_operations) - set(operations))
        if unknown:
            raise AssertionError(f'{cls.__name__} excludes {unknown}, which are not operations of the machine')
        cls.operations = {name: declared for name, declared in operations.items()
                          if name not in cls.excluded_operations}
        cls.checks = list(collect(cls, 'fuzz_check').values())

    def begin_example(self, warm_up=False):
        cls = type(self)
        cls.example_counter += 1
        self.example_id = cls.example_counter
        self.warm_up_example = warm_up
        self.failure = None
        self.steps = []
        # Set by a replay to the session that a recorded step acted on, so that removing steps cannot change it
        self.forced_session = None
        append('log', {'example': self.example_id, 'start': True, 'warm_up': warm_up})

    def end_example(self):
        append('log', {'example': self.example_id, 'end': True, 'warm_up': self.warm_up_example,
                      'failed': self.failure is not None})

    def perform(self, operation, arguments):
        if self.failure is not None:
            return
        step = {'rule': operation.name, 'args': arguments}
        self.steps.append(step)
        append('log', {'example': self.example_id, 'step': step})
        self.guarded(operation.function, arguments)

    def run_checks(self):
        for function in self.checks:
            if self.failure is not None:
                return
            self.guarded(function, {})

    def note_target(self, session):
        """Records which session the current step acted on. A replay uses it in place of the `which` index."""
        self.steps[-1]['session'] = session.index
        append('log', {'example': self.example_id, 'target': session.index})

    def guarded(self, function, arguments):
        try:
            function(self, **arguments)
        except Exception as error:
            self.record_failure(error)

    def record_failure(self, error):
        if self.failure is not None:
            return
        self.failure = error
        frames = traceback.extract_tb(error.__traceback__)
        record = {
            'example': self.example_id,
            'warm_up': self.warm_up_example,
            'kind': type(error).__name__,
            'message': str(error)[:2000],
            'where': frames[-1].name if frames else '',
            'steps': self.steps,
            'history': list(self.history),
            'timeline': list(self.timeline),
            'traceback': ''.join(traceback.format_exception(error))[-4000:],
        }
        append('failures', record)
        print(f'[adapter-fuzz] example {self.example_id}: {type(error).__name__}: {error}', flush=True)
