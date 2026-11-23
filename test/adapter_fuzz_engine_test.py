import random
from types import SimpleNamespace

import pytest

from adapter_fuzz.draws import booleans, integers, one_of
from adapter_fuzz.engine import replay, run_example, run_examples
from adapter_fuzz.operations import OperationModule, session_operation
from adapter_fuzz.recording import Recorder, check, operation, starting_operation


class Toy(Recorder):
    """A machine with no adapter. Every finished example is kept in `finished`, as (steps, failure)."""

    finished = []

    def __init__(self):
        self.history = []
        self.timeline = []
        self.begin_example()

    def teardown(self):
        type(self).finished.append((self.steps, self.failure))
        self.end_example()


def toy(**members):
    return type('Machine', (Toy,), {'finished': [], **members})


def names(steps):
    return [step['rule'] for step in steps]


def test_the_same_seed_gives_the_same_steps_and_a_different_seed_does_not():
    class Machine(toy()):
        @operation(number=integers(0, 10 ** 6), flag=booleans())
        def first(self, number, flag):
            pass

        @operation(choice=one_of(['a', 'b', 'c']))
        def second(self, choice):
            pass

    def run(seed):
        machine = type('Machine', (Machine,), {'finished': []})
        run_examples(machine, 3, 12, seed)
        return [steps for steps, failure in machine.finished]

    assert run(7) == run(7)
    assert run(7) != run(8)


def test_one_example_runs_the_same_alone_as_in_its_run():
    class Machine(toy()):
        @operation(number=integers(0, 10 ** 6))
        def draw(self, number):
            pass

    run_examples(Machine, 3, 8, 'seed')
    run_example(Machine, 8, random.Random('seed:2'))
    assert Machine.finished[3][0] == Machine.finished[2][0] != Machine.finished[1][0]


def test_an_operation_that_is_not_enabled_is_never_drawn():
    class Machine(toy()):
        @operation(when=lambda self: False)
        def never(self):
            pass

        @operation()
        def always(self):
            pass

    run_examples(Machine, 3, 20, 1)
    assert {name for steps, failure in Machine.finished for name in names(steps)} == {'always'}


def test_an_operation_is_enabled_by_what_its_machine_has_done():
    class Machine(toy()):
        def __init__(self):
            super().__init__()
            self.opened = False

        @operation(when=lambda self: not self.opened)
        def open(self):
            self.opened = True

        @operation(when=lambda self: self.opened)
        def use(self):
            pass

    run_examples(Machine, 5, 10, 1)
    for steps, failure in Machine.finished:
        assert names(steps)[0] == 'open' and names(steps).count('open') == 1


def test_a_weight_makes_an_operation_likelier():
    class Machine(toy()):
        @operation(weight=9)
        def heavy(self):
            pass

        @operation()
        def light(self):
            pass

    run_examples(Machine, 1, 400, 3)
    counts = [names(Machine.finished[0][0]).count(name) for name in ('heavy', 'light')]
    assert counts[0] > 4 * counts[1] > 0


def test_starting_operations_run_first_in_the_order_they_are_declared():
    class Machine(toy()):
        @operation()
        def ordinary(self):
            pass

        @starting_operation()
        def one(self):
            pass

        @starting_operation()
        def two(self):
            pass

    run_examples(Machine, 2, 5, 1)
    for steps, failure in Machine.finished:
        assert names(steps)[:2] == ['one', 'two']
        assert set(names(steps)[2:]) == {'ordinary'} and len(steps) == 7


def test_a_failure_ends_its_example_and_the_next_example_still_runs():
    class Machine(toy()):
        calls = 0

        @operation()
        def count(self):
            type(self).calls += 1
            if type(self).calls % 3 == 0:
                raise AssertionError('third call')

    run_examples(Machine, 2, 10, 1)
    assert [len(steps) for steps, failure in Machine.finished] == [3, 3]
    assert all(str(failure) == 'third call' for steps, failure in Machine.finished)
    assert Machine.calls == 6


def test_a_replay_gives_the_failure_of_the_run():
    class Machine(toy()):
        def __init__(self):
            super().__init__()
            self.total = 0

        @operation(amount=integers(1, 5))
        def add(self, amount):
            self.total += amount

        @operation()
        def verify_total(self):
            if self.total > 12:
                raise AssertionError(f'the total reached {self.total}')

    run_examples(Machine, 1, 30, 4)
    steps, failure = Machine.finished[0]
    assert failure is not None
    replay(Machine, steps)
    replayed_steps, replayed = Machine.finished[1]
    assert str(replayed) == str(failure) and replayed_steps == steps


def test_a_replay_skips_a_step_whose_operation_is_not_enabled_and_names_one_that_does_not_exist():
    class Machine(toy()):
        @operation(when=lambda self: False)
        def never(self):
            raise AssertionError('ran')

        @operation()
        def always(self):
            pass

    replay(Machine, [{'rule': 'never', 'args': {}}, {'rule': 'always', 'args': {}}])
    assert names(Machine.finished[0][0]) == ['always'] and Machine.finished[0][1] is None
    with pytest.raises(AssertionError, match="no operation 'missing'"):
        replay(Machine, [{'rule': 'missing', 'args': {}}])
    assert len(Machine.finished) == 2


def test_excluded_operations_are_not_run():
    class Base(toy()):
        @operation()
        def kept(self):
            pass

        @operation()
        def dropped(self):
            pass

    class Machine(Base):
        excluded_operations = frozenset({'dropped'})

    run_examples(Machine, 2, 15, 1)
    assert {name for steps, failure in Machine.finished for name in names(steps)} == {'kept'}
    assert 'dropped' in Base.operations


def test_excluding_a_name_that_is_not_an_operation_is_an_error():
    with pytest.raises(AssertionError, match=r"excludes \['typo'\]"):
        class Machine(toy()):
            excluded_operations = frozenset({'typo'})


def test_the_checks_run_after_every_step_including_the_starting_ones():
    class Machine(toy()):
        runs = 0

        @starting_operation()
        def begin(self):
            pass

        @operation()
        def ordinary(self):
            pass

        @check
        def counted(self):
            type(self).runs += 1

    run_examples(Machine, 2, 6, 1)
    assert Machine.runs == 2 * (1 + 6)


def test_a_failing_check_is_recorded_and_ends_the_example():
    class Machine(toy()):
        @operation()
        def ordinary(self):
            pass

        @check
        def at_the_second_step(self):
            if len(self.steps) == 2:
                raise AssertionError('invariant broken')

    run_examples(Machine, 1, 10, 1)
    steps, failure = Machine.finished[0]
    assert len(steps) == 2 and str(failure) == 'invariant broken'


def test_a_check_in_a_subclass_replaces_the_one_it_overrides():
    class Base(toy()):
        @operation()
        def ordinary(self):
            pass

        @check
        def strict(self):
            raise AssertionError('base')

    class Machine(Base):
        @check
        def strict(self):
            pass

    run_examples(Machine, 1, 3, 1)
    assert Machine.finished[0][1] is None


def test_a_draw_that_depends_on_the_machine_sees_the_machine():
    class Machine(toy()):
        modes = ['only']

        @operation(mode=one_of(lambda machine: machine.modes))
        def start(self, mode):
            pass

    class Other(Machine):
        finished = []
        modes = ['other']

    run_examples(Machine, 1, 5, 1)
    run_examples(Other, 1, 5, 1)
    assert {step['args']['mode'] for step in Machine.finished[0][0]} == {'only'}
    assert {step['args']['mode'] for step in Other.finished[0][0]} == {'other'}


def test_an_operation_in_a_subclass_replaces_the_one_it_overrides():
    class Base(toy()):
        @operation(value=integers(0, 0))
        def act(self, value):
            raise AssertionError('base')

    class Machine(Base):
        @operation(value=integers(5, 5))
        def act(self, value):
            pass

    run_examples(Machine, 1, 3, 1)
    steps, failure = Machine.finished[0]
    assert failure is None and [step['args'] for step in steps] == [{'value': 5}] * 3


def test_integers_include_both_ends_and_booleans_give_both_values():
    rng = random.Random(0)
    assert {integers(2, 4)(rng, None) for _ in range(100)} == {2, 3, 4}
    assert {booleans()(rng, None) for _ in range(100)} == {False, True}


class SessionToy(Toy, OperationModule):
    def __init__(self):
        super().__init__()
        self.sessions = [SimpleNamespace(index=index, model='active', launched=index > 0, state='paused',
                                         interfered=False)
                         for index in range(3)]
        self.allowed = True

    def act(self, session, what):
        self.history.append(what)

    @session_operation(lambda session: session.launched, when=lambda self: self.allowed)
    def poke(self, session):
        self.history.append(f'poked {session.index}')


def test_a_session_operation_records_its_session_and_a_replay_acts_on_that_one():
    machine = toy_session_machine()
    run_examples(machine, 1, 6, 1)
    steps = machine.finished[0][0]
    assert steps and all(step['session'] in (1, 2) for step in steps)
    # A different `which` would have chosen the other session, but the recorded session wins
    other = [{**step, 'args': {**step['args'], 'which': step['args']['which'] + 1}} for step in steps]
    machine.poked = []
    replay(machine, other)
    assert machine.poked == [step['session'] for step in steps]


def toy_session_machine():
    class Machine(SessionToy):
        finished = []
        poked = []

        @session_operation(lambda session: session.launched)
        def poke(self, session):
            type(self).poked.append(session.index)

    return Machine


def test_a_session_operation_is_not_drawn_without_a_session_that_satisfies_where_or_when_is_false():
    class NoSession(SessionToy):
        finished = []

        def __init__(self):
            super().__init__()
            self.sessions = self.sessions[:1]

    class Closed(SessionToy):
        finished = []

        def __init__(self):
            super().__init__()
            self.allowed = False

    class Open(SessionToy):
        finished = []

    for machine, expected in [(NoSession, 0), (Closed, 0), (Open, 5)]:
        run_examples(machine, 1, 5, 1)
        assert len(machine.finished[0][0]) == expected
