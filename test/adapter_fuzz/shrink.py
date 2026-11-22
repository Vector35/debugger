"""Makes a failing sequence of steps shorter and simpler, by replaying candidates until the failure stops."""

import copy
import dataclasses


@dataclasses.dataclass
class Shrunk:
    steps: list
    replays: int
    reproducible: bool


class Replayer:
    """Counts the replays and says whether a candidate fails the same way as the original."""

    def __init__(self, replay, key, budget):
        self.replay = replay
        self.key = key
        self.budget = budget
        self.count = 0

    @property
    def exhausted(self):
        return self.count >= self.budget

    def reproduces(self, steps):
        self.count += 1
        return self.replay(steps) == self.key


def shrink(steps, key, replay, budget):
    """The shortest, simplest steps found within `budget` replays that `replay` (steps -> failure key or None) says
    fail with `key`. Nothing is shrunk when the original steps do not fail that way when replayed."""
    replayer = Replayer(replay, key, budget)
    if not replayer.reproduces(steps):
        return Shrunk(steps, replayer.count, reproducible=False)
    steps = remove_steps(list(steps), replayer)
    steps = simplify_arguments(steps, replayer)
    return Shrunk(steps, replayer.count, reproducible=True)


def remove_steps(steps, replayer):
    """Delta debugging: tries dropping each of `parts` chunks; when none can go, splits the steps into more."""
    parts = 2
    while len(steps) >= 2 and not replayer.exhausted:
        size = max(1, len(steps) // parts)
        chunks = [steps[start:start + size] for start in range(0, len(steps), size)]
        smaller = first_removal(chunks, replayer)
        if smaller is not None:
            steps = smaller
            parts = max(parts - 1, 2)
        elif parts >= len(steps):
            break
        else:
            parts = min(parts * 2, len(steps))
    return steps


def first_removal(chunks, replayer):
    """The steps left after dropping the first chunk whose absence keeps the failure, or None if every chunk is needed."""
    for dropped in range(len(chunks)):
        if replayer.exhausted:
            return None
        remaining = [step for position, chunk in enumerate(chunks) if position != dropped for step in chunk]
        if remaining and replayer.reproduces(remaining):
            return remaining
    return None


def simplify_arguments(steps, replayer):
    """Replaces each number by 0 and each True by False where the failure still happens, so that what is left is only
    what the failure needs."""
    for index in range(len(steps)):
        for name, value in list(steps[index]['args'].items()):
            if name == 'which' and 'session' in steps[index]:
                continue    # the recorded session decides, not the index
            simpler = simpler_value(value)
            if simpler is None:
                continue
            if replayer.exhausted:
                return steps
            candidate = copy.deepcopy(steps)
            candidate[index]['args'][name] = simpler
            if replayer.reproduces(candidate):
                steps = candidate
    return steps


def simpler_value(value):
    """What to try instead of `value`, or None when it is already as simple as it gets."""
    if value is True:
        return False
    if isinstance(value, int) and not isinstance(value, bool) and value != 0:
        return 0
    return None
