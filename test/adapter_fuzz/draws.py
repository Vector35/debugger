"""Argument generators for operations: each is called with the example's random generator and the machine."""


class OneOf:
    def __init__(self, options):
        self.options = options

    def __call__(self, rng, machine):
        options = self.options(machine) if callable(self.options) else self.options
        return rng.choice(options)


class Integers:
    def __init__(self, low, high):
        self.low = low
        self.high = high

    def __call__(self, rng, machine):
        return rng.randint(self.low, self.high)


class Booleans:
    def __call__(self, rng, machine):
        return rng.choice([False, True])


def one_of(options):
    """One of a list, or of the list that a function of the machine returns, for a choice that depends on the adapter."""
    return OneOf(options)


def integers(low, high):
    """An integer from `low` to `high`, both included."""
    return Integers(low, high)


def booleans():
    return Booleans()
