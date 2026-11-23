"""Runs examples of a machine's operations, drawn at random from a seed, and replays recorded steps."""

import random


def draw_arguments(operation, rng, machine):
    return {name: draw(rng, machine) for name, draw in operation.arguments.items()}


def run_examples(machine_class, examples, steps, seed):
    """Example `i` draws from `random.Random(f'{seed}:{i}')`, so one example can be run again alone."""
    for index in range(examples):
        run_example(machine_class, steps, random.Random(f'{seed}:{index}'))


def run_example(machine_class, steps, rng):
    machine = machine_class()
    try:
        for operation in machine.operations.values():
            if operation.starting:
                machine.perform(operation, draw_arguments(operation, rng, machine))
                machine.run_checks()
        for _ in range(steps):
            if machine.failure is not None:
                break
            enabled = [operation for operation in machine.operations.values()
                       if not operation.starting and operation.enabled(machine)]
            if not enabled:
                break
            operation = rng.choices(enabled, weights=[operation.weight for operation in enabled])[0]
            machine.perform(operation, draw_arguments(operation, rng, machine))
            machine.run_checks()
    finally:
        machine.teardown()


def replay(machine_class, steps):
    """Runs recorded steps. A step whose operation is not enabled is skipped, since a shorter sequence may not reach
    the state that enabled it, and a step that recorded its session acts on that one."""
    machine = machine_class()
    try:
        for step in steps:
            if machine.failure is not None:
                break
            operation = machine.operations.get(step['rule'])
            if operation is None:
                raise AssertionError(f"{machine_class.__name__} has no operation {step['rule']!r} to replay")
            if not operation.enabled(machine):
                continue
            machine.forced_session = step.get('session')
            try:
                machine.perform(operation, step['args'])
            finally:
                machine.forced_session = None
            machine.run_checks()
    finally:
        machine.teardown()
