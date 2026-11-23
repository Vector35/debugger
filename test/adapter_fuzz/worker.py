"""Runs fuzz examples in a child process. Started by campaign.py."""

import argparse
import faulthandler
import importlib
import json
import sys

from . import engine
from .machine import machine_for
from .profile import ADAPTERS
from .recording import crash_stream


def load_machine(spec, profile_name):
    module_name, _, class_name = spec.partition(':')
    base = getattr(importlib.import_module(module_name), class_name)
    profile = next(profile for profile in ADAPTERS if profile.name == profile_name)
    return machine_for(profile, base)


def run(machine, examples, steps, seed_value):
    machine.warm_up()
    engine.run_examples(machine, examples, steps, seed_value)


def replay(machine, steps):
    machine.warm_up()
    engine.replay(machine, steps)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['run', 'replay'])
    parser.add_argument('--profile', required=True)
    parser.add_argument('--machine', required=True)
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--examples', type=int, default=10)
    parser.add_argument('--steps', type=int, default=15)
    parser.add_argument('--steps-file')
    arguments = parser.parse_args()
    faulthandler.enable(file=crash_stream() or sys.stderr, all_threads=True)
    machine = load_machine(arguments.machine, arguments.profile)
    if arguments.mode == 'run':
        run(machine, arguments.examples, arguments.steps, arguments.seed)
    else:
        with open(arguments.steps_file) as stream:
            replay(machine, json.load(stream))


if __name__ == '__main__':
    main()
