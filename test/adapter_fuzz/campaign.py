"""Runs batches of examples in worker processes and reports each distinct failure with the shortest sequence that
reproduces it. The settings are described in README.md."""

import dataclasses
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from .common import WORKER_SECONDS_PER_EXAMPLE
from .failures import Failure, crash_key, describe_crash, failure_key, unfinished_example
from .lock import CampaignBusy, CampaignLock
from .recording import WorkerFiles
from .report import Report, format_report, report_data
from .settings import from_environment
from .shrink import shrink

TEST_DIRECTORY = Path(__file__).resolve().parent.parent
BATCH_EXAMPLES = 50


@dataclasses.dataclass
class WorkerRun:
    returncode: object
    log: list
    failures: list
    crash: str
    files: WorkerFiles


def read_records(path):
    try:
        with open(path) as stream:
            return [json.loads(line) for line in stream if line.strip()]
    except FileNotFoundError:
        return []


class Campaign:
    def __init__(self, profile_name, machine_spec, settings=None):
        self.settings = settings or from_environment()
        self.profile = profile_name
        self.machine = machine_spec
        self.directory = (self.settings.directory or Path(tempfile.mkdtemp(prefix='adapter-fuzz-'))) /re.sub(r'\W+', '_', f'{profile_name}_{machine_spec}')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.failures = {}
        self.crashes = 0
        self.done = 0
        self.counter = 0

    def start_worker(self, mode, extra, timeout):
        self.counter += 1
        directory = self.directory / f'{mode}{self.counter}'
        directory.mkdir()
        files = WorkerFiles(directory)
        # The workers change debugger settings that they restore on teardown, which a hang or crash skips. With this
        # set, nothing they change reaches the user's settings file.
        environment = {'BN_DISABLE_USER_SETTINGS': 'true', **os.environ, 'PYTHONUNBUFFERED': '1', **files.environment()}
        command = [sys.executable, '-m', 'adapter_fuzz.worker', mode, '--profile', self.profile, '--machine', self.machine]
        with open(files.output, 'w') as output:
            try:
                result = subprocess.run(command + extra, cwd=TEST_DIRECTORY, env=environment, stdout=output,
                                        stderr=subprocess.STDOUT, timeout=timeout)
                returncode = result.returncode
            except subprocess.TimeoutExpired:
                returncode = 'timeout'
        crash = files.crash.read_text() if files.crash.exists() else ''
        return WorkerRun(returncode, read_records(files.log), read_records(files.failures), crash, files)

    def add(self, failure):
        known = self.failures.get(failure.key)
        if known is None:
            failure.original_steps = len(failure.steps)
            self.failures[failure.key] = failure
            return
        known.count += 1
        if len(failure.steps) < len(known.steps):
            known.steps = failure.steps
            known.original_steps = len(failure.steps)
            known.history = failure.history

    def add_recorded(self, record):
        self.add(Failure(key=failure_key(record), kind=record['kind'], message=record['message'], where=record['where'],
                         steps=record['steps'], traceback=record['traceback'], history=record['history']))

    def add_crash(self, returncode, unfinished, crash):
        self.crashes += 1
        steps = unfinished['steps'] if unfinished else []
        description = describe_crash(crash, returncode)
        self.add(Failure(key=crash_key(description, steps), kind='crash', message=description.name,
                         where=','.join(description.frames), steps=steps, crash=crash or f'exit status {returncode}'))

    def run(self):
        with CampaignLock(self.settings):
            return self.run_locked()

    def run_locked(self):
        started = time.monotonic()
        batch = 0
        while self.done < self.settings.examples:
            wanted = min(BATCH_EXAMPLES, self.settings.examples - self.done)
            worker = self.start_worker(
                'run', ['--seed', str(self.settings.seed + batch), '--examples', str(wanted),
                        '--steps', str(self.settings.steps)],
                timeout=WORKER_SECONDS_PER_EXAMPLE * wanted)
            batch += 1
            finished = [record for record in worker.log if record.get('end') and not record['warm_up']]
            self.done += len(finished)
            for record in worker.failures:
                if not record['warm_up']:
                    self.add_recorded(record)
            if worker.returncode == 0:
                if not finished:
                    break
                continue
            unfinished = unfinished_example(worker.log)
            if unfinished is None or unfinished['warm_up']:
                # The worker never got to run an example, so another one would not either
                output = worker.files.output.read_text()[-1500:]
                self.add(Failure(key='worker: could not start', kind='worker', message=output,
                                 where='worker', steps=[], crash=worker.crash))
                break
            self.done += 1
            self.add_crash(worker.returncode, unfinished, worker.crash)
        for failure in self.failures.values():
            self.shrink(failure)
        return Report(sorted(self.failures.values(), key=lambda failure: -failure.count), self.done, self.crashes,
                      self.directory, time.monotonic() - started, self.profile, self.machine, self.settings.seed)

    def replay(self, steps):
        """Runs the steps in a fresh process. Returns the key of the failure they cause, or None."""
        steps_file = self.directory / 'steps.json'
        steps_file.write_text(json.dumps(steps))
        worker = self.start_worker('replay', ['--steps-file', str(steps_file)], timeout=WORKER_SECONDS_PER_EXAMPLE)
        failures = [record for record in worker.failures if not record['warm_up']]
        if failures:
            return failure_key(failures[0])
        if worker.returncode != 0:
            unfinished = unfinished_example(worker.log)
            if unfinished is not None and not unfinished['warm_up']:
                return crash_key(describe_crash(worker.crash, worker.returncode), unfinished['steps'])
        return None

    def shrink(self, failure):
        if not failure.steps or failure.kind == 'worker' or self.settings.shrink_budget <= 0:
            return
        shrunk = shrink(failure.steps, failure.key, self.replay, self.settings.shrink_budget)
        failure.reproducible = shrunk.reproducible
        if shrunk.reproducible:
            failure.shrink_replays = shrunk.replays
            failure.steps = shrunk.steps


def run_campaign(profile_name, machine_spec):
    campaign = Campaign(profile_name, machine_spec)
    report = campaign.run()
    text = format_report(report)
    data = json.dumps(report_data(report, campaign.settings), indent=2)
    (campaign.directory / 'report.json').write_text(data)
    if campaign.settings.report:
        campaign.settings.report.write_text(data)
    print(text, flush=True)
    return report, text


def assert_clean(profile_name, machine_spec):
    """Runs a campaign and fails with its report if it found anything."""
    try:
        report, text = run_campaign(profile_name, machine_spec)
    except CampaignBusy as busy:
        pytest.fail(str(busy), pytrace=False)
    if report.failures:
        pytest.fail(text, pytrace=False)
