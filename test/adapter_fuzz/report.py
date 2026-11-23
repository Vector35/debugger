"""What a campaign found, as text for the person running it and as JSON for tools."""

import dataclasses
from pathlib import Path
from typing import List

from .failures import Failure


@dataclasses.dataclass
class Report:
    failures: List[Failure]
    examples: int
    crashes: int
    directory: Path
    seconds: float
    adapter: str
    machine: str
    seed: int


def format_step(step):
    arguments = ', '.join(f'{name}={value!r}' for name, value in step['args'].items()
                          if not (name == 'which' and 'session' in step))
    target = f"s{step['session']}." if 'session' in step else ''
    return f"{target}{step['rule']}({arguments})"


def format_report(report):
    lines = [f'{len(report.failures)} distinct failure(s) in {report.examples} examples '
             f'({report.crashes} crashed or hung the process), {report.seconds:.0f}s, logs in {report.directory}']
    for number, failure in enumerate(report.failures, 1):
        lines += ['', f'[{number}] {failure.kind}: {failure.message.splitlines()[0] if failure.message else ""}',
                  f'    seen {failure.count} time(s); detected in {failure.where or "the worker"}']
        if failure.reproducible is False:
            lines.append('    did not reproduce when replayed, so this is the unshrunk sequence '
                         f'({len(failure.steps)} steps)')
        elif failure.reproducible:
            lines.append(f'    shortest sequence found ({len(failure.steps)} of {failure.original_steps} steps, '
                         f'{failure.shrink_replays} replays):')
        lines += [f'      {format_step(step)}' for step in failure.steps]
        if failure.crash:
            lines += ['    crash output:'] + [f'      {line}' for line in failure.crash.strip().splitlines()[:14]]
        elif failure.traceback:
            lines += ['    traceback:'] + [f'      {line}' for line in failure.traceback.strip().splitlines()[-6:]]
    return '\n'.join(lines)


def report_data(report, settings):
    return {
        'adapter': report.adapter, 'machine': report.machine, 'seed': report.seed,
        'examples': report.examples, 'crashes': report.crashes, 'seconds': round(report.seconds, 1),
        'patience': settings.patience, 'directory': str(report.directory),
        'failures': [{'key': failure.key, 'kind': failure.kind, 'message': failure.message, 'where': failure.where,
                      'count': failure.count, 'reproducible': failure.reproducible,
                      'original_steps': failure.original_steps, 'shrink_replays': failure.shrink_replays,
                      'steps': failure.steps, 'traceback': failure.traceback, 'crash': failure.crash}
                     for failure in report.failures],
    }
