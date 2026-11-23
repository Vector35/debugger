"""What a failure is, and how failures are told apart: keys, normalized messages, crash descriptions."""

import dataclasses
import re
from typing import NamedTuple, Optional


@dataclasses.dataclass
class Failure:
    key: str
    kind: str
    message: str
    where: str
    steps: list
    count: int = 1
    crash: str = ''
    traceback: str = ''
    history: list = dataclasses.field(default_factory=list)
    reproducible: Optional[bool] = None
    shrink_replays: int = 0
    original_steps: int = 0


class CrashDescription(NamedTuple):
    name: str
    frames: list


def normalize(text):
    text = re.sub(r'0x[0-9a-fA-F]+', 'ADDR', text)
    text = re.sub(r'\bs\d+(\([^)]*\))?', 'sN', text)
    text = re.sub(r'\[[^\]]*\]', '[...]', text)
    return re.sub(r'\d+', 'N', text)


def failure_key(record):
    return f"{record['where']}: {record['kind']}: {normalize(record['message'])}"


def describe_crash(text, returncode):
    """Names a dead worker from what faulthandler wrote: the signal or timeout, and the Python frames of the crashing
    thread when it had any."""
    first = next((line for line in text.splitlines()
                  if line.startswith(('Fatal Python error', 'Windows fatal exception', 'Timeout'))), '')
    if first.startswith('Timeout'):
        name = 'hang'
    elif first:
        name = first.split(':', 1)[1].strip() if ':' in first else first
    else:
        name = f'exit status {returncode}'
    frames = []
    block = text.split('Current thread', 1)
    if len(block) == 2:
        for line in block[1].splitlines()[1:]:
            match = re.match(r'\s+File "[^"]*", line \d+ in (\S+)', line)
            if not match:
                break
            frames.append(match.group(1))
            if len(frames) == 3:
                break
    return CrashDescription(name, frames)


def crash_key(description, steps):
    where = ','.join(description.frames) if description.frames \
        else f'while running {steps[-1]["rule"] if steps else "nothing"}'
    return f'crash: {description.name}: {where}'


def unfinished_example(log):
    """The steps of the example that was running when the worker died, or None if it was between examples."""
    started = {}
    for record in log:
        example = record['example']
        if record.get('start'):
            started[example] = {'steps': [], 'warm_up': record['warm_up']}
        elif 'step' in record:
            started[example]['steps'].append(record['step'])
        elif 'target' in record:
            started[example]['steps'][-1]['session'] = record['target']
        elif record.get('end'):
            started.pop(example, None)
    return next(iter(started.values()), None)
