"""Every ADAPTER_FUZZ_* environment variable, read and validated once. Workers inherit the environment."""

import dataclasses
import math
import os
import tempfile
from pathlib import Path
from typing import Mapping, Optional

LENGTHS = {'ci': {'examples': 10, 'steps': 15}, 'long': {'examples': 200, 'steps': 40}}


class SettingsError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Settings:
    sessions: int
    patience: float
    length: str
    examples: int
    steps: int
    seed: int
    shrink_budget: int
    directory: Optional[Path]
    report: Optional[Path]
    parallel: bool
    lock: Path


def _read(environment, name, convert, default, accepts, expected):
    text = environment.get(name, '')
    if text == '':
        return default
    try:
        value = convert(text)
    except ValueError:
        raise SettingsError(f'{name} must be {expected}, not {text!r}') from None
    if not accepts(value):
        raise SettingsError(f'{name} must be {expected}, not {text!r}')
    return value


def _flag(text):
    if text not in ('0', '1'):
        raise ValueError(text)
    return text == '1'


def _anything(value):
    return True


def from_environment(environment: Mapping[str, str] = os.environ) -> Settings:
    """Reads the settings; an unset or empty variable has its default. Raises SettingsError naming a bad one."""
    length = _read(environment, 'ADAPTER_FUZZ_LENGTH', str, 'ci', LENGTHS.__contains__,
                   f"one of {', '.join(LENGTHS)}")
    return Settings(
        sessions=_read(environment, 'ADAPTER_FUZZ_SESSIONS', int, 3, lambda value: value >= 1,
                       'a whole number of at least 1'),
        patience=_read(environment, 'ADAPTER_FUZZ_PATIENCE', float, 1.0,
                       lambda value: math.isfinite(value) and value > 0, 'a number above 0'),
        length=length,
        examples=_read(environment, 'ADAPTER_FUZZ_EXAMPLES', int, LENGTHS[length]['examples'],
                       lambda value: value >= 1, 'a whole number of at least 1'),
        steps=LENGTHS[length]['steps'],
        seed=_read(environment, 'ADAPTER_FUZZ_SEED', int, 0, _anything, 'a whole number'),
        shrink_budget=_read(environment, 'ADAPTER_FUZZ_SHRINK', int, 25, lambda value: value >= 0,
                            'a whole number of at least 0'),
        directory=_read(environment, 'ADAPTER_FUZZ_DIR', Path, None, _anything, 'a directory'),
        report=_read(environment, 'ADAPTER_FUZZ_REPORT', Path, None, _anything, 'a file path'),
        parallel=_read(environment, 'ADAPTER_FUZZ_ALLOW_PARALLEL', _flag, False, _anything, '0 or 1'),
        lock=_read(environment, 'ADAPTER_FUZZ_LOCK', Path, Path(tempfile.gettempdir()) / 'adapter-fuzz.lock',
                   _anything, 'a file path'),
    )
