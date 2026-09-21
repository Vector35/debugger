"""WinDbg/TTD integration test supervisor.

This module deliberately does not import Binary Ninja.  The worker is a fresh process whose first
Binary Ninja import happens after BN_DEBUGENGINE_DLLS has been set by CI.
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent


@pytest.mark.skipif(platform.system() != "Windows", reason="WinDbg is Windows-only")
def test_pinned_windbg_ttd_in_clean_process(tmp_path):
    windbg_root = Path(os.environ["BN_DEBUGENGINE_DLLS"])
    recorder = windbg_root / "amd64" / "ttd" / "TTD.exe"
    target = ROOT / "binaries" / "Windows-x86_64" / "helloworld.exe"
    trace = tmp_path / "helloworld.run"
    assert recorder.is_file(), recorder
    assert target.is_file(), target

    record = subprocess.run([str(recorder), "-out", str(trace), str(target)],
                            capture_output=True, text=True, timeout=120)
    print(record.stdout)
    print(record.stderr, file=sys.stderr)
    assert record.returncode == 0
    assert trace.is_file()

    environment = os.environ.copy()
    environment["BN_DEBUGENGINE_DLLS"] = str(windbg_root)
    worker = ROOT / "windbg_test_worker.py"
    replay = subprocess.run([sys.executable, str(worker), str(target), str(trace)], env=environment,
                            capture_output=True, text=True, timeout=120)
    print(replay.stdout)
    print(replay.stderr, file=sys.stderr)
    assert replay.returncode == 0
    assert "WINDBG_TTD_OK" in replay.stdout
