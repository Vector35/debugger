"""WinDbg/TTD integration test supervisor.

This module deliberately does not import Binary Ninja.  The worker is a fresh process whose first
Binary Ninja import happens after BN_DBGENG_DLLS has been set by CI.
"""

import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
TARGET_SHA256 = "4ea4d20b6357794a8c01cf371e6a7b3eec16384e235fc4f9ea02f57d3d368663"
TRACE_SHA256 = "eace0baeb61ef64a2032663310e2f8c7c8e1ccd8cacfde067aedb1c71f980c5a"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@pytest.mark.skipif(platform.system() != "Windows", reason="WinDbg is Windows-only")
def test_pinned_windbg_ttd_in_clean_process():
    windbg_root = Path(os.environ["BN_DBGENG_DLLS"])
    target = ROOT / "binaries" / "Windows-x86_64" / "helloworld.exe"
    trace = ROOT / "binaries" / "Windows-x86_64" / "helloworld.run"
    assert target.is_file(), target
    assert trace.is_file()
    assert sha256(target) == TARGET_SHA256
    assert sha256(trace) == TRACE_SHA256

    environment = os.environ.copy()
    environment["BN_DBGENG_DLLS"] = str(windbg_root)
    worker = ROOT / "windbg_test_worker.py"
    replay = subprocess.run([sys.executable, str(worker), str(target), str(trace)], env=environment,
                            capture_output=True, text=True, timeout=120)
    print(replay.stdout)
    print(replay.stderr, file=sys.stderr)
    assert replay.returncode == 0
    assert "WINDBG_TTD_OK" in replay.stdout
