"""WinDbg/TTD integration test supervisor.

This module deliberately does not import Binary Ninja.  The worker is a fresh process whose first
Binary Ninja import happens after BN_DBGENG_DLLS has been set by CI.
"""

import hashlib
import gzip
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "ttd"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@pytest.mark.skipif(platform.system() != "Windows", reason="WinDbg is Windows-only")
@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_pinned_windbg_ttd_in_clean_process(arch, tmp_path):
    windbg_root = Path(os.environ["BN_DBGENG_DLLS"])
    target = ROOT / "binaries" / ("Windows-x86_64" if arch == "x64" else "Windows-x86") / "helloworld.exe"
    expected_path = FIXTURES / f"helloworld-{arch}.json"
    expected = json.loads(expected_path.read_text())
    archive = FIXTURES / f"helloworld-{arch}.run.gz"
    assert sha256(archive) == expected["archive_sha256"]
    trace = tmp_path / f"helloworld-{arch}.run"
    trace.write_bytes(gzip.decompress(archive.read_bytes()))
    assert target.is_file(), target
    assert trace.is_file()
    assert sha256(target) == expected["target_sha256"]
    assert sha256(trace) == expected["trace_sha256"]

    environment = os.environ.copy()
    environment["BN_DBGENG_DLLS"] = str(windbg_root)
    worker = ROOT / "windbg_test_worker.py"
    replay = subprocess.run([sys.executable, str(worker), str(target), str(trace), str(expected_path)], env=environment,
                            capture_output=True, text=True, timeout=300)
    print(replay.stdout)
    print(replay.stderr, file=sys.stderr)
    assert replay.returncode == 0
    assert "WINDBG_TTD_OK" in replay.stdout
