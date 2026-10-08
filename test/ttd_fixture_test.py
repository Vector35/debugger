"""Cross-platform checks of the committed replay inputs and oracle shape."""
import gzip
import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_ttd_fixture_integrity(arch):
    fixture = ROOT / "fixtures" / "ttd"
    expected = json.loads((fixture / f"helloworld-{arch}.json").read_text())
    archive = (fixture / f"helloworld-{arch}.run.gz").read_bytes()
    assert hashlib.sha256(archive).hexdigest() == expected["archive_sha256"]
    assert hashlib.sha256(gzip.decompress(archive)).hexdigest() == expected["trace_sha256"]
    directory = "Windows-x86_64" if arch == "x64" else "Windows-x86"
    target = (ROOT / "binaries" / directory / "helloworld.exe").read_bytes()
    assert hashlib.sha256(target).hexdigest() == expected["target_sha256"]
    assert {key: len(rows) for key, rows in expected["memory"].items()} == {"r": 4, "w": 1, "e": 1, "rw": 5}
    assert len(expected["calls"]) == 3
