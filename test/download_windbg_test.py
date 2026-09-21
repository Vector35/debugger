from pathlib import Path

import pytest

from scripts.download_windbg import package_version, pinned_version


def test_downloader_uses_source_pin():
    header = Path(__file__).resolve().parents[1] / "installer" / "windbg_version.h"
    assert f'kDefaultVersion = "{pinned_version()}"' in header.read_text(encoding="utf-8")


def test_reads_namespaced_package_version(tmp_path):
    (tmp_path / "AppxManifest.xml").write_text(
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
        '<Identity Name="Microsoft.WinDbg" Version="1.2603.20001.0" />'
        '</Package>', encoding="utf-8")
    assert package_version(tmp_path) == "1.2603.20001.0"


def test_rejects_manifest_without_identity(tmp_path):
    (tmp_path / "AppxManifest.xml").write_text("<Package />", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Could not read package version"):
        package_version(tmp_path)
