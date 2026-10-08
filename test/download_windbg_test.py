from pathlib import Path

import pytest

from scripts.download_windbg import package_version, pinned_version
from scripts import download_windbg


def test_validates_extracted_installation_against_pin(tmp_path):
    version = pinned_version()
    (tmp_path / "AppxManifest.xml").write_text(f'<Package><Identity Version="{version}" /></Package>')
    (tmp_path / "installed_version.txt").write_text(version)
    for name in download_windbg.REQUIRED:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    download_windbg.validate_installation(tmp_path)
    (tmp_path / "installed_version.txt").write_text("0.0.0.0")
    with pytest.raises(RuntimeError, match="source pin"):
        download_windbg.validate_installation(tmp_path)
    (tmp_path / "installed_version.txt").write_text(version)
    (tmp_path / download_windbg.REQUIRED[0]).unlink()
    with pytest.raises(RuntimeError, match="missing"):
        download_windbg.validate_installation(tmp_path)


def test_signature_path_is_passed_as_environment_data(monkeypatch, tmp_path):
    package = tmp_path / "bundle with 'quotes' and $variables.msixbundle"
    calls = []
    monkeypatch.setattr(download_windbg.sys, "platform", "win32")
    monkeypatch.setattr(download_windbg.subprocess, "run",
                        lambda args, **kwargs: calls.append((args, kwargs)))
    download_windbg.verify_signature(package)
    args, kwargs = calls[0]
    assert args[-2] == "-Command"
    assert "$env:BN_WINDBG_BUNDLE" in args[-1]
    assert str(package) not in args[-1]
    assert kwargs["env"]["BN_WINDBG_BUNDLE"] == str(package.resolve())
    assert kwargs["check"] is True


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
