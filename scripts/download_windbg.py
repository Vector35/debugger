#!/usr/bin/env python3
"""Download the debugger's pinned WinDbg package and create a CI artifact."""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_HEADER = ROOT / "installer" / "windbg_version.h"
REQUIRED = (
    "amd64/dbgeng.dll", "amd64/dbghelp.dll", "amd64/dbgmodel.dll",
    "amd64/dbgcore.dll", "amd64/dbgsrv.exe", "amd64/ttd/TTD.exe",
    "amd64/ttd/TTDRecord.dll",
)


def pinned_version():
    match = re.search(r'kDefaultVersion\s*=\s*"([0-9.]+)"',
                      VERSION_HEADER.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"Could not read kDefaultVersion from {VERSION_HEADER}")
    return match.group(1)


def verify_signature(package):
    if sys.platform != "win32":
        return
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; "
        "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Microsoft') "
        "{ Write-Error ('Invalid WinDbg signature: ' + $s.Status); exit 1 }"
    )
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command,
                    str(package)], check=True)


def extract_member(archive, member, destination):
    with zipfile.ZipFile(archive) as bundle:
        try:
            info = next(item for item in bundle.infolist()
                        if Path(item.filename).name.lower() == member.lower())
        except StopIteration as error:
            raise RuntimeError(f"{member} is missing from {archive}") from error
        with bundle.open(info) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)


def build_artifact(output_dir):
    version = pinned_version()
    url = ("https://windbg.download.prss.microsoft.com/dbazure/prod/"
           f"{version.replace('.', '-')}/windbg.msixbundle")
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = output_dir / f"windbg_{version}.zip"

    with tempfile.TemporaryDirectory(prefix="debugger-windbg-") as temporary_name:
        temporary = Path(temporary_name)
        bundle = temporary / "windbg.msixbundle"
        inner = temporary / "windbg_win-x64.msix"
        extracted = temporary / "windbg"
        print(f"Downloading WinDbg {version} from {url}", flush=True)
        urllib.request.urlretrieve(url, bundle)
        verify_signature(bundle)
        extract_member(bundle, "windbg_win-x64.msix", inner)
        with zipfile.ZipFile(inner) as package:
            package.extractall(extracted)

        missing = [name for name in REQUIRED if not (extracted / Path(name)).is_file()]
        if missing:
            raise RuntimeError("WinDbg package is missing required files: " + ", ".join(missing))
        (extracted / "installed_version.txt").write_text(version, encoding="utf-8")
        if artifact.exists():
            artifact.unlink()
        shutil.make_archive(str(artifact.with_suffix("")), "zip", extracted)

    print(f"Created {artifact}", flush=True)
    return artifact


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts")
    args = parser.parse_args()
    build_artifact(args.output.resolve())


if __name__ == "__main__":
    main()
