#!/usr/bin/env python3
"""Run debugger pytest against a local standalone build and its matching BN bundle."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from test_process import run_tests


def cache_value(cache, name):
    match = re.search(rf"^{re.escape(name)}:[^=]*=(.*)$", cache, re.MULTILINE)
    if not match:
        raise SystemExit(f"Missing {name} in CMakeCache.txt")
    return Path(match.group(1)).resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    build = args.build_dir.resolve()
    cache_file = build / "CMakeCache.txt"
    if not cache_file.is_file():
        raise SystemExit(f"Configure and build first: {cache_file} is missing")
    cache = cache_file.read_text()
    if cache_value(cache, "CMAKE_HOME_DIRECTORY") != root:
        raise SystemExit("Build directory belongs to another debugger checkout")
    api = cache_value(cache, "BN_API_PATH")
    bn = cache_value(cache, "BN_INSTALL_DIR")
    revision_file = bn.parent / "Resources" / "api_REVISION.txt"
    if not revision_file.is_file():
        raise SystemExit(f"BN API revision file is missing: {revision_file}")
    match = re.search(r"/tree/([0-9a-f]{40})", revision_file.read_text())
    if not match:
        raise SystemExit("Cannot parse BN API revision")
    api_revision = subprocess.check_output(["git", "-C", str(api), "rev-parse", "HEAD"], text=True).strip()
    if api_revision != match.group(1):
        raise SystemExit(f"API mismatch: BN requires {match.group(1)}, checkout is {api_revision}")

    plugins = build / "out" / "plugins"
    if not (plugins / "libdebuggercore.dylib").is_file() or not (plugins / "debugger" / "__init__.py").is_file():
        raise SystemExit(f"Built standalone plugin is missing in {plugins}")
    bn_python = bn.parent / "Resources" / "python"
    if not bn_python.is_dir():
        raise SystemExit(f"BN Python bindings missing: {bn_python}")
    license_file = Path.home() / "Library" / "Application Support" / "Binary Ninja" / "license.dat"
    if not license_file.is_file():
        raise SystemExit(f"BN license file is missing: {license_file}")

    env = os.environ.copy()
    env.update({
        "BN_DISABLE_USER_SETTINGS": "true",
        "BN_USER_DIRECTORY": str(build / "out"),
        "BN_STANDALONE_DEBUGGER": "true",
        "BN_DISABLE_CORE_DEBUGGER": "true",
        "BN_LICENSE": license_file.read_text(),
        "PYTHONPATH": os.pathsep.join((str(bn_python), str(plugins))),
        "PYTHONUNBUFFERED": "1",
    })
    sources = [str(root / "test" / "debugger_test.py"), str(root / "test" / "attach_timeout_test.py")]
    extra = args.pytest_args
    if extra and extra[0] == "--":
        extra = extra[1:]
    print(f"Testing {plugins} against {bn} (API {api_revision})", flush=True)
    return run_tests([sys.executable, "-m", "pytest", "-s", "--junitxml", str(root / "test" / "results-local.xml"), *sources, *extra], env, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
