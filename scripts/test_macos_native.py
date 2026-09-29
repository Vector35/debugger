#!/usr/bin/env python3
"""Run the local native adapter with an entitled, isolated embedded-Python host.

Run this script using a framework Python with pytest installed. It signs only a
new executable in the build directory and never modifies installed applications.
"""
import argparse
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import sysconfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, default=Path('build-native'))
    parser.add_argument('--bn-install', type=Path, required=True,
                        help='Binary Ninja.app used when configuring this build')
    parser.add_argument('--timeout', type=int, default=180,
                        help='Watchdog seconds for the entire pytest process group')
    parser.add_argument('--license-file', type=Path,
                        help='Optional existing license; read into the child environment only')
    parser.add_argument('tests', nargs='*', default=['test/debugger_test.py::MacOSNativeArm64Test'])
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('This PoC requires an arm64 Mac')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    root = Path(__file__).resolve().parents[1]
    build = args.build.resolve()
    output = build / 'out'
    plugins = output / 'plugins'
    if not (plugins / 'libdebuggercore.dylib').is_file() or not (plugins / 'debugger/_debuggercore.py').is_file():
        parser.error('Build debuggercore and debugger_generator_copy before running tests')
    framework = sysconfig.get_config_var('PYTHONFRAMEWORK')
    prefix = sysconfig.get_config_var('PYTHONFRAMEWORKPREFIX')
    include = sysconfig.get_config_var('INCLUDEPY')
    if not framework or not prefix or not include:
        parser.error('Run this script with a framework Python (for example Homebrew Python)')
    host_dir = build / 'test-host'
    host_dir.mkdir(parents=True, exist_ok=True)
    host = host_dir / 'native-python'
    subprocess.run(['xcrun', 'clang', str(root / 'test/macos_native_python.c'),
                    '-I' + include, '-F' + prefix, '-framework', framework, '-o', str(host)], check=True)
    subprocess.run(['codesign', '--force', '--options', 'runtime', '--entitlements',
                    str(root / 'test/macos_native_debugger_entitlements.plist'), '--sign', '-', str(host)], check=True)
    env = os.environ.copy()
    env.update(BN_USER_DIRECTORY=str(output), BN_STANDALONE_DEBUGGER='1', BN_DISABLE_CORE_DEBUGGER='1')
    env['PYTHONPATH'] = os.pathsep.join([str(args.bn_install.resolve() / 'Contents/Resources/python'),
                                       str(plugins), str(root / 'test')])
    license_file = args.license_file
    if not license_file and 'BN_LICENSE' not in env:
        license_file = Path.home() / 'Library/Application Support/Binary Ninja/license.dat'
    if license_file and license_file.is_file():
        env['BN_LICENSE'] = license_file.read_text()
    log_path = build / 'macos-native-tests.log'
    command = [str(host), '-u', '-m', 'pytest', '-v', '-rs'] + args.tests
    print('Testing the worktree adapter; log:', log_path, flush=True)
    with log_path.open('w') as log:
        worker = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result = worker.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print('Watchdog expired; terminating the owned pytest/fixture process group', flush=True)
            os.killpg(worker.pid, signal.SIGKILL)
            worker.wait()
            result = 124
        except KeyboardInterrupt:
            os.killpg(worker.pid, signal.SIGKILL)
            worker.wait()
            result = 130
        finally:
            # Fixtures deliberately inherit this fresh group. Reap any stragglers
            # after failures without touching targets from other debugger sessions.
            try:
                os.killpg(worker.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    print(log_path.read_text(), end='')
    return result


if __name__ == '__main__':
    raise SystemExit(main())
