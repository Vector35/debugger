#!/usr/bin/env python3

import os
import re
import shlex
import shutil
import subprocess
import sys
import zipfile
import glob
import platform
from pathlib import Path

from target_llvm_version import llvm_version, msvc_build, vs_version

qt_version = "6.10.1"


def normalized_platform():
    machine = platform.machine().lower()
    if platform.system() == "Darwin":
        return "macosx"
    if platform.system() == "Linux":
        return "linux-arm" if machine in ("aarch64", "arm64") else "linux"
    if platform.system() == "Windows":
        return "win64"
    return sys.platform


def remove_dir(path: os.PathLike):
    if sys.platform == 'win32':
        # Windows being Windows. Not doing this as a recursive delete from the shell will yield
        # "access denied" errors. Even deleting the individual files from the terminal does this.
        # Somehow, deleting this way works correctly.
        subprocess.call(f'rmdir /S /Q "{path}"', shell=True)
    else:
        shutil.rmtree(path)


if sys.platform.startswith("win"):
    make_cmd = "ninja"
    # parallel = []
    cmake_generator_array = ["-G", "Ninja"]

    # Import vcvars from Visual Studio
    vcvars = subprocess.check_output(fR"""call "C:\Program Files\Microsoft Visual Studio\{vs_version}\Professional\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver={msvc_build} && set""", shell=True)
    for line in vcvars.split(b'\r\n'):
        line = line.strip()
        if b'=' not in line:
            continue
        parts = line.split(b'=')
        key = parts[0].decode()
        value = b'='.join(parts[1:]).decode()
        os.environ[key] = value
else:
    make_cmd = "ninja"
    # parallel = ["-j", str(args.jobs)]
    cmake_generator_array = ["-G", "Ninja"]

sysroot = None
if sys.platform == 'darwin':
    if Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk').exists():
        if Path('/Applications/Xcode.app').exists():
            print("!! Xcode and CommandLineTools both installed. Defaulting to CommandLineTools but the build may fail.")
        sysroot = '/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk'
    else:
        sysroot = subprocess.check_output(['xcode-select', '-p']).decode().strip()
        sysroot += '/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk'

    print("Sysroot is                   " + sysroot)

base_dir = Path(__file__).resolve().parent.parent
build_path = base_dir / "build"
api_path = build_path / "api"
external_artifacts_path = base_dir / "artifacts-extern"
bn_dev_path = build_path / "BN-dev"

if platform.system() == 'Darwin':
    bn_core_path = bn_dev_path / 'Binary Ninja.app' / 'Contents' / 'MacOS'
elif platform.system() == 'Linux':
    bn_core_path = bn_dev_path / 'binaryninja'
else:
    bn_core_path = bn_dev_path / 'BinaryNinja'

build_output_path = build_path / "out"

if not build_output_path.exists():
    build_output_path.mkdir(parents=True)

# Clean existing files
for f in build_output_path.glob('*'):
    f.unlink()

artifact_path = base_dir / "artifacts"

if not artifact_path.exists():
    artifact_path.mkdir(parents=True)

# Clean existing files
for f in artifact_path.glob('*'):
    f.unlink()

if build_path.exists():
    remove_dir(build_path)

if (base_dir / "CMakeCache.txt").exists():
    (base_dir / "CMakeCache.txt").unlink()


# Copy BN dev to the build directory
path = '{}/{}'.format(external_artifacts_path, 'binaryninja_*.zip')
print(path)
files = glob.glob(path)
if len(files) == 0:
    print('Failed to find binaryninja dev artifact')
    sys.exit(-1)


def extract_zip(bundle, target):
    if sys.platform.startswith("win"):
        z = zipfile.ZipFile(bundle)
        z.extractall(target)
        return True
    else:
        # Don't use zipfile on unix systems, it doesn't do permissions properly
        return subprocess.call(["unzip", "-qq", "-DD", bundle, "-d", target]) == 0


if not os.path.exists(bn_dev_path):
    os.makedirs(bn_dev_path)

try:
    qt_artifact_name = f'qt_{normalized_platform()}_{qt_version}.zip'
    qt_artifact_candidates = [
        external_artifacts_path / qt_artifact_name,
        external_artifacts_path / 'artifacts' / qt_artifact_name,
    ]
    qt_artifact_path = next(path for path in qt_artifact_candidates if path.exists())
    extract_zip(qt_artifact_path, external_artifacts_path)
except StopIteration:
    pass

qt_root = external_artifacts_path / 'Qt' / qt_version
qt_cmake_path = qt_root / 'lib' / 'cmake'
qt_config_path = qt_cmake_path / 'Qt6' / 'Qt6Config.cmake'
if qt_config_path.exists():
    os.environ['QT_INSTALL_DIR'] = str(qt_root.parent)
    os.environ['PATH'] = f'{qt_root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}'
else:
    qt_install_parent = Path(os.environ.get('QT_INSTALL_DIR', Path.home() / 'Qt'))
    qt_root = qt_install_parent / qt_version
    qt_cmake_path = qt_root / 'lib' / 'cmake'
    qt_config_path = qt_cmake_path / 'Qt6' / 'Qt6Config.cmake'
    if not qt_config_path.exists():
        print(f'Failed to find Qt {qt_version} in the new artifact layout.')
        print(f'Expected artifact: {qt_artifact_name}')
        print(f'Checked Qt config: {qt_config_path}')
        sys.exit(1)
    os.environ['PATH'] = f'{qt_root / "bin"}{os.pathsep}{os.environ.get("PATH", "")}'

try:
    # The LLVM build publishes lldb_<platform>_<version>.zip (lowercase). copyExternalArtifactsEx
    # preserves the upstream artifacts/ prefix, so check both locations like Qt above.
    lldb_artifact_name = f'lldb_{normalized_platform()}_{llvm_version}.zip'
    lldb_artifact_candidates = [
        external_artifacts_path / lldb_artifact_name,
        external_artifacts_path / 'artifacts' / lldb_artifact_name,
    ]
    lldb_artifact_path = next(path for path in lldb_artifact_candidates if path.exists())
    extract_zip(lldb_artifact_path, external_artifacts_path)
except StopIteration:
    pass

if not extract_zip(files[0], bn_dev_path):
    print('Failed to unzip binaryninja dev artifact')
    sys.exit(-1)

if subprocess.call(["git", "clone", "https://github.com/Vector35/binaryninja-api", api_path]) != 0:
    print("Failed to clone BN API git repository")
    sys.exit(1)

if subprocess.call(["git", "submodule", "update", "--init", "--recursive"], cwd=api_path) != 0:
    print("Failed to init submodules for BN API")
    sys.exit(1)

# Checkout the API to the correct commit specified in api_REVISION.txt
if platform.system() == 'Darwin':
    api_revision_path = bn_dev_path / 'Binary Ninja.app' / 'Contents' / 'Resources' / 'api_REVISION.txt'
elif platform.system() == 'Linux':
    api_revision_path = bn_dev_path / 'binaryninja' / 'api_REVISION.txt'
else:
    api_revision_path = bn_dev_path / 'BinaryNinja' / 'api_REVISION.txt'

if api_revision_path.exists():
    try:
        with open(api_revision_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            # Extract the commit hash from the URL (format: https://github.com/Vector35/binaryninja-api/tree/<commit_hash>)
            if '/tree/' in first_line:
                api_commit = first_line.split('/tree/')[-1]
                # Remove any trailing path components (e.g., /path or ?query)
                api_commit = api_commit.split('/')[0].split('?')[0]
                # Validate that the commit hash contains only valid git commit characters (hex digits)
                # Git short hashes are typically 7+ chars, full SHA-1 is 40 chars, SHA-256 is 64 chars
                if re.match(r'^[0-9a-fA-F]{7,64}$', api_commit):
                    print(f"Checking out API commit: {api_commit}")
                    if subprocess.call(["git", "checkout", api_commit], cwd=api_path) != 0:
                        print(f"Warning: Failed to checkout API commit {api_commit}")
                        sys.exit(1)
                else:
                    print(f"Warning: Invalid commit hash format in api_REVISION.txt: {api_commit}")
                    sys.exit(1)
            else:
                print(f"Warning: Could not parse API commit from api_REVISION.txt: {first_line}")
                sys.exit(1)
    except (IOError, UnicodeDecodeError) as e:
        print(f"Warning: Failed to read api_REVISION.txt: {e}")
        sys.exit(1)
else:
    print(f"Warning: api_REVISION.txt not found at {api_revision_path}, using default branch")
    sys.exit(1)


print("\nConfiguring debugger...")
if not build_path.exists():
    build_path.mkdir()

cmake_params = []
cmake_params.append(('CMAKE_BUILD_TYPE', 'Release'))
cmake_params.append(('BN_API_PATH', api_path))
cmake_params.append(('BN_INSTALL_DIR', bn_core_path))
cmake_params.append(('CMAKE_PREFIX_PATH', qt_cmake_path))

if sys.platform == 'darwin':
    if sysroot is not None:
        cmake_params.append(('CMAKE_OSX_SYSROOT', sysroot))

    cmake_params.append(("CMAKE_OSX_DEPLOYMENT_TARGET", "10.15"))
    cmake_params.append(("CMAKE_OSX_ARCHITECTURES", "arm64;x86_64"))

cmake_params_array = []
for option, value in cmake_params:
    cmake_params_array.append("-D{}={}".format(option, value))

print(' '.join(shlex.quote(a) for a in ["cmake", str(base_dir)] + cmake_params_array + cmake_generator_array))
if subprocess.call(["cmake", base_dir] + cmake_params_array + cmake_generator_array, cwd=build_path) != 0:
    print("Failed to configure debugger build")
    sys.exit(1)


print("\nBuilding debugger...")
if subprocess.call([make_cmd], cwd=build_path) != 0:
    print("Debugger failed to build")
    sys.exit(1)


print("\nCreating archive...")
with zipfile.ZipFile(artifact_path / f'debugger-{sys.platform}.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(build_output_path):
        root_path = Path(root)
        relpath = root_path.resolve().relative_to(build_output_path.resolve())
        for file in files:
            file_path = root_path / file
            arc_path = Path(file) if relpath == Path('.') else relpath / file
            arc_name = arc_path.as_posix()
            print(f"Adding {arc_name}...")
            info = zipfile.ZipInfo(arc_name)
            info.compress_type = zipfile.ZIP_DEFLATED

            if os.access(file_path, os.X_OK):
                info.external_attr = 0o755 << 16 # -rwxr-xr-x
            else:
                info.external_attr = 0o644 << 16 # -rwxr--r--

            with file_path.open('rb') as f:
                z.writestr(info, f.read())


print("\nRunning unit tests")
env = os.environ.copy()
env["BN_DISABLE_USER_SETTINGS"] = "true"
env["BN_USER_DIRECTORY"] = str(build_output_path)
env["BN_STANDALONE_DEBUGGER"] = "true"
env["BN_DISABLE_CORE_DEBUGGER"] = "true"

license_path = 'license.dat'
if platform.system() == "Linux":
    license_path = os.path.join(os.environ['HOME'], '.binaryninja', 'license.dat')
elif platform.system() == "Darwin":
    license_path = os.path.join(os.environ['HOME'], 'Library', 'Application Support', 'Binary Ninja', 'license.dat')
elif platform.system() == "Windows":
    license_path = os.path.join(os.environ['APPDATA'], 'Binary Ninja', 'license.dat')
with open(license_path, 'r') as f:
    env["BN_LICENSE"] = f.read()

if platform.system() == "Linux":
    bn_python_path = bn_core_path / 'python'
elif platform.system() == "Darwin":
    bn_python_path = bn_core_path.parent / 'Resources' / 'python'
    bn_python_path = bn_python_path.resolve()
elif platform.system() == "Windows":
    bn_python_path = bn_core_path / 'python'

pythonpath = f'{bn_python_path}{os.pathsep}{build_output_path / "plugins"}'
env["PYTHONPATH"] = str(pythonpath)
print('PYTHONPATH: ', pythonpath)

results = base_dir / "test" / "results.xml"
if os.path.exists(results):
    os.unlink(results)

pytest_sources = [
    str(base_dir / "test" / "debugger_test.py")
]


p = subprocess.Popen(["pytest", "-s", "--junitxml", str(results)] + pytest_sources, env=env)
# wait for process to complete
p_stdout, p_stderr = p.communicate()
assert 0 <= p.returncode < 128, f"test run failed: {p_stdout} {p_stderr}"

sys.exit(0)
