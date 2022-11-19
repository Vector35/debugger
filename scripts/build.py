#!/usr/bin/env python3

import os
import shlex
import shutil
import subprocess
import sys
import zipfile
import glob
import platform
from pathlib import Path

from target_llvm_version import llvm_version, msvc_build, vs_version


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
bn_dev_artifact_path = base_dir / "artifacts-extern" / "artifacts"
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
path = '{}/{}'.format(bn_dev_artifact_path, 'binaryninja_*.zip')
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
        return subprocess.call(["unzip", "-DD", bundle, "-d", target]) == 0


if not os.path.exists(bn_dev_path):
    os.makedirs(bn_dev_path)

if not extract_zip(files[0], bn_dev_path):
    print('Failed to unzip binaryninja dev artifact')
    sys.exit(-1)

if subprocess.call(["git", "clone", "https://github.com/Vector35/binaryninja-api", api_path]) != 0:
    print("Failed to clone BN API git repository")
    sys.exit(1)


print("\nConfiguring debugger...")
if not build_path.exists():
    build_path.mkdir()

cmake_params = []
cmake_params.append(('CMAKE_BUILD_TYPE', 'Release'))
cmake_params.append(('BN_API_PATH', api_path))
cmake_params.append(('BN_INSTALL_DIR', bn_core_path))

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
        relpath = root.replace(str(build_output_path), "")
        relpath = relpath.strip('\/')
        for file in files:
            print(f"Adding {relpath}/{file}...")
            file_path = os.path.join(root, file)
            arc_name = os.path.join(relpath, file)
            info = zipfile.ZipInfo(arc_name)
            info.compress_type = zipfile.ZIP_DEFLATED

            if os.access(file_path, os.X_OK):
                info.external_attr = 0o755 << 16 # -rwxr-xr-x
            else:
                info.external_attr = 0o644 << 16 # -rwxr--r--

            with open(file_path, 'rb') as f:
                z.writestr(info, f.read())


print("\nRunning unit tests")
env = os.environ.copy()
env["BN_DISABLE_USER_SETTINGS"] = "true"
env["BN_DISABLE_REPOSITORY_PLUGINS"] = "true"
env["BN_USER_DIRECTORY"] = str(build_output_path)
env["BN_STANDALONE_DEBUGGER"] = "true"

license_path = 'license.dat'
if platform.system() == "Linux":
    license_path = os.path.join(os.environ['HOME'], '.binaryninja', 'license.dat')
elif platform.system() == "Darwin":
    license_path = os.path.join(os.environ['HOME'], 'Library', 'Application Support', 'Binary Ninja', 'license.dat')
elif platform.system() == "Windows":
    license_path = os.path.join(os.environ['APPDATA'], 'Binary Ninja', 'license.dat')
with open(license_path, 'r') as f:
    env["BN_LICENSE"] = f.read()

winpath = ''
if platform.system() == "Linux":
    bn_python_path = bn_core_path / 'python'
elif platform.system() == "Darwin":
    bn_python_path = bn_core_path.parent / 'Resources' / 'python'
    bn_python_path = bn_python_path.resolve()
elif platform.system() == "Windows":
    bn_python_path = bn_core_path / 'python'
    winpath = os.environ["LOCALAPPDATA"] + "\\Programs\\Python\\Python38\\Scripts\\"

pythonpath = f'{bn_python_path}{os.pathsep}{build_output_path / "plugins"}'
env["PYTHONPATH"] = str(pythonpath)
print('PYTHONPATH: ', pythonpath)

results = base_dir / "test" / "results.xml"
if os.path.exists(results):
    os.unlink(results)

pytest_sources = [
    str(base_dir / "test" / "debugger_test.py")
]

p = subprocess.Popen(["pipenv", "run", winpath + "py.test", "--junitxml", str(results)] + pytest_sources, env=env)
# wait for process to complete
p_stdout, p_stderr = p.communicate()
assert 0 <= p.returncode < 128, f"pipenv run failed: {p_stdout} {p_stderr}"
p = subprocess.Popen(["pipenv", "--rm"], env=env)
p_stdout, p_stderr = p.communicate()
assert p.returncode == 0, f"pipenv --rm failed: {p_stdout} {p_stderr}"

sys.exit(0)
