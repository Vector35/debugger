# Building

- Update to the latest development build of Binary Ninja 
  - Follow [this](https://docs.binary.ninja/guide/index.html#support) guide to do so

- Clone `binaryninja-api` and checkout to the corresponding commit used to build the version of Binary Ninja you are running
  - If you updated to the latest dev build of Binary Ninja, then you can checkout the api repo to the latest dev as well
  - A more robust approach is to find the file `api_REVISION.txt` in `BN_INSTALLATION_FOLDER/Resources`

```bash
git clone --recurse-submodules https://github.com/Vector35/binaryninja-api.git
cd binaryninja-api
git checkout dev
# or git checkout commit_hash
```

- Download LLDB development build for your OS at https://github.com/Vector35/lldb-artifacts/releases/latest - make sure that the correct LLDB version is downloaded (`grep 'LLVM_VERSION ' core/CMakeLists.txt` can help)
  - Extract the zip archive to `~/libclang`

- Download Qt development build for your OS at https://github.com/Vector35/qt-artifacts/releases/latest.
  - Extract the zip archive to `~/Qt`

- Build and install a static Protobuf (needed for `X2WinRpcAdapter`)

  macOS / Linux:
  ```bash
  git clone --depth 1 -b v35.1 https://github.com/protocolbuffers/protobuf.git
  cmake -S protobuf -B protobuf/build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_STANDARD=20 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF \
    -Dprotobuf_BUILD_TESTS=OFF \
    -DCMAKE_DISABLE_FIND_PACKAGE_absl=ON \
    -DCMAKE_INSTALL_PREFIX="$HOME/local/protobuf-static"
  cmake --build protobuf/build --target install -j $(nproc 2>/dev/null || sysctl -n hw.ncpu)
  ```

  Windows (PowerShell, from a Developer Command Prompt so MSVC is on `PATH`):
  ```powershell
  git clone --depth 1 -b v35.1 https://github.com/protocolbuffers/protobuf.git
  cmake -S protobuf -B protobuf/build `
    -DCMAKE_CXX_STANDARD=20 `
    -DCMAKE_CXX_STANDARD_REQUIRED=ON `
    -DBUILD_SHARED_LIBS=OFF `
    -Dprotobuf_BUILD_SHARED_LIBS=OFF `
    -Dprotobuf_BUILD_TESTS=OFF `
    -DCMAKE_DISABLE_FIND_PACKAGE_absl=ON `
    -DCMAKE_INSTALL_PREFIX="$env:HOMEDRIVE$env:HOMEPATH\local\protobuf-static"
  cmake --build protobuf/build --target install --config Release
  ```

  `core/CMakeLists.txt` looks for this install at `~/local/protobuf-static` (or `%HOMEDRIVE%%HOMEPATH%\local\protobuf-static` on Windows) by default. Set the `PROTOBUF_PATH` environment variable if you installed it somewhere else.

- Build the debugger

```bash
# Get the source
git clone https://github.com/Vector35/debugger.git

# Do an out-of-source build
mkdir -p build
cd build

# Build it
cmake -DBN_API_PATH=../binaryninja-api -DBN_INSTALL_DIR=/path/to/binaryninja/installation ..

make
```

While the code is compiling, it's a good time to check the [Binary Ninja slack](https://slack.binary.ninja) for any updates!

The build artifacts will be in the folder `out`. You should find two files `libdebuggercore` and `libdebuggerui`, and two folders `debugger` (that contains the Python code) and `lldb`. 

- Run the debugger
  - Open Binary Ninja, disable the setting `corePlugins.debugger` so the debugger that comes with Binary Ninja is not loaded
  - Close Binary Ninja
  - Copy everything in the `out` folder to the user plugin folder - `cp -r out/plugins/* ~/.binaryninja/plugins/`
  - Set the environment variable `BN_STANDALONE_DEBUGGER=1`
  - Launch BinaryNinja


## Notes:

- On Windows, building the debugger in Debug mode may cause obscure bugs since the debug ABI of MSVC can be different from that of the release build.
It is recommended to build with `RelWithDebInfo` on Windows.
