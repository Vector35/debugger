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

- Build the debugger

  FlatBuffers (needed for `X2WinRpcAdapter`'s wire protocol) is vendored as a git submodule
  under `vendor/` and built as part of this project's own CMake configure/build -- no separate
  install step needed, just make sure submodules are cloned (`--recurse-submodules` below, or
  `git submodule update --init --recursive` after the fact).

```bash
# Get the source
git clone --recurse-submodules https://github.com/Vector35/debugger.git

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
  - On Windows, `BN_DBGENG_DLLS` may point to either the root of an extracted WinDbg package
    (containing `amd64`/`x86` directories) or directly to a directory containing the DbgEng DLLs.
    It takes precedence over the `debugger.x64dbgEngPath` and `debugger.x86dbgEngPath` settings.
  - Launch BinaryNinja


## Windows Remote Debug Server

Windows builds include `windows-debug-server.exe` for Windows user-mode remote debugging from Linux, macOS, or Windows.
It is built and packaged with the debugger; it is not built on Linux or macOS. To build just the server from an already
configured Windows build directory, run:

```powershell
cmake --build build --config RelWithDebInfo --target x2winstub
```

The internal CMake target remains `x2winstub`, but the executable is named `windows-debug-server.exe`.
In a standalone Ninja build it is under `build/out/plugins`; multi-configuration generators such as Visual Studio
place it under `build/out/plugins/RelWithDebInfo`. Internal Binary Ninja builds place it in `BN_CORE_PLUGIN_DIR`.
The Windows package includes the executable in its `plugins` directory. Copy it to the Windows host to run it;
running the server does not require installing Binary Ninja there.

See the [Windows Remote guide](docs/guide/remote-debugging.md#windows-remote-debugging) for connection and launch steps,
and [integration test instructions](test/README.md#windows-remote-integration-tests) for testing it locally on Windows.

## Notes:

- On Windows, building the debugger in Debug mode may cause obscure bugs since the debug ABI of MSVC can be different from that of the release build.
It is recommended to build with `RelWithDebInfo` on Windows.
