# Building

- Download LLDB development build for your OS at https://github.com/Vector35/lldb-artifacts/releases. 
  - Extract the zip archive to `~/libclang`

- Download Qt development build for your OS at https://github.com/Vector35/qt-artifacts/releases.
  - Extract the zip archive to `~/Qt`

- Build the debugger

```
# Get the source
git clone https://github.com/Vector35/binaryninja-api.git
git clone https://github.com/Vector35/debugger.git

# Do an out-of-source build
mkdir build
cd build

# Build it
cmake -DBN_API_PATH=../binaryninja-api 
      -DBN_INSTALL_DIR=/path/to/binaryninja/installation

make
```

The build artifacts will be in the folder `out`.

- Run the debugger
  - Open Binary Ninja, disable the setting `corePlugins.debugger` so the debugger that comes with Binary Ninja is not loaded 
  - Copy everything in the `out` folder to the user plugin folder
  - Set the environment variable `BN_STANDALONE_DEBUGGER=1`
  - Launch BinaryNinja
