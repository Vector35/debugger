# Binary Ninja Debugger

This is the repository for Binary Ninja Debugger. The debugger is written in C++ and is shipped with BN as a plugin.

The debugger is currently in beta status, so it is disabled by default. To enable it, check "Settings" -> "corePlugins" -> "Debugger Plugin (Beta)".


## Platform and Target Support

Currently, the debugger supports local debugging on Windows, Linux, and macOS.

We plan to support remote debugging across different operating systems, as well as attaching to gdb/lldb stub. The progress is tracked in [this issue](https://github.com/Vector35/debugger/issues/122).




## Documentation

- [Online Debugger Python API documentation](https://dev-api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html#binaryninja.debugger.debuggercontroller.DebuggerController)
- There is also a section about the debugger in the User Guide that comes with Binary Ninja

## Building

The build instructions are **outdated**. The stable branch of the debugger is shipped with Binary Ninja on latest dev.

```
# Get the source
git clone https://github.com/Vector35/binaryninja-api.git
git clone https://github.com/Vector35/debugger.git
cd debugger
git checkout dev

# Do an out-of-source build
cd ../
mkdir build
cd build

# Build it
cmake -DBN_API_PATH=../binaryninja-api -DBN_INSTALL_DIR=/path/to/binaryninja/installation ../debugger/
make -j8
```

If you wish a debug build, add `-DCMAKE_BUILD_TYPE=Debug` to the cmake command line.

To install it, first disable `corePlugins.debugger` so the debugger that comes with Binary Ninja is not loaded. Then copy the built `libdebuggercore.so/dll` and the `libdebuggerui.so/dll` to the user plugin folder and relaunch BinaryNinja.


## License

The Binary Ninja Debugger is open-source with [Apache License 2.0](https://raw.githubusercontent.com/Vector35/debugger/dev/LICENSE)

For other open-source components and their respective licenses, please refer to this [list](open-source.md).