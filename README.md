# Binary Ninja Debugger

This is the repository for Binary Ninja Debugger. The debugger is written in C++ and is shipped with BN as a plugin.

## Platform and Target Support

This is the current comparability matrix of the debugger. The horizontal lines stands for where we run BN and the vertical lines stands for the targets.

| Target  🔽 Host ▶️    | macOS              | Linux              | Windows            | Note |
|-----------------------|--------------------|--------------------|--------------------|------|
| macOS                 | Yes (Local/Remote) | Yes (Remote)       | Yes (Remote)       |      |
| Linux                 | Yes (Remote)       | Yes (Local/Remote) | Yes (Remote)       |      |
| Windows               | Planned            | Planned            | Yes (Local/Remote) |      |
| GDB Server            | Yes                | Yes                | Yes                | (1)  |
| LLDB Server           | Yes                | Yes                | Yes                |      |
| Windows Kernel        | TBD                | TBD                | Planned            |      |
| DebugAdapter Protocol | Planned            | Planned            | Planned            |      |

Explanation:
- `Yes` means the feature is supported.
- `Planned` means that we plan to implement it.
- `TBD` means that we have not decided whether to support it, or how to support it.
- `No` means it is not possible to do, at least for now.

Notes:

(1). Right now, we only support gdbserver with android remote debugging. Support for other gdbserver or gdb stub, e.g., qiling, VMWare, QEMU, will be added later.

The progress is tracked in [this issue](https://github.com/Vector35/debugger/issues/122).




## Documentation

- [Online Debugger Python API documentation](https://dev-api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html#binaryninja.debugger.debuggercontroller.DebuggerController)
- There is also a section about the debugger in the User Guide that comes with Binary Ninja

## Building

The build instructions are **outdated**. The stable branch of the debugger is shipped with Binary Ninja on latest dev.

```
# Get the source
git clone https://github.com/Vector35/binaryninja-api.git
git clone https://github.com/Vector35/debugger.git

# Do an out-of-source build
mkdir build
cd build

# Build it
cmake -DBN_API_PATH=../binaryninja-api -DBN_INSTALL_DIR=/path/to/binaryninja/installation -DLLDB_PATH=/path/to/lldb ../debugger/
make
```

The build artifacts will be in the folder `out`.

Note, the above instruction requires LLDB, whose build instruction is not included here. We will update this later.

To install it, first disable `corePlugins.debugger` so the debugger that comes with Binary Ninja is not loaded. Then copy everything in the `out` folder to the user plugin folder and relaunch BinaryNinja.


## License

The Binary Ninja Debugger is open-source with [Apache License 2.0](https://raw.githubusercontent.com/Vector35/debugger/dev/LICENSE)

For other open-source components and their respective licenses, please refer to this [list](open-source.md).
