# Binary Ninja Debugger

This is the repository for Binary Ninja Debugger. The debugger is written in C++ and is shipped with BN as a plugin.

## Platform and Target Support

This is the current comparability matrix of the debugger. The horizontal lines stand for where we run BN and the vertical lines stand for the targets.

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

The debugger is already shipped with Binary Ninja in stable and development branch. If you wish to contribute code, see [build](build.md) instructions.

## License

The Binary Ninja Debugger is open-source with [Apache License 2.0](https://raw.githubusercontent.com/Vector35/debugger/dev/LICENSE)

For other open-source or redistributable components and their respective licenses, please refer to this
[list](https://dev-docs.binary.ninja/guide/debugger/index.html#open-source).