# Binary Ninja Debugger

This is the repository for Binary Ninja Debugger. The debugger is written in C++ and is shipped with BN as a plugin.

## Features

- Multi-platform debugging support (Windows, Linux, macOS)
- Multiple debug adapters (LLDB, GDB, WinDbg, etc.)
- Remote debugging capabilities
- **Custom Debug Adapter API** - Create your own debug adapters in C++ or Python
- Time Travel Debugging (TTD) support
- Kernel debugging on Windows

## Custom Debug Adapters

The debugger now supports custom debug adapters that can be implemented in both C++ and Python. This allows extending the debugger with support for new protocols, targets, or specialized debugging scenarios.

See [docs/custom_debug_adapters.md](docs/custom_debug_adapters.md) for detailed documentation and examples.

## Platform and Target Support

This is the current comparability matrix of the debugger. The columns stand for where we run BN and the rows stand for the targets.

| Target  🔽 Host ▶️                   | macOS                                                   | Linux                                                   | Windows                                                 | Note |
|--------------------------------------|---------------------------------------------------------|---------------------------------------------------------|---------------------------------------------------------|------|
| macOS user                           | Yes (Local/Remote)                                      | Yes (Remote)                                            | Yes (Remote)                                            |      |
| Linux user                           | Yes (Remote)                                            | Yes (Local/Remote)                                      | Yes (Remote)                                            |      |
| Windows user                         | [#70](https://github.com/Vector35/debugger/issues/70)   | [#70](https://github.com/Vector35/debugger/issues/70)   | Yes (Local/Remote)                                      |      |
| GDB Server                           | Yes                                                     | Yes                                                     | Yes                                                     |      |
| GDB RSP (QEMU/VMWare/Qiling/Android) | Yes                                                     | Yes                                                     | Yes                                                     |      |
| GDB Machine Interface                | [#170](https://github.com/Vector35/debugger/issues/170) | [#170](https://github.com/Vector35/debugger/issues/170) | [#170](https://github.com/Vector35/debugger/issues/170) |      |
| LLDB Server                          | Yes                                                     | Yes                                                     | Yes                                                     |      |
| iOS/debugserver                      | Yes                                                     | Yes                                                     | Yes                                                     |      |
| Windows Kernel                       | No                                                      | No                                                      | Yes (Local/Remote)                                      |      |
| Windows TTD (WinDbg)                 | No                                                      | No                                                      | Yes (Local)                                             |      |
| Linux TTD (rr)                       | Yes (Remote)                                            | Yes (Local/Remote)                                      | Yes (Remote)                                            |      |
| Windows Dump File                    | No                                                      | No                                                      | Yes (Local)                                             |      |
| Corellium                            | Yes (Remote)                                            | Yes (Remote)                                            | Yes (Remote)                                            |      |

The progress is also tracked in issue [#122](https://github.com/Vector35/debugger/issues/122).



## Documentation

- [Online Debugger Python API documentation](https://dev-api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html#binaryninja.debugger.debuggercontroller.DebuggerController)
- There is also a section about the debugger in the User Guide that comes with Binary Ninja

## Building

The debugger is already shipped with Binary Ninja in stable and development branch. If you wish to contribute code, see [build](build.md) instructions.

## License

The Binary Ninja Debugger is open-source with [Apache License 2.0](https://raw.githubusercontent.com/Vector35/debugger/dev/LICENSE)

For other open-source or redistributable components and their respective licenses, please refer to this
[list](https://dev-docs.binary.ninja/guide/debugger/index.html#open-source).