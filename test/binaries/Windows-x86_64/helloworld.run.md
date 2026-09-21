# WinDbg TTD test fixture

`helloworld.run` is a fixed trace of the adjacent `helloworld.exe` test program. It was recorded
on Windows 11 x64 using the Microsoft-signed WinDbg package version `1.2603.20001.0`, which is the
version pinned by `installer/windbg_version.h`.

- Target SHA-256: `4ea4d20b6357794a8c01cf371e6a7b3eec16384e235fc4f9ea02f57d3d368663`
- Trace SHA-256: `eace0baeb61ef64a2032663310e2f8c7c8e1ccd8cacfde067aedb1c71f980c5a`
- Recorder: TTD `1.11.592.0` x64

The test intentionally replays this fixture rather than recording during CI. Recording requires an
elevated process and would make test input vary between runs; replay does not require elevation.
