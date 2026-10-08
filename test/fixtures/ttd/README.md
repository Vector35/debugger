# Fixed HelloWorld TTD replay fixtures

Recorded on 2026-10-08 on the authorized Windows 11 VM 115, using the existing
`test/binaries/Windows-x86_64/helloworld.exe` and `Windows-x86/helloworld.exe`.
Windows build: 22631.6199. Source-pinned WinDbg: 1.2603.20001.0.
Recorder: TTD 1.11.592.0. CDB: 10.0.29547.1002.

The Microsoft-signed WinDbg artifact came from `debugger-download-windbg` build 2:
SHA-256 `72bf7b1e58ee0a13fde52ad8803c45558f5b833ce6ae43ec274925c39b753c1b`.
Recording required an administrator token; replay in CI does not record anything.

```
TTD.exe -acceptEula -noUI -replayCpuSupport MostConservative -out trace.run -launch helloworld.exe
```

Both recordings completed successfully; both targets exited with code 10.
Traces are complete and unindexed. The x64 trace is 25,165,824 bytes raw and
5,439,509 bytes compressed; x86 is 20,971,520 bytes raw and 4,724,129 compressed.
Each JSON file records SHA-256 hashes of its compressed trace, raw trace, and
target, followed by independent CDB query results. Compression uses gzip level
9 with mtime zero. Tests extract into a temporary directory, so replay indexes
cannot modify checked-in artifacts.

To regenerate the oracle, load the trace with the pinned CDB and use a command
file (`-cf`, avoiding PowerShell native argument quoting):

```
.scriptload C:\path\oracle.js
dx @$scriptContents.oracle("x64")
q
```

Use `x86` for the other trace. Capture the JSON after `TTD_ORACLE` from CDB
output, then add the artifact hashes. `oracle.js` contains the fixed recorded
addresses. Calls use address strings rather than external symbol servers, so
results do not depend on symbol availability. The expected data contains every
read/write/execute event at the selected addresses and all three calls to the
program's printf wrapper, including thread IDs, positions, arguments and returns.
These are recorded ASLR addresses, not assumptions about future recordings.

CI copies the exact source-pinned WinDbg ZIP, validates its extracted manifest,
version marker and required files, then sets `BN_DBGENG_DLLS`. The fresh-process
worker imports Binary Ninja only after receiving that environment. It deliberately
sets an invalid `debugger.x64dbgEngPath` to check override precedence, verifies
forward/reverse stepping, and compares debugger API queries with this oracle.

The compressed pair adds about 9.7 MiB to Git. Avoid routinely re-recording these
binary fixtures: each replacement permanently adds another blob to history.
The superseded raw x64 fixture remains recoverable in prior Git commits.
