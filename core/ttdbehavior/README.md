# TTD behavior extractor

`ttdcapa-extract.exe` sweeps a Time Travel Debugging trace and writes the `.ttdb` report the
TTD Behavior sidebar reads. It runs out of process rather than being linked in, so a fault
or hang while replaying a hostile trace costs an extraction rather than the whole
application, and so the several gigabytes it can use building a report are reclaimed on
exit.

CMake copies this directory to `plugins/ttdbehavior/` next to `debuggercore`, which is where
the sidebar looks for it. Setting `debugger.ttdBehaviorExtractorPath` overrides that, for
running a build of your own.

## Contents

| File | |
| --- | --- |
| `x64/ttdcapa-extract.exe` | the extractor |
| `x64/win32-index.bin` | Win32 API metadata it decodes call arguments against; must sit beside the executable, or be named with `--win32-index` |
| `x64/ttdcapa-extract.md` | command-line reference and the `.ttdb` format specification |

## Provenance

Built by CI from [Vector35/ttd-capa](https://github.com/Vector35/ttd-capa), a fork of
[HullaBrian/ttd-capa](https://github.com/HullaBrian/ttd-capa) (Apache-2.0), from commit
`330b935` on branch `metadata-decoding`.

To update: take the `ttdcapa-extract-x64` artifact from a green run of that repo's `build`
workflow, replace the files in `x64/`, and note the new commit here.

## What is deliberately not here

Microsoft's `TTDReplay.dll` and `TTDReplayCPU.dll`, which the extractor needs to replay a
trace. They ship with WinDbg and are not ours to redistribute. The extractor delay-loads
`TTDReplay.dll` and takes `--ttd-dlls <dir>`, so the sidebar passes the location of the
WinDbg install the debugger already manages -- the same folder `ui/ttdrecord.cpp` uses for
recording. Nothing needs copying.
