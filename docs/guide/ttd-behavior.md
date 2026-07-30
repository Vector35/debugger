# TTD Behavior

While TTD already makes reverse engineering so much easier, we still want better ways to
help us analyze the program. The **TTD Behavior** feature sweeps a trace once and records
every Windows API call the process made -- when it happened, which function was called,
what its arguments were, and what it returned -- into a report you can then query, sort
through, and jump into.

Arguments are decoded against Microsoft's Win32 API metadata, so they come back named and
typed rather than as four guessed registers:

```
kernel32!CreateFileW(lpFileName: "C:\Users\me\AppData\Local\Temp\x.dat",
                     dwDesiredAccess: GENERIC_WRITE,
                     dwCreationDisposition: CREATE_ALWAYS, ...)  -> 0xf4
```

## Platform support

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Extracting a report from a trace | Yes | No | No |
| Opening and querying a report | Yes | Yes | Yes |

Extraction replays the trace through Microsoft's TTD engine, which only exists on Windows,
so the **Extract...** button is hidden elsewhere. Reading a report is just a memory-mapped
file with no Windows dependency at all, so a report extracted on Windows can be copied to a
Linux or macOS machine and opened there normally, in the UI or from Python.

## Extracting a report

1. Open the **TTD Behavior** sidebar.
2. Click **Extract...**.
3. If the current session is already replaying a trace, that trace is used. Otherwise you
   are asked for a `.run` file.

The report is written next to the trace as `<trace>.ttdb`. If the trace sits somewhere
unwritable you are asked where to put it instead.

Extraction runs in the background. A progress bar shows elapsed and estimated remaining
time, and **Cancel** stops the sweep while keeping everything recorded so far -- a
cancelled run produces a complete, valid report covering the portion of the trace that has
been processed.

The extraction is quite performant, and generally faster than running multiple TTD Calls
queries in the old way.

## Loading a report

**Load Report...** opens any `.ttdb` file. Loading is a memory map rather than a parse, so
it is effectively instant regardless of report size.

## Reading the table

| Column | Meaning |
| --- | --- |
| `#` | index of the call within the report |
| `Position` | TTD position, `sequence:step` |
| `TID` | thread that made the call |
| `Module` | module the function was resolved in, e.g. `kernel32` |
| `Function` | function name |
| `Parameters` | decoded arguments |
| `Return` | return value |
| `Return Address` | the call site -- useful for isolating calls the sample made itself |

Selecting a row shows the full detail below the table, including a hex dump of any buffer
argument. Buffer arguments also appear inline in the table as `0x1eefd98 -> [4d 5a 90 00
…]`, so you can see at a glance what a `WriteFile` actually wrote.

**Double-clicking a row time travels to that call and navigates to the instruction pointer
at that position**, which requires an active TTD session on the same trace.

## Querying

The filter box takes terms combined with AND. A bare word matches anywhere in the row,
including buffer contents.

| Term | Matches |
| --- | --- |
| `module:kernel32` | exact module, so `ntdll!WriteFile` is excluded |
| `api:WriteFile` | exact function name |
| `api:Reg*` | trailing `*` matches a prefix |
| `tid:4` | thread id |
| `ret:!0` | return value; also `>` `>=` `<` `<=` and `10-20` ranges |
| `retaddr:0x400000-0x500000` | call site within a range |
| `"c:\windows"` | quoted phrase |

Values may be decimal or `0x` hex. An unrecognised prefix is treated as text, so
`foo:bar` searches for that literal string rather than erroring.

Queries run inside the core over the whole report; a full scan of a 3.4M-call report takes
60-190 ms, so results appear as you type.

Each tab holds its own query. Use **+** to open another, which lets you keep one view of
`api:CreateFileW` beside another of `module:ws2_32` rather than retyping.

## Settings

| Setting | Default | Effect |
| --- | --- | --- |
| `debugger.ttdBehaviorExtractorPath` | empty | Path to the extractor executable. Empty uses the one shipped with the debugger; set it to run a build of your own. |
| `debugger.ttdBehaviorMaxBuffer` | 65536 | Bytes kept from any one buffer argument. Longer buffers are captured as a prefix and marked truncated. |

## The Python API

Reports can be opened and queried from Python on any platform, and extracted from Python
on Windows.

```python
from debugger.ttdbehavior import TTDBehaviorReport

with TTDBehaviorReport(r"C:\traces\sample.ttdb") as report:
    print(f"{report.call_count} calls from pid {report.pid}, {report.architecture}")

    for call in report.query("api:CreateFileW"):
        name = call.params[0].string if call.params else "?"
        print(f"{call.position}  {name} -> {call.ret:#x}")
```

### Extracting

`extract()` runs the same sweep the **Extract...** button does, with the same defaults --
the configured or bundled extractor, WinDbg's replay DLLs, and
`debugger.ttdBehaviorMaxBuffer`. It writes the report beside the trace and returns it
open:

```python
from debugger.ttdbehavior import extract

report = extract(r"C:\traces\sample.run")
print(f"{report.call_count} calls -> {report.path}")
```

Pass `progress` to follow along. It is called a few times a second with the phase
(`"sweep"` or `"write"`), a percentage, and the running call count; returning `False`
cancels, which stops the replay and writes what has been recorded so far:

```python
def show(phase, percent, calls):
    print(f"{phase} {percent}% ({calls} calls)")
    return calls < 1_000_000        # stop once we have a million

report = extract(r"C:\traces\sample.run", progress=show)
```

`output`, `extractor`, `ttd_dlls` and `max_buffer` override the corresponding defaults.
Off Windows, `extract()` raises `RuntimeError` -- there is no replay engine to sweep with.

`query()` filters entirely inside the core and returns matching rows, decoding each one
only as you reach it. Iterating a multi-million-call report one call at a time is possible
but slow -- narrow with a query first.

Calls come back with parameters decoded. On a query matching millions of rows that is
worth turning off:

```python
for call in report.query("", with_params=False):
    print(call.param_summary)     # still populated; the structured list is skipped
```

Useful members:

| | |
| --- | --- |
| `report.call_count`, `report.decoded_count` | totals; `decoded_count` counts calls that had a real signature |
| `report.pid`, `report.trace_path`, `report.architecture` | provenance |
| `report.path` | the `.ttdb` file this was opened from |
| `report.query_indices(q)` | just the row indices |
| `report.get_call(i)` | one call by index; `report[i]` also works |
| `call.module`, `call.api`, `call.tid`, `call.ret`, `call.return_address` | the call |
| `call.position` | `sequence:step` as a string |
| `call.decoded` | whether a real signature backed the parameters |
| `call.params` | list of `TTDApiCallParam` |
| `param.name`, `.type`, `.kind`, `.value` | one argument |
| `param.string`, `.flags`, `.data` | its resolved string, symbolic flags, or captured buffer |
| `param.truncated` | whether `data` is a prefix of a larger buffer |

## What the data can and cannot tell you

**An accessible buffer is not guaranteed to be extracted.** Due to the specific way the
extractor works (and some complex TTD shenanigans), buffers and strings that are indeed
readable may not always be properly recorded. This is a known limitation. When that
happens, time travelling to the timestamp yourself will read them fine.

**Calls without a signature have guessed arguments.** Metadata coverage is the public
Windows SDK, so `ntdll` internals and CRT helpers fall back to capturing argument registers
(x64) or stack slots (x86). Those values are positional, unnamed, and the count is a guess.
Such calls are flagged in the report and counted by `decoded_count`.

**Buffers are captured up to a limit.** See `debugger.ttdBehaviorMaxBuffer` above. A
truncated buffer still records its true length, so a short buffer is distinguishable from a
cut-off one.

## Running the extractor directly

The extractor ships with the debugger at `ttd-extract/ttdcapa-extract.exe` under the plugin
directory, alongside the `win32-index.bin` metadata it reads from beside itself. It is a
normal command-line tool and can be run without Binary Ninja:

```
ttdcapa-extract.exe trace.run -b report.ttdb --ttd-dlls <windbg>\amd64\ttd
```

`TTDReplay.dll` and `TTDReplayCPU.dll` are Microsoft's, ship with WinDbg, and are not
redistributed with the debugger -- `--ttd-dlls` points at the copy WinDbg installed. Full
option reference and the `.ttdb` format specification are in `ttd-extract/README.md`.

The extractor is built by CI from
[Vector35/ttd-capa](https://github.com/Vector35/ttd-capa), a fork of
[HullaBrian/ttd-capa](https://github.com/HullaBrian/ttd-capa). The README's footer records
the exact commit the shipped binary was built from.
